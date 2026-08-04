import { evaluatePolicy, policyWindows } from "./policy/engine.js";
import { MemorySpendLimiter, merchantKeyOf } from "./enforce/spend-limiter.js";
import {
  applyRiskTier,
  RiskUnscorableError,
  type RiskAssessment,
  type RiskScorecard,
} from "./risk/scorecard.js";
import type { AuditLedger, LedgerEntry } from "./ledger/ledger.js";
import type { MandateManager } from "./mandate/mandate.js";
import type {
  ApprovalHandler,
  GuardResult,
  PaymentIntent,
  PolicyResult,
  SpendHistory,
  SpendLimiter,
  SpendPolicy,
} from "./types.js";

export interface VadunoGuardOptions {
  policy: SpendPolicy;
  ledger: AuditLedger;
  mandates?: MandateManager;
  /** When true, every intent must carry a valid mandateId. Default false. */
  requireMandate?: boolean;
  /**
   * When true, execute()/authorize() deny every intent (HYDRATION_REQUIRED)
   * until hydrateFromLedger() has succeeded on this instance. Set it whenever
   * the guard restarts over a persistent ledger: without it, a restart that
   * never attempts hydrate serves with fresh, empty state (no restored
   * freeze, zero counted spend), which is silently the maximally permissive
   * configuration. Opt-in rather than default only because most single-run
   * guards never hydrate and would otherwise deny forever.
   *
   * Independent of this option, a hydrate that was ATTEMPTED and FAILED
   * denies by default until a retry succeeds — a guard that has seen its
   * ledger fail verification does not get to shrug and serve open. This
   * option adds coverage for the restart that forgets to hydrate at all.
   */
  requireHydration?: boolean;
  /**
   * Called when policy says "require_approval". If absent, such intents are
   * DENIED (fail closed) — never silently allowed.
   */
  approvalHandler?: ApprovalHandler;
  /**
   * Spend-history source for rolling-window checks. Defaults to a
   * ledger-backed, guard-wide implementation. Override to plug a database
   * aggregate query (see SpendHistory docs on the agentId caveat).
   */
  history?: SpendHistory;
  /**
   * Authoritative, ATOMIC spend limiter — what makes "total spend ≤ cap" hold
   * across PROCESSES rather than only within one.
   *
   * Defaults to a `MemorySpendLimiter`, which is correct for a single process
   * and nothing more: two guard processes each holding their own memory are
   * two separate budgets, so a $50/day cap lets $100 through. Supply a
   * `FileSpendLimiter` (several processes on one box) or a database-backed
   * limiter (multiple instances) to close that.
   *
   * `history` above is only an advisory fast-fail; THIS is the gate money
   * actually passes through.
   */
  limiter?: SpendLimiter;
  /**
   * Consulted immediately before money moves: has this mandate (or agent) been
   * revoked? Supply `createRegistryCheck(registry)` from @vaduno/revocation.
   *
   * It runs INSIDE the critical section, after any human approval, so a
   * revocation racing a long-pending approval still wins. It MUST fail closed
   * — a check that throws denies the payment.
   */
  revocationCheck?: RevocationCheck;
  /**
   * Deterministic risk scorecard (see `RiskScorecard`). When configured,
   * every intent that passes policy is scored from the ledger TWICE — a
   * preliminary pass outside the mutex, and a final pass inside the critical
   * section (signals move as concurrent intents commit) — and each
   * assessment is hard-appended as a `risk_scored` ledger entry before it is
   * acted on. The tier can only TIGHTEN the policy decision: low changes
   * nothing; elevated routes through the EXISTING approval branch
   * (RISK_STEPUP; no handler configured = NO_APPROVAL_HANDLER deny); high
   * denies (RISK_DENY) and the approval handler is NEVER invoked — approval
   * answers a step-up, it never overrides a deny. Both risk denials happen
   * BEFORE `limiter.reserve()` and `mandates.consumeOnce()`, so a risk deny
   * never burns budget or a mandate use. When this option is absent the
   * pipeline is unchanged. Risk is defense-in-depth, never an allow
   * authority: no assessment can loosen a policy outcome.
   */
  risk?: RiskScorecard;
  /** Injectable clock for tests. */
  now?: () => Date;
}

export type RevocationVerdict =
  | { allowed: true }
  | { allowed: false; code: string; message: string };

/**
 * What hydrateFromLedger() restored, and what it could NOT read.
 *
 * `skippedUnparseableSpendRows` counts `execution_result` rows that claim a
 * successful charge (or whose data is not an object at all) but carry no
 * usable amount/currency/timestamp — every such row is a spend the restored
 * counter does NOT include. Nonzero means the restored totals may UNDER-count
 * real charges (e.g. rows written by a pre-0.3.0 settle(), which recorded no
 * economic fields): reconcile against the rail before trusting the restored
 * caps. Rows recording failed attempts are not spend and count toward
 * neither number. Both counts are 0 when a custom `history` was supplied,
 * because the in-memory spend restore does not run at all in that case.
 */
export interface HydrateReport {
  restoredSpendRows: number;
  skippedUnparseableSpendRows: number;
}

/** Authorization-time revocation gate. Must fail closed. */
export type RevocationCheck = (intent: PaymentIntent) => Promise<RevocationVerdict>;

/**
 * VadunoGuard wraps a payment executor with deterministic policy checks,
 * mandate verification, human approval, and a tamper-evident audit trail.
 *
 * It NEVER holds funds, keys to funds, or the ability to move money — the
 * executor you pass in does the moving; the guard only decides whether that
 * function may run, and records everything.
 *
 * Concurrency: the decision→reserve→consume→execute→commit critical section is
 * serialized per guard instance (an async mutex), so parallel execute() calls
 * cannot race a rolling-spend or velocity limit. Human approval, which may
 * block indefinitely, runs OUTSIDE the mutex; the policy is then re-evaluated
 * under the mutex before anything executes.
 */
export class VadunoGuard {
  private policy: SpendPolicy;
  private frozen: { reason: string } | null = null;
  private readonly ledger: AuditLedger;
  private readonly mandates: MandateManager | undefined;
  private readonly requireMandate: boolean;
  private readonly approvalHandler: ApprovalHandler | undefined;
  private readonly revocationCheck: RevocationCheck | undefined;
  /** Deterministic risk scorecard, or undefined = pipeline unchanged. */
  private readonly risk: RiskScorecard | undefined;
  private readonly now: () => Date;
  private readonly history: SpendHistory;
  /** Authoritative atomic budget gate. See VadunoGuardOptions.limiter. */
  private readonly limiter: SpendLimiter;
  /** Serializes the spend-accounting critical section. */
  private critical: Promise<unknown> = Promise.resolve();
  /**
   * Authoritative in-memory record of executed spend, appended under the
   * mutex the instant the executor succeeds. This — not a read-back of the
   * ledger — is what enforces rolling/velocity limits by default, so a
   * dropped or doctored audit write can never un-count a real charge. See
   * SECURITY.md for the single-process scope and hydrateFromLedger().
   */
  private readonly executed: Array<{
    ms: number;
    amountMinor: number;
    currency: string;
    /** merchantKeyOf() key. Absent on rows hydrated from a pre-velocity ledger. */
    merchantKey?: string;
  }> = [];
  private readonly usingInMemoryHistory: boolean;
  private auditDegraded = false;
  private limiterDegraded = false;
  private freezeDegraded = false;
  private hydrated = false;
  /** True after a hydrate attempt threw. Denies by default until a retry succeeds. */
  private hydrateFailed = false;
  private readonly requireHydration: boolean;
  /**
   * Monotonic generation counter, bumped by every freeze()/unfreeze() at the
   * same instant the flag flips. The LATEST synchronous flip is always the
   * truth; the only deferred write to `this.frozen` — hydrateFromLedger()'s
   * snapshot restore — applies only if this counter has not moved since the
   * hydrate was called. Without the stamp, ANY deferred assignment (a queued
   * mutex re-assertion, a hydrate snapshot) can land after a newer flip and
   * resurrect state the operator already changed — in the fatal direction,
   * that is a stale unfreeze overwriting a live freeze.
   */
  private freezeEpoch = 0;
  /**
   * Settlement of the most recently issued freeze/unfreeze ledger write,
   * errors swallowed (a failed write is already reported via
   * isFreezeDegraded()). hydrateFromLedger() awaits this before reading the
   * ledger, so its snapshot can never miss a freeze-state record the
   * operator issued before hydrating — without it, an unawaited unfreeze()
   * racing hydrate could be re-asserted from a snapshot taken before its
   * guard_unfrozen record landed. The ledger's internal append queue makes
   * the latest write's settlement imply all earlier ones.
   */
  private freezeWrites: Promise<unknown> = Promise.resolve();

  constructor(opts: VadunoGuardOptions) {
    this.policy = opts.policy;
    this.ledger = opts.ledger;
    this.mandates = opts.mandates;
    this.requireMandate = opts.requireMandate ?? false;
    this.requireHydration = opts.requireHydration ?? false;
    this.approvalHandler = opts.approvalHandler;
    this.revocationCheck = opts.revocationCheck;
    this.risk = opts.risk;
    this.now = opts.now ?? (() => new Date());
    this.usingInMemoryHistory = opts.history === undefined;
    this.history = opts.history ?? this.inMemoryHistory();
    this.limiter = opts.limiter ?? new MemorySpendLimiter();
  }

  /**
   * True if any audit record failed to persist — including, but not limited
   * to, the record of an executed charge.
   *
   * This is the SEVERE one and it is worth alarming on: the durable trail is
   * incomplete, and if the lost entry was an `execution_result` then money
   * moved unrecorded. Reconcile against the rail.
   *
   * It used to also become true when a spend-limiter COMMIT failed — a
   * condition this class documents as benign (the reservation stays held, so
   * the amount still counts; at worst budget is over-held). Conflating the two
   * meant a harmless over-hold raised the same alarm as a lost audit record,
   * which is how a real alarm gets ignored. That case is now
   * `isLimiterDegraded()`.
   */
  isAuditDegraded(): boolean {
    return this.auditDegraded;
  }

  /**
   * True if a spend-limiter commit or release failed.
   *
   * Benign by construction, and deliberately separate from
   * `isAuditDegraded()`: an uncommitted reservation stays reserved and a
   * reserved amount already counts against every cap, so the ONLY effect is
   * that budget is held longer than the truth. Worth surfacing — it means the
   * limiter store is unhealthy — but it never means money went unrecorded.
   */
  isLimiterDegraded(): boolean {
    return this.limiterDegraded;
  }

  /**
   * True if a freeze()/unfreeze() could not persist its ledger record.
   *
   * Deliberately a separate signal from isAuditDegraded(): that flag means
   * the EVIDENCE trail has a hole while enforcement stayed correct; this one
   * means the current ENFORCEMENT state itself is not durable — a lost
   * guard_frozen record hydrates a restarted guard back to UNFROZEN (and a
   * lost guard_unfrozen resurrects a lifted freeze). The in-process flag
   * keeps enforcing either way; on seeing this, re-issue the freeze/unfreeze
   * or repair the ledger before trusting a restart.
   */
  isFreezeDegraded(): boolean {
    return this.freezeDegraded;
  }

  /**
   * Decide, reserve, and hand the decision back — WITHOUT running anything.
   *
   * `execute(intent, executor)` requires the guard to own the payment call.
   * Every agent framework's hook point is decide-only — Claude Agent SDK
   * `PreToolUse`, Vercel AI SDK `toolApproval`, OpenAI Agents `needsApproval`,
   * LangChain `wrapToolCall` — so none of them can use it. This is the shape
   * they can: ask, get an answer, do the thing yourself, report back.
   *
   * On `status: "authorized"` the budget is RESERVED and any mandate use is
   * consumed, so a second concurrent authorization cannot pass the same cap.
   * Call `settle(intent.id, …)` when you know what happened.
   *
   * TWO THINGS TO BE CLEAR ABOUT:
   *  - An authorization you never settle keeps holding budget until its window
   *    rolls off. That is deliberate — over-hold, never overspend — but it does
   *    mean a caller that forgets to settle slowly starves its own cap.
   *  - On this path the ledger records a SELF-REPORTED outcome. With
   *    `execute()` the guard watched the executor run; here it takes your word.
   *    That is a real reduction in evidence quality and is recorded as such.
   *
   * Settlement keys on `intent.id`, not on a returned closure, precisely so a
   * framework can serialize its state and settle from another process.
   */
  async authorize(intent: PaymentIntent): Promise<GuardResult<never>> {
    return this.run<never>(intent, null);
  }

  /**
   * Report what happened to an authorization from `authorize()`.
   *
   * "executed" commits the reserved spend. "failed" leaves it RESERVED — a
   * thrown rail may still have moved money, so the amount keeps counting until
   * you can prove otherwise via `releaseSpend(intentId)`. Same burn-on-failure
   * rule `execute()` applies; the two paths must not disagree about money.
   *
   * THE LEDGER ROW CARRIES THE MONEY. The `execution_result` appended here
   * holds the same `amountMinor`/`currency`/`merchantId`/`rail` an `execute()`
   * row holds — recovered from this intent's `execution_started` authorization
   * snapshot — plus `selfReported: true`, because on this path the guard never
   * watched the rail run. Before 0.3.0 the row held neither amount nor
   * currency, so a restarted guard's `hydrateFromLedger()` skipped every
   * two-phase spend and re-authorized the full budget: a silent caps reset on
   * exactly the path every framework integration takes.
   *
   * MONEY-IDEMPOTENT, deduped by OUTCOME, not by position. A retrying caller
   * cannot double-count spend: the reservation commit is idempotent, and at
   * most one COUNTABLE success row lands per authorization — an "executed"
   * settle is suppressed only by an existing success row after the current
   * authorization snapshot; a "failed" settle by any result row after it.
   * (If the dedupe's trail read itself fails, the outcome is still appended —
   * losing the settlement record over a read hiccup would be worse — but
   * WITHOUT economic fields, so that row can never be counted as spend. The
   * sharper edge: if that happens on the FIRST executed settle, the fieldless
   * success row suppresses a later healthy retry, so the amount stays
   * uncountable for that charge and post-restart caps re-admit it. Never
   * silent — it surfaces as a `skippedUnparseableSpendRows` hydrate-report
   * skip; reconcile against the rail before trusting restored totals.) The
   * dedupe is deliberately not positional: on the recovery interleave
   * authorize → settle(failed) → releaseSpend → re-authorize(same id) →
   * late-retried settle(failed) → settle(executed), a positional check let the
   * stale failure row suppress the genuine executed outcome — the ledger
   * permanently said `success: false` for a charge that HAPPENED, and a
   * restart re-authorized the full amount. The residue of outcome-keyed
   * dedupe is bounded and safe: that late retried "failed" adds one redundant
   * failure row to the trail, and failure rows are never counted as spend.
   *
   * Safe to call for an unknown id: the limiter is untouched and the outcome
   * row carries no economic fields (there is no authorization row to recover
   * them from), so it can never count as spend.
   *
   * The dedupe read-check-append runs inside the guard's critical section so
   * two concurrent retries cannot both pass the check. Do not call settle()
   * from inside an `execute()` executor — that path holds the same mutex.
   *
   * TRUST BOUNDARY of the read-back: `trailFor()` is NOT chain-verified here.
   * A store that tampers an `execution_started` snapshot (breaking the chain
   * at that row) could make this method RECORD a laundered amount in a fresh,
   * correctly-hashed row. It cannot make the guard ALLOW anything: the
   * authoritative cap gate is `limiter.reserve()` at authorize time, and both
   * `verify()` and `hydrateFromLedger()` fail on the broken link at the
   * tampered row before any restored guard would trust the laundered row.
   * This row is evidence, not enforcement.
   */
  async settle(
    intentId: string,
    outcome: { status: "executed" | "failed"; error?: string; mandateId?: string },
  ): Promise<void> {
    const settledAt = this.now().toISOString();

    if (outcome.status === "executed") {
      await this.commitBestEffort(intentId);
    }
    // On "failed" the reservation is deliberately left alone: neither committed
    // nor released. See releaseSpend().

    if (outcome.mandateId) {
      await this.settleBestEffort(outcome.mandateId, intentId, {
        status: outcome.status,
        settledAt,
        ...(outcome.error !== undefined ? { error: outcome.error } : {}),
      });
    }

    await this.recordSettlement(intentId, outcome);
  }

  /**
   * Append the settle outcome, carrying the economic snapshot recovered from
   * the authorization row. See settle() for the dedupe rules and the trust
   * boundary of the (unverified) trailFor() read-back.
   */
  private async recordSettlement(
    intentId: string,
    outcome: { status: "executed" | "failed"; error?: string },
  ): Promise<void> {
    await this.runExclusive(async () => {
      let trail: LedgerEntry[] = [];
      try {
        trail = await this.ledger.trailFor(intentId);
      } catch {
        // A failed read must not lose the settlement record: fall through and
        // append the outcome without economic fields (appendBestEffort flags
        // auditDegraded if the write fails too).
      }

      // The LAST two-phase execution_started row is the CURRENT authorization
      // epoch for this intent id: releaseSpend + re-authorize legitimately
      // reuses an id, and each re-authorization appends a fresh snapshot.
      let authIndex = -1;
      for (let i = trail.length - 1; i >= 0; i--) {
        const e = trail[i]!;
        if (e.type !== "execution_started") continue;
        const d = e.data;
        if (d !== null && typeof d === "object" && (d as { twoPhase?: unknown }).twoPhase === true) {
          authIndex = i;
          break;
        }
      }

      // OUTCOME-KEYED dedupe. "executed" is suppressed ONLY by an existing
      // SUCCESS row after the current snapshot; "failed" by any result row.
      // A positional any-row check here suppressed a genuine executed outcome
      // behind a late-retried failure row (see settle() docblock) — the ledger
      // then under-counted a real charge forever.
      const success = outcome.status === "executed";
      const isSuccessRow = (e: LedgerEntry) =>
        e.data !== null &&
        typeof e.data === "object" &&
        (e.data as { success?: unknown }).success === true;
      for (let i = authIndex + 1; i < trail.length; i++) {
        const e = trail[i]!;
        if (e.type !== "execution_result") continue;
        if (!success || isSuccessRow(e)) return; // already recorded — a retry
      }

      // Recover the economic snapshot and the agent from the authorization
      // row. Validation mirrors what the hydrate/history consumers require, so
      // a row this method writes is a row they will count.
      let recorded: {
        amountMinor: number;
        currency: string;
        merchantId: string;
        merchantKey?: string;
        rail: string;
      } | null = null;
      let agentId = "";
      if (authIndex >= 0) {
        const auth = trail[authIndex]!;
        if (typeof auth.agentId === "string") agentId = auth.agentId;
        const d = auth.data as {
          amountMinor?: unknown;
          currency?: unknown;
          merchantId?: unknown;
          merchantKey?: unknown;
          rail?: unknown;
        };
        if (
          Number.isSafeInteger(d.amountMinor) &&
          typeof d.currency === "string" &&
          typeof d.merchantId === "string" &&
          typeof d.rail === "string"
        ) {
          recorded = {
            amountMinor: d.amountMinor as number,
            currency: d.currency,
            merchantId: d.merchantId,
            rail: d.rail,
            // OPTIONAL on purpose: an authorization row written before
            // merchant velocity existed has no key, and its settle row must
            // still be countable — it lands keyless and counts toward every
            // merchant window rather than escaping them.
            ...(typeof d.merchantKey === "string" ? { merchantKey: d.merchantKey } : {}),
          };
        }
      }

      // Strict superset of an execute() row: same economic field names and
      // values, plus selfReported — the guard did not watch this rail run and
      // the evidence must say so.
      await this.appendBestEffort(
        "execution_result",
        {
          success,
          selfReported: true,
          ...(outcome.error !== undefined ? { error: outcome.error } : {}),
          ...(recorded ?? {}),
        },
        { intentId, agentId },
      );
    });
  }

  /**
   * Reclaim the budget held by a FAILED execution, for the case where you can
   * prove the rail did not move money.
   *
   * When an executor throws, Vaduno keeps the amount counted against your
   * caps, because a timeout after the charge landed is indistinguishable from
   * a clean failure — and treating every failure as free is how a retry loop
   * spends past a cap. If your rail gives you certainty (an explicit
   * `card_declined`, a 4xx before submission, an idempotent lookup showing no
   * charge), call this to give the budget back.
   *
   * Safe by construction: a SUCCESSFUL execution's spend is committed and
   * cannot be released by this call, so a mistaken invocation cannot un-count
   * real money.
   */
  async releaseSpend(intentId: string): Promise<void> {
    await this.releaseBestEffort(intentId);
  }

  private inMemoryHistory(): SpendHistory {
    return {
      totalsSince: async (_agentId, sinceIso, currency) => {
        const sinceMs = Date.parse(sinceIso);
        const want = currency.toUpperCase();
        let totalMinor = 0;
        let count = 0;
        for (const e of this.executed) {
          if (e.ms < sinceMs) continue;
          if (e.currency.toUpperCase() !== want) continue;
          if (!Number.isSafeInteger(e.amountMinor)) continue;
          totalMinor += e.amountMinor;
          count += 1;
        }
        return { totalMinor, count };
      },
      merchantCountSince: async (_agentId, merchantKey, sinceIso, currency) => {
        const sinceMs = Date.parse(sinceIso);
        const want = currency.toUpperCase();
        let count = 0;
        for (const e of this.executed) {
          if (e.ms < sinceMs) continue;
          if (e.currency.toUpperCase() !== want) continue;
          // A keyless entry (hydrated from a pre-velocity ledger row) counts
          // toward EVERY merchant — deny over guess, self-heals as it ages
          // out of the window.
          if (e.merchantKey !== undefined && e.merchantKey !== merchantKey) continue;
          count += 1;
        }
        return { count };
      },
    };
  }

  /**
   * Restore in-memory state from a persistent, shared ledger on startup:
   *  - the spend counter (from execution_result entries), and
   *  - the freeze state (from the last guard_frozen / guard_unfrozen entry).
   *
   * Gated on chain integrity: the ledger is verified first (optionally
   * against a retained head), and a failed verification makes hydrate THROW
   * without changing spend or freeze state — a tampered/truncated ledger
   * cannot inject a spend counter or lift a freeze THROUGH this call. A
   * failed attempt also flips the guard into DENY (`HYDRATION_REQUIRED`)
   * until a retry succeeds: the alternative — keeping the instance's FRESH
   * state (no freeze, zero counted spend) in force — is the maximally
   * PERMISSIVE configuration, and "the ledger failed verification, so I
   * served with no history" is fail-open by any honest reading. A guard that
   * never attempts hydrate is unaffected; `requireHydration: true` covers
   * that case too. Runs inside the critical section and only once per
   * instance (a failed attempt may be retried). Trusting a verified ledger
   * at startup is a documented boundary (see SECURITY.md).
   *
   * Returns a HydrateReport rather than void: a row the restore cannot parse
   * is SKIPPED, never counted as zero — but a silent skip is a spend the
   * operator does not know is missing from the restored caps. Check
   * `skippedUnparseableSpendRows` and reconcile when it is nonzero.
   */
  async hydrateFromLedger(
    expectedHead?: Parameters<AuditLedger["verify"]>[0],
  ): Promise<HydrateReport> {
    // Captured at CALL time, not at task start: any freeze()/unfreeze() the
    // operator issues after this line is newer than whatever snapshot this
    // hydrate will read, and must win over it.
    const epochAtCall = this.freezeEpoch;
    return this.runExclusive(async () => {
      if (this.hydrated) {
        throw new Error("hydrateFromLedger already called on this guard instance");
      }
      try {
        const report = await this.restoreFromLedger(expectedHead, epochAtCall);
        this.hydrateFailed = false;
        return report;
      } catch (err) {
        // Deny by default from here on (HYDRATION_REQUIRED): an attempted
        // hydrate that failed must not leave a fresh, permissive guard
        // serving as if there were no history to restore.
        this.hydrateFailed = true;
        throw err;
      }
    });
  }

  /** The body of hydrateFromLedger(). Runs under the mutex; throws = failed. */
  private async restoreFromLedger(
    expectedHead: Parameters<AuditLedger["verify"]>[0] | undefined,
    epochAtCall: number,
  ): Promise<HydrateReport> {
    // A freeze/unfreeze issued before this hydrate may still have its ledger
    // record in flight; wait for it to land (or definitively fail) so the
    // snapshot below cannot miss freeze state the operator already set.
    // Lock-free waits on lock-free writes: no cycle with the mutex this
    // method runs under.
    await this.freezeWrites;
    const verdict = await this.ledger.verify(expectedHead);
    if (!verdict.ok) {
      throw new Error(
        `hydrateFromLedger refused: ledger failed verification (${verdict.problem ?? "unknown"})`,
      );
    }
    const entries = await this.ledger.all();

    const executed: Array<{
      ms: number;
      amountMinor: number;
      currency: string;
      merchantKey?: string;
    }> = [];
    let restoredSpendRows = 0;
    let skippedUnparseableSpendRows = 0;
    if (this.usingInMemoryHistory) {
      for (const entry of entries) {
        if (entry.type !== "execution_result") continue;
        const data = entry.data;
        if (data === null || typeof data !== "object") {
          // A result row we cannot even inspect. Skipped, but COUNTED as
          // skipped: a silent skip here is how a real charge vanishes from
          // the restored caps with no one told.
          skippedUnparseableSpendRows += 1;
          continue;
        }
        const d = data as {
          success?: unknown;
          amountMinor?: unknown;
          currency?: unknown;
          merchantKey?: unknown;
        };
        // Failed/denied attempts are not spend — not restored, not "skipped".
        if (d.success !== true) continue;
        // Skip malformed rows rather than poisoning the counter with NaN
        // (which would silently disable rolling limits) — but report the
        // skip: each one is a claimed-successful charge the restored counter
        // does NOT include (e.g. a pre-0.3.0 settle() row, which carried no
        // amount or currency at all).
        if (
          !Number.isSafeInteger(d.amountMinor) ||
          typeof d.currency !== "string" ||
          Number.isNaN(Date.parse(entry.timestamp))
        ) {
          skippedUnparseableSpendRows += 1;
          continue;
        }
        executed.push({
          ms: Date.parse(entry.timestamp),
          amountMinor: d.amountMinor as number,
          currency: d.currency,
          // A row with no usable merchantKey (every pre-velocity row) is
          // restored KEYLESS, and a keyless entry counts toward every
          // merchant window — the upgrade has no velocity-free interval.
          ...(typeof d.merchantKey === "string" ? { merchantKey: d.merchantKey } : {}),
        });
        restoredSpendRows += 1;
      }
    }

    // Freeze state: the LAST guard_frozen/guard_unfrozen entry is
    // authoritative, so walk from the tail and stop at the first one found.
    // Computed into a local, assigned once (never transiently null a live
    // frozen flag while a concurrent commit might read it).
    let frozen: { reason: string } | null = null;
    for (let i = entries.length - 1; i >= 0; i--) {
      const entry = entries[i]!;
      if (entry.type === "guard_unfrozen") break;
      if (entry.type === "guard_frozen") {
        const data = entry.data;
        const reason =
          data && typeof data === "object" && typeof (data as { reason?: unknown }).reason === "string"
            ? ((data as { reason: string }).reason)
            : "frozen";
        frozen = { reason };
        break;
      }
    }

    this.executed.length = 0;
    this.executed.push(...executed);
    // The snapshot restore applies ONLY if no freeze()/unfreeze() has
    // happened since hydrate was called (the epoch stamp). A live flip is
    // strictly newer than anything this snapshot can say, and a deferred
    // assignment that ignores that ordering is exactly how a startup
    // freeze got clobbered back to null — freeze() resolved cleanly, the
    // ledger said guard_frozen, and the guard kept authorizing.
    //
    // Even with the epoch unchanged the restore merges TOWARD frozen
    // (`frozen ?? this.frozen`), never away: a freeze whose guard_frozen
    // append FAILED (isFreezeDegraded()) is live and real, yet the
    // verified ledger legitimately lacks its record — an unconditional
    // assignment would lift it. A snapshot `frozen` can only mean the
    // ledger's last freeze-state record is guard_frozen, so keeping the
    // live flag can never overwrite a NEWER unfreeze (that unfreeze would
    // have bumped the epoch and skipped this restore entirely).
    if (this.freezeEpoch === epochAtCall) {
      this.frozen = frozen ?? this.frozen;
    }
    this.hydrated = true;
    return { restoredSpendRows, skippedUnparseableSpendRows };
  }

  /**
   * Emergency stop: every subsequent intent **on this guard instance** is
   * denied until `unfreeze()`.
   *
   * PER-PROCESS, and that matters more than it sounds. `frozen` is an in-memory
   * field, so freezing one process does not stop another live process — the
   * peers keep spending until each is frozen or restarted. An operator who
   * pulls the switch, sees spending stop locally, and concludes it has stopped
   * everywhere is wrong. `hydrateFromLedger()` restores freeze state at STARTUP
   * from the ledger, so a restart honours it, but nothing propagates to a
   * running peer.
   *
   * For a kill a second process actually observes, use `@vaduno/revocation`
   * with a shared registry: it is checked on the execution path, after
   * approval, and an unreachable registry denies rather than allows.
   *
   * Within this process: the deny flag flips SYNCHRONOUSLY, before the first
   * await — an emergency stop must not queue behind a slow in-flight payment.
   * commit() re-reads the flag immediately before invoking the executor, so a
   * freeze landing while a payment is mid-decision still denies it if the
   * rail has not run.
   *
   * NO LOCK, ever. freeze() must be safe to call — and await — from inside
   * an executor or revocationCheck ("this charge looks hostile, stop the
   * guard"), which runs inside the critical section; routing the durable
   * record through that same mutex is a deadlock cycle (0.2.x allowed the
   * pattern and it must keep working). It must also leave nothing deferred:
   * a queued "re-assert my flag later" task can run after a NEWER
   * freeze/unfreeze and resurrect state the operator already changed — a
   * stale unfreeze re-assertion overwriting a live freeze lets a queued
   * payment through a frozen guard. So the flag flips here, once, stamped by
   * `freezeEpoch`; the guard_frozen record goes straight to the ledger
   * (whose own internal queue keeps the chain linear); and the epoch stamp
   * is what stops a concurrent hydrateFromLedger() from overwriting the flag
   * with an older snapshot.
   *
   * The append is best-effort: if it fails, the LOCAL freeze stands (the
   * safe direction) and isFreezeDegraded() reports that the freeze would not
   * survive a restart. Throwing away the local freeze on a failed write
   * would fail OPEN.
   *
   * `details.autoFreeze` (additive, optional) is how the risk scorecard's
   * auto-freeze records WHICH intent and score pulled the switch: the
   * structured `{intentId, score, atScore}` rides on the guard_frozen ledger
   * record so the evidence names the trigger, not just a reason string.
   * Everything else — synchronous flag flip, epoch stamp, lock-free
   * best-effort append — is identical for both callers.
   */
  async freeze(
    reason: string,
    details?: { autoFreeze?: { intentId: string; score: number; atScore: number } },
  ): Promise<void> {
    this.frozen = { reason };
    this.freezeEpoch += 1;
    const write = this.ledger.append("guard_frozen", {
      reason,
      ...(details?.autoFreeze !== undefined ? { autoFreeze: details.autoFreeze } : {}),
    });
    this.freezeWrites = write.then(
      () => undefined,
      () => undefined,
    );
    try {
      await write;
    } catch {
      this.freezeDegraded = true;
    }
  }

  /**
   * Lift the freeze. Same rules as freeze(): the flag clears synchronously
   * with an epoch stamp (so neither a concurrent hydrate nor any deferred
   * task can resurrect the freeze — or outlive a freeze issued after this
   * call; hydrate additionally waits for this call's ledger write to settle
   * before snapshotting), the guard_unfrozen record is appended lock-free,
   * and a failed append sets isFreezeDegraded() — a restart, or a later
   * hydrate on this instance, would come back FROZEN: divergent, but in the
   * safe direction.
   */
  async unfreeze(): Promise<void> {
    const reason = this.frozen?.reason ?? null;
    this.frozen = null;
    this.freezeEpoch += 1;
    const write = this.ledger.append("guard_unfrozen", { previousReason: reason });
    this.freezeWrites = write.then(
      () => undefined,
      () => undefined,
    );
    try {
      await write;
    } catch {
      this.freezeDegraded = true;
    }
  }

  isFrozen(): boolean {
    return this.frozen !== null;
  }

  /** Replace the active policy; the change itself is audited. */
  async setPolicy(policy: SpendPolicy): Promise<void> {
    const previous = { id: this.policy.id, version: this.policy.version };
    this.policy = policy;
    await this.ledger.append("policy_updated", {
      previous,
      next: { id: policy.id, version: policy.version },
      policy,
    });
  }

  getPolicy(): SpendPolicy {
    return this.policy;
  }

  /** Run `fn` after any in-flight critical section; serialize the next one. */
  private runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const task = this.critical.then(fn, fn);
    this.critical = task.then(
      () => undefined,
      () => undefined,
    );
    return task;
  }

  /**
   * Evaluate an intent and, if permitted, run the executor.
   * Every step is written to the ledger regardless of outcome.
   * This method never rejects — failures come back as a GuardResult.
   */
  async execute<T>(
    intent: PaymentIntent,
    executor: (intent: PaymentIntent) => Promise<T>,
  ): Promise<GuardResult<T>> {
    return this.run<T>(intent, executor);
  }

  /**
   * The single decision pipeline behind BOTH `execute()` and `authorize()`.
   *
   * One path on purpose: two implementations of "may this spend happen" would
   * eventually disagree, and the disagreement would be about money. A null
   * executor stops the pipeline after the reservation instead of running
   * anything.
   */
  private async run<T>(
    intent: PaymentIntent,
    executor: ((intent: PaymentIntent) => Promise<T>) | null,
  ): Promise<GuardResult<T>> {
    // Pin every field to a plain snapshot up front: a hostile intent could use
    // getters that return a benign value during checks and a malicious one at
    // execution (TOCTOU). structuredClone flattens getters to values and
    // strips functions. The executor is handed this same safe copy.
    let safe: PaymentIntent;
    try {
      safe = structuredClone(intent);
    } catch {
      // Non-cloneable intent (functions/symbols) — deny without touching it,
      // but still leave a best-effort trace of the rejected attempt.
      const intentId = typeof intent?.id === "string" ? intent.id : "(unknown)";
      const policyResult = internalDeny(
        this.policy,
        "INTENT_NOT_SERIALIZABLE",
        "intent could not be safely snapshotted",
      );
      await this.appendBestEffort("policy_decision", { policyResult }, {
        intentId,
        agentId:
          typeof intent?.agentId === "string" ? intent.agentId : "(unknown)",
      });
      return { status: "denied", intentId, policyResult };
    }

    const refs = { intentId: safe.id, agentId: safe.agentId };

    try {
      await this.ledger.append("intent_received", { intent: safe }, refs);
    } catch (err) {
      // Even the first audit write failed. Fail closed without executing.
      return {
        status: "denied",
        intentId: safe.id,
        policyResult: internalDeny(
          this.policy,
          "AUDIT_WRITE_FAILED",
          errMsg(err),
        ),
      };
    }

    try {
      // Hydration gate. An unhydrated guard holds this instance's fresh
      // state — no restored freeze, zero counted spend: the maximally
      // permissive configuration. Two ways in:
      //  - a hydrate was ATTEMPTED and FAILED: deny BY DEFAULT until a retry
      //    succeeds. "The ledger failed verification, so I served with no
      //    history" is fail-open; a guard that never calls hydrate is
      //    unaffected, so tightening this default breaks no one.
      //  - requireHydration covers the restart that never attempts hydrate.
      if (this.hydrateFailed || (this.requireHydration && !this.hydrated)) {
        return await this.denyAudited(
          safe,
          refs,
          "HYDRATION_REQUIRED",
          this.hydrateFailed
            ? "hydrateFromLedger() was attempted and failed; denying until a retry succeeds (fail closed)"
            : "requireHydration is set and hydrateFromLedger() has not succeeded (fail closed)",
        );
      }

      if (this.frozen) {
        return await this.denyAudited(safe, refs, "GUARD_FROZEN", `guard is frozen: ${this.frozen.reason}`);
      }

      // Mandate pre-flight (consumption happens later, under the mutex).
      if (this.requireMandate || safe.mandateId) {
        const failure = this.mandatePreflightFailure(safe);
        if (failure) {
          await this.ledger.append("policy_decision", { policyResult: failure }, refs);
          return { status: "denied", intentId: safe.id, policyResult: failure };
        }
      }

      // Preliminary evaluation — decides deny/approval BEFORE we take the
      // mutex, so a blocking human approval never stalls other payments.
      const prelim = await evaluatePolicy(safe, this.policy, this.history, this.now);

      if (prelim.decision === "deny") {
        await this.ledger.append("policy_decision", { policyResult: prelim }, refs);
        return { status: "denied", intentId: safe.id, policyResult: prelim };
      }

      // DETERMINISTIC RISK, PRELIMINARY pass — outside the mutex, like the
      // policy prelim, so a step-up approval can never stall other payments.
      // Skipped when the policy already denied: risk only TIGHTENS, and
      // there is nothing tighter than a deny. A high tier denies RIGHT HERE,
      // before the approval branch below can run — approval answers a
      // step-up; it must never be offered a chance to override a deny.
      let prelimStance = prelim;
      if (this.risk) {
        const scored = await this.scoreRisk(safe, refs, "prelim");
        if (scored.kind === "unscorable") {
          return await this.denyRiskUnscorable(safe, refs, scored.message);
        }
        if (scored.assessment.tier === "high") {
          return await this.denyRiskHigh(safe, refs, prelim, scored.assessment);
        }
        // low = unchanged; elevated = require_approval through the EXISTING
        // approval branch, reasons carrying RISK_STEPUP + the fired signals.
        prelimStance = applyRiskTier(prelim, scored.assessment);
      }

      let approved = false;
      if (prelimStance.decision === "require_approval") {
        if (!this.approvalHandler) {
          const denied = withExtraReason(
            prelimStance,
            "NO_APPROVAL_HANDLER",
            "approval required but no approvalHandler configured (fail closed)",
          );
          await this.ledger.append("policy_decision", { policyResult: denied }, refs);
          return { status: "denied", intentId: safe.id, policyResult: denied };
        }
        await this.ledger.append("approval_requested", { reasons: prelimStance.reasons }, refs);
        const response = await this.approvalHandler({
          intent: safe,
          policyResult: prelimStance,
          requestedAt: this.now().toISOString(),
        });
        await this.ledger.append("approval_resolved", { response }, refs);
        if (!response.approved) {
          return { status: "approval_rejected", intentId: safe.id, policyResult: prelimStance };
        }
        approved = true;
      }

      // Critical section: re-check freeze, re-evaluate against the CURRENT
      // policy and CURRENT spend totals, consume the mandate, execute, record
      // — all serialized so concurrent calls cannot jointly exceed a limit.
      // setPolicy/freeze/unfreeze all mutate guard state synchronously (and
      // WITHOUT this mutex — freeze must never wait behind a payment), so a
      // call issued before this section begins is seen by the re-checks at
      // its top; a freeze landing WHILE the section runs is re-checked once
      // more immediately before execution starts (the unclosable residue is
      // that last audit write plus one tick — see the docblock in commit()).
      // What orders freeze/unfreeze against hydrateFromLedger is the
      // freezeEpoch stamp, not this mutex.
      return await this.runExclusive(() => this.commit(safe, refs, approved, executor));
    } catch (err) {
      // Fail closed: any unexpected error denies the payment and is audited.
      return await this.denyAudited(safe, refs, "GUARD_INTERNAL_ERROR", errMsg(err));
    }
  }

  private async commit<T>(
    intent: PaymentIntent,
    refs: { intentId: string; agentId: string },
    approved: boolean,
    /** null = two-phase: authorize only, the caller executes and settles. */
    executor: ((intent: PaymentIntent) => Promise<T>) | null,
  ): Promise<GuardResult<T>> {
    if (this.frozen) {
      return await this.denyAudited(intent, refs, "GUARD_FROZEN", `guard is frozen: ${this.frozen.reason}`);
    }

    const finalResult = await evaluatePolicy(intent, this.policy, this.history, this.now);

    if (finalResult.decision === "deny") {
      await this.ledger.append("policy_decision", { policyResult: finalResult }, refs);
      return { status: "denied", intentId: intent.id, policyResult: finalResult };
    }
    if (finalResult.decision === "require_approval" && !approved) {
      // Policy tightened between prelim and now to require an approval we do
      // not hold. Fail closed rather than execute unapproved.
      const denied = withExtraReason(
        finalResult,
        "APPROVAL_REQUIRED_AFTER_POLICY_CHANGE",
        "policy now requires approval that was not obtained (fail closed)",
      );
      await this.ledger.append("policy_decision", { policyResult: denied }, refs);
      return { status: "denied", intentId: intent.id, policyResult: denied };
    }

    // DETERMINISTIC RISK, FINAL pass — RE-EVALUATED here inside the critical
    // section, not reused from the prelim, because every signal is
    // ledger-derived and concurrent intents commit entries between the
    // prelim and this point: the score that was low outside the mutex may
    // not be low anymore. Ordered BEFORE limiter.reserve() and
    // mandates.consumeOnce() below — a risk deny must never burn budget or
    // a mandate use.
    let finalStance = finalResult;
    if (this.risk) {
      const scored = await this.scoreRisk(intent, refs, "final");
      if (scored.kind === "unscorable") {
        return await this.denyRiskUnscorable(intent, refs, scored.message);
      }
      if (scored.assessment.tier === "high") {
        // Deny even if a human already approved a step-up: approval answers
        // a step-up, it never overrides a deny.
        return await this.denyRiskHigh(intent, refs, finalResult, scored.assessment);
      }
      finalStance = applyRiskTier(finalResult, scored.assessment);
      if (finalStance.decision === "require_approval" && !approved) {
        // Risk ROSE between the prelim and this re-evaluation into the
        // step-up tier, and no approval is held. Mirrors
        // APPROVAL_REQUIRED_AFTER_POLICY_CHANGE: fail closed rather than
        // execute a step-up nobody answered.
        const denied = withExtraReason(
          finalStance,
          "RISK_STEPUP_UNAPPROVED",
          "risk reached the step-up tier after the preliminary evaluation; no approval was obtained (fail closed)",
        );
        await this.ledger.append("policy_decision", { policyResult: denied }, refs);
        return { status: "denied", intentId: intent.id, policyResult: denied };
      }
    }
    await this.ledger.append("policy_decision", { policyResult: finalStance }, refs);

    // Revocation gate: checked HERE — inside the critical section, after any
    // human approval — so a kill switch pulled while an approval was pending
    // still wins the race. Fails closed on any error.
    if (this.revocationCheck) {
      let verdict: RevocationVerdict;
      try {
        verdict = await this.revocationCheck(intent);
      } catch (err) {
        verdict = {
          allowed: false,
          code: "REVOCATION_CHECK_FAILED",
          message: `revocation status could not be determined (fail closed): ${errMsg(err)}`,
        };
      }
      if (!verdict.allowed) {
        const denied = internalDeny(this.policy, verdict.code, verdict.message);
        await this.ledger.append("policy_decision", { policyResult: denied }, refs);
        return { status: "denied", intentId: intent.id, policyResult: denied };
      }
    }

    // ATOMIC BUDGET RESERVATION — the authoritative rolling-limit gate.
    //
    // Placed HERE, before the mandate is consumed, for two reasons that are
    // both load-bearing:
    //  1. A refused reservation is a DENIAL, and denials must never burn a
    //     mandate use. Reserving after consumption would spend a use on a
    //     payment that never happened.
    //  2. It is after the revocation gate and after approval, so nothing that
    //     can deny remains between the reservation and the executor except the
    //     mandate check — whose failure paths release below.
    //
    // The reservation, not `evaluatePolicy`, is what actually enforces the
    // cap: evaluatePolicy reads totals and is check-then-act by construction.
    //
    // Derived from the SAFE snapshot via merchantKeyOf() — the one shared
    // merchant-identity function — so the limiter's merchant windows and the
    // advisory engine cannot disagree about which merchant this spend is.
    const merchantKey = merchantKeyOf(intent.merchant);
    const reservation = await this.limiter.reserve({
      // The POLICY id, never intent.agentId. The threat model assumes the agent
      // controls every field of the intent, so scoping a cap by agentId lets a
      // compromised agent mint a fresh budget by changing one string. That was
      // a real bypass: two guards sharing one limiter passed $100 through a $50
      // cap by rotating agentId, while a fixed agentId correctly denied.
      scope: this.policy.id,
      currency: this.policy.currency,
      amountMinor: intent.amount.amountMinor,
      // The intent id, so a retry storm reserves ONCE rather than draining
      // the budget one refused attempt at a time.
      reservationId: intent.id,
      windows: policyWindows(this.policy),
      merchantKey,
      nowMs: this.now().getTime(),
    });
    if (!reservation.ok) {
      const denied = internalDeny(this.policy, reservation.code, reservation.message);
      await this.ledger.append("policy_decision", { policyResult: denied }, refs);
      return { status: "denied", intentId: intent.id, policyResult: denied };
    }

    // A REPLAYED reservation means this intent id already claimed budget, so an
    // earlier attempt already reached the rail. Returning here — rather than
    // falling through — is what stops the executor running twice while the
    // spend is counted once.
    //
    // Without this, `reserve()` being idempotent actively HID a double
    // execution: same intent id twice ran the rail twice and counted one
    // charge, and a throwing executor retried eight times ran the rail eight
    // times and still counted one. Mandates would have caught it, but mandates
    // are optional and the cap is not.
    // A MANDATE, if present, is the better replay authority: its consume-once
    // registry holds the intent digest (so id reuse with different money is
    // DENIED, not replayed) and the settled outcome (so a failed attempt
    // replays "failed", not "unresolved"). Let it decide, and don't release a
    // reservation we didn't take.
    //
    // Without a mandate there is no other execution guard, and the limiter is
    // the only thing between a duplicate id and a second charge. Before this,
    // `reserve()` being idempotent actively HID a double execution: the same
    // intent id twice ran the rail twice and counted one charge, and a throwing
    // executor retried eight times ran the rail eight times and still counted
    // one. Mandates are optional; the cap is not.
    const mandated = this.requireMandate || Boolean(intent.mandateId);
    if (reservation.replayed && !mandated) {
      return this.replayedResult(intent, reservation.state);
    }

    // Only a reservation WE took may be released on a later denial. A replayed
    // one belongs to the original attempt; releasing it would un-count spend
    // that may be real.
    const ourReservation = reservation.replayed ? null : reservation.reservationId;
    const releaseIfOurs = async () => {
      if (ourReservation) await this.releaseBestEffort(ourReservation);
    };

    // Consume the mandate atomically, as the final gate before money moves.
    // consumeOnce also enforces idempotent replay: a RETRY of an already-
    // consumed (mandate, intent id) must never reach the executor again.
    let consumedMandateId: string | null = null;
    if (this.requireMandate || intent.mandateId) {
      const outcome = await this.mandates!.consumeOnce(intent.mandateId!, intent);
      if (outcome.kind === "rejected") {
        // The rail definitely did not run, so the budget goes back.
        await releaseIfOurs();
        const denied = internalDeny(
          this.policy,
          `MANDATE_${outcome.check.code}`,
          outcome.check.message,
        );
        await this.ledger.append("policy_decision", { policyResult: denied }, refs);
        return { status: "denied", intentId: intent.id, policyResult: denied };
      }
      if (outcome.kind === "replayed") {
        if (!outcome.digestMatches) {
          // Same intent id, different payment — an id-reuse attack, not a
          // retry. Deny; never replay, never execute.
          await releaseIfOurs();
          const denied = internalDeny(
            this.policy,
            "MANDATE_REPLAY_MISMATCH",
            "intent id was already consumed by a DIFFERENT payment (amount/merchant/rail changed)",
          );
          await this.ledger.append("policy_decision", { policyResult: denied }, refs);
          return { status: "denied", intentId: intent.id, policyResult: denied };
        }
        const claim = outcome.claim;
        const original =
          claim.status === "settled" && claim.outcome
            ? {
                status: claim.outcome.status,
                settledAt: claim.outcome.settledAt,
                ...(claim.outcome.error !== undefined ? { error: claim.outcome.error } : {}),
              }
            : // Claimed but never settled: the original attempt is in flight
              // or crashed mid-execution. Money MAY have moved — surface
              // "unresolved" for reconciliation; never re-execute.
              { status: "unresolved" as const };
        // This attempt did not run the rail — the original did, and holds its
        // own reservation. Give back only what we took.
        await releaseIfOurs();
        return {
          status: "replayed",
          intentId: intent.id,
          mandateId: intent.mandateId!,
          original,
        };
      }
      consumedMandateId = intent.mandateId!;
    }

    // Snapshot the money-affecting fields BEFORE calling the executor, so the
    // counted/recorded amount is exactly what policy checked — independent of
    // any mutation the executor might make to the passed object.
    // merchantKey rides along so a restart (hydrateFromLedger) can rebuild
    // per-merchant counts from the rows this snapshot lands in.
    const recorded = {
      amountMinor: intent.amount.amountMinor,
      currency: intent.amount.currency,
      merchantId: intent.merchant.id,
      merchantKey,
      rail: intent.rail,
    };

    // LAST-EXIT FREEZE RE-CHECK. The freeze check at the top of this section
    // is separated from the executor by six awaits (policy re-eval, its audit
    // write, the revocation fetch, the budget reservation, the mandate
    // consume, the execution_started write), and freeze() flips its flag
    // synchronously WITHOUT waiting for the mutex precisely so a freeze
    // landing inside that gap can still be honored here. This re-read narrows
    // the blind window to the execution_started write plus one synchronous
    // tick. It cannot close it, and it must not try: once the executor is
    // invoked, Vaduno has no power to recall the charge — a cancellable
    // in-flight payment would require exactly the control over funds this
    // project must never hold. On the two-phase path this is the last exit
    // before the authorization is handed back for the CALLER to execute.
    //
    // PLACEMENT DECISION (after the mandate consume, not before): the
    // ConsumeStore interface is claim/settle/get/countClaims — deliberately
    // NO un-claim, because an un-claim primitive is the same lever that
    // would let a crash-looping caller resurrect uses (the reason a thrown
    // executor burns its use, see below). So a freeze that lands in the
    // consume→here gap costs one mandate use on a payment that never ran.
    // That is an over-hold — the direction every ambiguous path here fails
    // toward — and it is the price of keeping the consume round-trip (an IO
    // await on shared stores) OUT of the blind window this check exists to
    // shrink. The burned use is settled "failed" so a retry after unfreeze
    // replays a terminal outcome instead of "unresolved". The budget
    // reservation, unlike the mandate use, has an explicit release() for
    // payments that provably never ran — and this one provably never ran —
    // so it goes back.
    // The cast undoes TS narrowing from the top-of-section check: the flow
    // analysis assumes no cross-await mutation, which is the very thing this
    // re-read exists to observe.
    const lateFrozen = this.frozen as { reason: string } | null;
    if (lateFrozen) {
      await releaseIfOurs();
      if (consumedMandateId) {
        await this.settleBestEffort(consumedMandateId, intent.id, {
          status: "failed",
          settledAt: this.now().toISOString(),
          error: "denied by freeze before execution; the rail was never invoked",
        });
      }
      return await this.denyAudited(
        intent,
        refs,
        "GUARD_FROZEN",
        `guard is frozen: ${lateFrozen.reason}`,
      );
    }

    // TWO-PHASE STOP. `authorize()` passes no executor: the decision is made,
    // the budget is reserved and the mandate use is consumed, and the caller
    // runs the payment itself and reports back via `settle()`.
    //
    // Stopping HERE rather than earlier is the whole point — an authorization
    // that has not reserved is just an opinion, and two of them would both pass
    // the same cap.
    if (executor === null) {
      // The FULL economic snapshot rides on this row, not just the rail:
      // settle() recovers amount/currency/merchant from it so the
      // execution_result it appends is countable by hydrateFromLedger() and
      // ledgerSpendHistory(). Without these fields the settle row recorded no
      // money, and a restarted guard re-authorized the full budget.
      await this.ledger.append(
        "execution_started",
        { ...recorded, twoPhase: true },
        refs,
      );
      return {
        status: "authorized",
        intentId: intent.id,
        policyResult: finalStance,
        ...(consumedMandateId ? { mandateId: consumedMandateId } : {}),
      } as GuardResult<T>;
    }

    await this.ledger.append("execution_started", { rail: recorded.rail }, refs);

    let value: T;
    try {
      value = await executor(intent);
    } catch (err) {
      const message = errMsg(err);
      // The reservation is deliberately left RESERVED — neither committed nor
      // released. A thrown executor may still have moved money: a timeout
      // after the charge landed is indistinguishable from a clean failure
      // here. A reserved amount keeps counting against every cap, so a crash
      // loop cannot spend without bound — which is exactly the failure mode
      // caps exist to prevent.
      //
      // It stays RESERVED rather than committed so it remains reclaimable: a
      // caller who can prove the rail did not charge calls
      // `guard.releaseSpend(intent.id)`. Otherwise it ages out with its window.
      // Over-hold, never overspend.
      //
      // Mandate use is NOT refunded here for the same reason: re-arming the
      // mandate could authorize a double charge. See SECURITY.md.
      await this.appendBestEffort(
        "execution_result",
        { success: false, error: message, ...recorded },
        refs,
      );
      // Settle so a retry of this intent replays "failed" instead of hanging
      // on an unresolved claim. Best-effort: if it fails, retries see
      // "unresolved" — fail closed either way.
      if (consumedMandateId) {
        await this.settleBestEffort(consumedMandateId, intent.id, {
          status: "failed",
          settledAt: this.now().toISOString(),
          error: message,
        });
      }
      return { status: "failed", intentId: intent.id, policyResult: finalStance, error: message };
    }

    // The charge happened. Settle the reservation into committed spend FIRST —
    // before the (best-effort) audit write — so a store failure can never let
    // this spend escape the next request's limit check.
    await this.commitBestEffort(reservation.reservationId);

    if (this.usingInMemoryHistory) {
      this.executed.push({
        ms: this.now().getTime(),
        amountMinor: recorded.amountMinor,
        currency: recorded.currency,
        merchantKey: recorded.merchantKey,
      });
    }

    // Settle the consumed use so any retry of this intent id replays the
    // executed outcome instead of re-running the rail.
    if (consumedMandateId) {
      await this.settleBestEffort(consumedMandateId, intent.id, {
        status: "executed",
        settledAt: this.now().toISOString(),
      });
    }

    // Recording MUST NOT reclassify an executed charge as failed. If the audit
    // write throws we still report executed, but flag the durable-trail loss.
    let auditDegraded = false;
    try {
      await this.ledger.append("execution_result", { success: true, ...recorded }, refs);
    } catch {
      this.auditDegraded = true;
      auditDegraded = true;
    }
    return auditDegraded
      ? { status: "executed", intentId: intent.id, policyResult: finalStance, value, auditDegraded: true }
      : { status: "executed", intentId: intent.id, policyResult: finalStance, value };
  }

  /**
   * One risk pass: read the ledger, score, hard-append the evidence.
   *
   * Fail-closed map, exhaustively:
   *  - the HISTORY SOURCE (ledger.all) throws → "unscorable", which the
   *    callers turn into a RISK_UNSCORABLE deny with the approval handler,
   *    the limiter and the mandate registry all untouched;
   *  - the scorer raises RiskUnscorableError (config incoherent for the
   *    active policy, unusable inputs) → same RISK_UNSCORABLE deny;
   *  - any OTHER scorer error is a bug, and a bug is not a pass: it is
   *    rethrown into the pipeline's outer catch, which denies
   *    GUARD_INTERNAL_ERROR — still before any budget or mandate use;
   *  - the risk_scored append is HARD: an assessment that cannot be recorded
   *    must not be acted on, so a failed append throws into the same
   *    GUARD_INTERNAL_ERROR deny.
   */
  private async scoreRisk(
    intent: PaymentIntent,
    refs: { intentId: string; agentId: string },
    phase: "prelim" | "final",
  ): Promise<
    | { kind: "scored"; assessment: RiskAssessment }
    | { kind: "unscorable"; message: string }
  > {
    let entries: LedgerEntry[];
    try {
      entries = await this.ledger.all();
    } catch (err) {
      return {
        kind: "unscorable",
        message: `risk history source failed: ${errMsg(err)} (fail closed)`,
      };
    }
    let assessment: RiskAssessment;
    try {
      assessment = this.risk!.assess({
        intent,
        policy: this.policy,
        entries,
        nowMs: this.now().getTime(),
      });
    } catch (err) {
      if (err instanceof RiskUnscorableError) {
        return { kind: "unscorable", message: errMsg(err) };
      }
      throw err;
    }
    await this.ledger.append("risk_scored", { phase, assessment }, refs);
    return { kind: "scored", assessment };
  }

  /** "Cannot score" is a DENY, never a skip: zero is the most permissive score. */
  private async denyRiskUnscorable<T>(
    intent: PaymentIntent,
    refs: { intentId: string; agentId: string },
    message: string,
  ): Promise<GuardResult<T>> {
    const denied = internalDeny(this.policy, "RISK_UNSCORABLE", message);
    await this.ledger.append("policy_decision", { policyResult: denied }, refs);
    return { status: "denied", intentId: intent.id, policyResult: denied };
  }

  /**
   * High-tier deny (RISK_DENY), plus the auto-freeze when the score reaches
   * `autoFreeze.atScore`. The freeze happens BEFORE the deny is appended:
   * freeze() flips its flag synchronously, so even if the append below throws
   * (GUARD_INTERNAL_ERROR deny), the stop is already in force — fail closed.
   * Auto-freeze inherits the local freeze's PER-PROCESS scope (peers keep
   * serving until each is frozen; see SECURITY.md) and is lifted by manual
   * unfreeze() only. Skipped if the guard is already frozen — the operator's
   * standing reason must not be overwritten by a racing assessment.
   */
  private async denyRiskHigh<T>(
    intent: PaymentIntent,
    refs: { intentId: string; agentId: string },
    base: PolicyResult,
    assessment: RiskAssessment,
  ): Promise<GuardResult<T>> {
    const atScore = this.risk!.autoFreezeAtScore;
    if (atScore !== null && assessment.score >= atScore && !this.frozen) {
      await this.freeze(
        `auto-freeze: risk score ${assessment.score} >= ${atScore}`,
        { autoFreeze: { intentId: intent.id, score: assessment.score, atScore } },
      );
    }
    const denied = applyRiskTier(base, assessment);
    await this.ledger.append("policy_decision", { policyResult: denied }, refs);
    return { status: "denied", intentId: intent.id, policyResult: denied };
  }

  private async denyAudited<T>(
    intent: PaymentIntent,
    refs: { intentId: string; agentId: string },
    code: string,
    message: string,
  ): Promise<GuardResult<T>> {
    const policyResult = internalDeny(this.policy, code, message);
    await this.appendBestEffort("policy_decision", { policyResult }, refs);
    return { status: "denied", intentId: intent.id, policyResult };
  }

  private async settleBestEffort(
    mandateId: string,
    useKey: string,
    outcome: { status: "executed" | "failed"; settledAt: string; error?: string },
  ): Promise<void> {
    try {
      await this.mandates?.settleUse(mandateId, useKey, outcome);
    } catch {
      // Swallow: the money outcome is already decided and must be reported
      // truthfully. An unsettled claim replays as "unresolved" — fail closed.
    }
  }

  /**
   * A duplicate intent id that already claimed budget. The rail must NOT run
   * again; report what the first attempt did.
   *
   * "committed" means it settled — the rail ran and the spend is real.
   * "reserved" means it claimed budget and never settled: in flight, or crashed
   * mid-execution. Money MAY have moved, so this reports `unresolved` rather
   * than guessing. Never tell a caller a charge didn't happen when it might.
   */
  private replayedResult<T>(
    intent: PaymentIntent,
    state: "reserved" | "committed" | undefined,
  ): GuardResult<T> {
    return {
      status: "replayed",
      intentId: intent.id,
      ...(intent.mandateId ? { mandateId: intent.mandateId } : {}),
      original:
        state === "committed"
          ? { status: "executed" as const, settledAt: this.now().toISOString() }
          : { status: "unresolved" as const },
    };
  }

  /**
   * Settle a reservation into committed spend. Best-effort BECAUSE the failure
   * mode is safe: a reservation that cannot be committed stays "reserved", and
   * a reserved amount already counts against every cap. The count is never
   * lost — at worst the budget is held slightly longer than the truth.
   * Throwing here would be worse: the money has already moved.
   */
  private async commitBestEffort(reservationId: string): Promise<void> {
    try {
      await this.limiter.commit(reservationId);
    } catch {
      // NOT auditDegraded: no audit record was lost here. See the two
      // accessors' docblocks for why keeping these apart matters.
      this.limiterDegraded = true;
    }
  }

  /**
   * Give back a reservation for a payment that provably did not run. Also
   * best-effort, and also safe to fail: an un-released reservation over-holds
   * budget until its window rolls off. Denying a later payment is recoverable;
   * an uncounted charge is not.
   */
  private async releaseBestEffort(reservationId: string): Promise<void> {
    try {
      await this.limiter.release(reservationId);
    } catch {
      // Over-hold. See above. Flagged like a failed commit — same cause (an
      // unhealthy limiter store), same benign effect, and silently swallowing
      // it left the store's ill health with no signal at all.
      this.limiterDegraded = true;
    }
  }

  private async appendBestEffort(
    type: Parameters<AuditLedger["append"]>[0],
    data: unknown,
    refs: { intentId: string; agentId: string },
  ): Promise<void> {
    try {
      await this.ledger.append(type, data, refs);
    } catch {
      // Do not THROW: the money-affecting decision has already been made and
      // must be reported truthfully even if this particular audit write failed.
      //
      // But do not swallow it SILENTLY either, which is what used to happen.
      // Two of this method's four call sites append `execution_result` — the
      // two-phase settle() path and the failed-execution path — so a store
      // dropping writes lost payment records with no signal whatsoever, while
      // the single-call execute() path flagged the identical failure. That gap
      // widened when @vaduno/agent made two-phase the route every framework
      // integration takes.
      this.auditDegraded = true;
    }
  }

  private mandatePreflightFailure(intent: PaymentIntent): PolicyResult | null {
    if (!this.mandates) {
      return internalDeny(
        this.policy,
        "MANDATE_MANAGER_MISSING",
        "mandate required but no MandateManager configured (fail closed)",
      );
    }
    if (!intent.mandateId) {
      return internalDeny(
        this.policy,
        "MANDATE_REQUIRED",
        "policy requires a mandate but intent carries none",
      );
    }
    const check = this.mandates.check(intent.mandateId, intent);
    if (!check.ok) {
      return internalDeny(this.policy, `MANDATE_${check.code}`, check.message);
    }
    return null;
  }
}

function internalDeny(
  policy: SpendPolicy,
  code: string,
  message: string,
): PolicyResult {
  return {
    decision: "deny",
    reasons: [{ code, message }],
    policyId: policy.id,
    policyVersion: policy.version,
  };
}

function withExtraReason(
  base: PolicyResult,
  code: string,
  message: string,
): PolicyResult {
  return {
    ...base,
    decision: "deny",
    reasons: [...base.reasons, { code, message }],
  };
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * SpendHistory backed by the audit ledger: sums successful execution_result
 * entries GUARD-WIDE (all agents). Deny/failed attempts do not count.
 * See SpendHistory docs for why agentId is intentionally ignored here.
 *
 * A row is counted ONLY if its amount is a safe integer and its currency a
 * string. Anything else is skipped and surfaced through `onUnparseable` —
 * never counted as zero. The old `amountMinor ?? 0` treated a malformed row
 * as a $0 spend (and a STRING amount would have string-concatenated the
 * running total, silently disabling the cap it feeds); both are now
 * impossible by construction.
 *
 * `onUnparseable` fires once per malformed row per totalsSince() call (which
 * runs on every policy evaluation that checks a windowed cap or velocity
 * limit — a policy with only per-transaction limits never calls it — log
 * accordingly). It is an observer, not
 * a gate: a THROWING callback is swallowed, because policy evaluation must
 * not become an outage — or a fail-open path — over a malformed historical
 * row. Rows in another currency are a mismatch, not malformed; they skip
 * without firing it.
 */
export function ledgerSpendHistory(
  ledger: AuditLedger,
  onUnparseable?: (entry: LedgerEntry, problem: string) => void,
): SpendHistory {
  const surface = (entry: LedgerEntry, problem: string) => {
    if (!onUnparseable) return;
    try {
      onUnparseable(entry, problem);
    } catch {
      // The observer failing must not take policy evaluation down with it.
    }
  };
  return {
    async totalsSince(_agentId, sinceIso, currency) {
      const entries = await ledger.all();
      let totalMinor = 0;
      let count = 0;
      const wantCurrency = currency.toUpperCase();
      for (const entry of entries) {
        if (entry.type !== "execution_result") continue;
        if (entry.timestamp < sinceIso) continue;
        const data = entry.data;
        if (data === null || typeof data !== "object") {
          surface(entry, "data is not an object");
          continue;
        }
        const d = data as {
          success?: unknown;
          amountMinor?: unknown;
          currency?: unknown;
        };
        if (d.success !== true) continue;
        if (!Number.isSafeInteger(d.amountMinor)) {
          surface(entry, "amountMinor is not a safe integer");
          continue;
        }
        if (typeof d.currency !== "string") {
          surface(entry, "currency is not a string");
          continue;
        }
        if (d.currency.toUpperCase() !== wantCurrency) continue;
        totalMinor += d.amountMinor as number;
        count += 1;
      }
      return { totalMinor, count };
    },
    async merchantCountSince(_agentId, merchantKey, sinceIso, currency) {
      const entries = await ledger.all();
      let count = 0;
      const wantCurrency = currency.toUpperCase();
      for (const entry of entries) {
        if (entry.type !== "execution_result") continue;
        if (entry.timestamp < sinceIso) continue;
        const data = entry.data;
        if (data === null || typeof data !== "object") {
          surface(entry, "data is not an object");
          continue;
        }
        const d = data as {
          success?: unknown;
          currency?: unknown;
          merchantKey?: unknown;
        };
        if (d.success !== true) continue;
        if (typeof d.currency !== "string") {
          surface(entry, "currency is not a string");
          continue;
        }
        if (d.currency.toUpperCase() !== wantCurrency) continue;
        // A row with no usable merchantKey — every row written before
        // merchant velocity existed — counts toward EVERY merchant: deny
        // over guess, ages out of the window on its own.
        if (typeof d.merchantKey === "string" && d.merchantKey !== merchantKey) {
          continue;
        }
        count += 1;
      }
      return { count };
    },
  };
}
