import { evaluatePolicy } from "./policy/engine.js";
import type { AuditLedger } from "./ledger/ledger.js";
import type { MandateManager } from "./mandate/mandate.js";
import type {
  ApprovalHandler,
  GuardResult,
  PaymentIntent,
  PolicyResult,
  SpendHistory,
  SpendPolicy,
} from "./types.js";

export interface SwaleGuardOptions {
  policy: SpendPolicy;
  ledger: AuditLedger;
  mandates?: MandateManager;
  /** When true, every intent must carry a valid mandateId. Default false. */
  requireMandate?: boolean;
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
   * Consulted immediately before money moves: has this mandate (or agent) been
   * revoked? Supply `createRegistryCheck(registry)` from @swale/revocation.
   *
   * It runs INSIDE the critical section, after any human approval, so a
   * revocation racing a long-pending approval still wins. It MUST fail closed
   * — a check that throws denies the payment.
   */
  revocationCheck?: RevocationCheck;
  /** Injectable clock for tests. */
  now?: () => Date;
}

export type RevocationVerdict =
  | { allowed: true }
  | { allowed: false; code: string; message: string };

/** Authorization-time revocation gate. Must fail closed. */
export type RevocationCheck = (intent: PaymentIntent) => Promise<RevocationVerdict>;

/**
 * SwaleGuard wraps a payment executor with deterministic policy checks,
 * mandate verification, human approval, and a tamper-evident audit trail.
 *
 * It NEVER holds funds, keys to funds, or the ability to move money — the
 * executor you pass in does the moving; the guard only decides whether that
 * function may run, and records everything.
 *
 * Concurrency: the decision→consume→execute→record critical section is
 * serialized per guard instance (an async mutex), so parallel execute() calls
 * cannot race a rolling-spend or velocity limit. Human approval, which may
 * block indefinitely, runs OUTSIDE the mutex; the policy is then re-evaluated
 * under the mutex before anything executes.
 */
export class SwaleGuard {
  private policy: SpendPolicy;
  private frozen: { reason: string } | null = null;
  private readonly ledger: AuditLedger;
  private readonly mandates: MandateManager | undefined;
  private readonly requireMandate: boolean;
  private readonly approvalHandler: ApprovalHandler | undefined;
  private readonly revocationCheck: RevocationCheck | undefined;
  private readonly now: () => Date;
  private readonly history: SpendHistory;
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
  }> = [];
  private readonly usingInMemoryHistory: boolean;
  private auditDegraded = false;
  private hydrated = false;

  constructor(opts: SwaleGuardOptions) {
    this.policy = opts.policy;
    this.ledger = opts.ledger;
    this.mandates = opts.mandates;
    this.requireMandate = opts.requireMandate ?? false;
    this.approvalHandler = opts.approvalHandler;
    this.revocationCheck = opts.revocationCheck;
    this.now = opts.now ?? (() => new Date());
    this.usingInMemoryHistory = opts.history === undefined;
    this.history = opts.history ?? this.inMemoryHistory();
  }

  /** True if any executed charge failed to persist its audit record. */
  isAuditDegraded(): boolean {
    return this.auditDegraded;
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
    };
  }

  /**
   * Restore in-memory state from a persistent, shared ledger on startup:
   *  - the spend counter (from execution_result entries), and
   *  - the freeze state (from the last guard_frozen / guard_unfrozen entry).
   *
   * Gated on chain integrity: the ledger is verified first (optionally against
   * a retained head) and hydrate FAILS CLOSED — throwing without changing
   * state — if verification fails, so a tampered/truncated ledger cannot reset
   * spend or lift a freeze. Runs inside the critical section and only once per
   * instance. Trusting a verified ledger at startup is a documented boundary
   * (see SECURITY.md).
   */
  async hydrateFromLedger(expectedHead?: Parameters<AuditLedger["verify"]>[0]): Promise<void> {
    return this.runExclusive(async () => {
      if (this.hydrated) {
        throw new Error("hydrateFromLedger already called on this guard instance");
      }
      const verdict = await this.ledger.verify(expectedHead);
      if (!verdict.ok) {
        throw new Error(
          `hydrateFromLedger refused: ledger failed verification (${verdict.problem ?? "unknown"})`,
        );
      }
      const entries = await this.ledger.all();

      const executed: Array<{ ms: number; amountMinor: number; currency: string }> = [];
      if (this.usingInMemoryHistory) {
        for (const entry of entries) {
          if (entry.type !== "execution_result") continue;
          const data = entry.data;
          if (data === null || typeof data !== "object") continue;
          const d = data as { success?: unknown; amountMinor?: unknown; currency?: unknown };
          if (d.success !== true) continue;
          // Skip malformed rows rather than poisoning the counter with NaN
          // (which would silently disable rolling limits).
          if (!Number.isSafeInteger(d.amountMinor)) continue;
          if (typeof d.currency !== "string") continue;
          const ms = Date.parse(entry.timestamp);
          if (Number.isNaN(ms)) continue;
          executed.push({ ms, amountMinor: d.amountMinor as number, currency: d.currency });
        }
      }

      // Compute freeze state into a local, assign once (never transiently null
      // a live frozen flag while a concurrent commit might read it).
      let frozen: { reason: string } | null = null;
      for (const entry of entries) {
        if (entry.type === "guard_frozen") {
          const data = entry.data;
          const reason =
            data && typeof data === "object" && typeof (data as { reason?: unknown }).reason === "string"
              ? ((data as { reason: string }).reason)
              : "frozen";
          frozen = { reason };
        } else if (entry.type === "guard_unfrozen") {
          frozen = null;
        }
      }

      this.executed.length = 0;
      this.executed.push(...executed);
      this.frozen = frozen;
      this.hydrated = true;
    });
  }

  /** Emergency stop: every subsequent intent is denied until unfreeze(). */
  async freeze(reason: string): Promise<void> {
    this.frozen = { reason };
    await this.ledger.append("guard_frozen", { reason });
  }

  async unfreeze(): Promise<void> {
    const reason = this.frozen?.reason ?? null;
    this.frozen = null;
    await this.ledger.append("guard_unfrozen", { previousReason: reason });
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

      let approved = false;
      if (prelim.decision === "require_approval") {
        if (!this.approvalHandler) {
          const denied = withExtraReason(
            prelim,
            "NO_APPROVAL_HANDLER",
            "approval required but no approvalHandler configured (fail closed)",
          );
          await this.ledger.append("policy_decision", { policyResult: denied }, refs);
          return { status: "denied", intentId: safe.id, policyResult: denied };
        }
        await this.ledger.append("approval_requested", { reasons: prelim.reasons }, refs);
        const response = await this.approvalHandler({
          intent: safe,
          policyResult: prelim,
          requestedAt: this.now().toISOString(),
        });
        await this.ledger.append("approval_resolved", { response }, refs);
        if (!response.approved) {
          return { status: "approval_rejected", intentId: safe.id, policyResult: prelim };
        }
        approved = true;
      }

      // Critical section: re-check freeze, re-evaluate against the CURRENT
      // policy and CURRENT spend totals, consume the mandate, execute, record
      // — all serialized so concurrent calls cannot jointly exceed a limit and
      // a mid-flight setPolicy/freeze is honored.
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
    executor: (intent: PaymentIntent) => Promise<T>,
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
    await this.ledger.append("policy_decision", { policyResult: finalResult }, refs);

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

    // Consume the mandate atomically, as the final gate before money moves.
    // consumeOnce also enforces idempotent replay: a RETRY of an already-
    // consumed (mandate, intent id) must never reach the executor again.
    let consumedMandateId: string | null = null;
    if (this.requireMandate || intent.mandateId) {
      const outcome = await this.mandates!.consumeOnce(intent.mandateId!, intent);
      if (outcome.kind === "rejected") {
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
    const recorded = {
      amountMinor: intent.amount.amountMinor,
      currency: intent.amount.currency,
      merchantId: intent.merchant.id,
      rail: intent.rail,
    };

    await this.ledger.append("execution_started", { rail: recorded.rail }, refs);

    let value: T;
    try {
      value = await executor(intent);
    } catch (err) {
      const message = errMsg(err);
      // Mandate use is intentionally NOT refunded here: a thrown executor may
      // still have moved money (e.g. a timeout after the charge landed), so
      // re-arming the mandate could authorize a double charge. Burn-on-failure
      // is the fail-safe choice; see SECURITY.md.
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
      return { status: "failed", intentId: intent.id, policyResult: finalResult, error: message };
    }

    // The charge happened. Count it in the authoritative in-memory ledger
    // FIRST — before the (best-effort) audit write — so a store failure can
    // never let this spend escape the next request's limit check.
    if (this.usingInMemoryHistory) {
      this.executed.push({
        ms: this.now().getTime(),
        amountMinor: recorded.amountMinor,
        currency: recorded.currency,
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
      ? { status: "executed", intentId: intent.id, policyResult: finalResult, value, auditDegraded: true }
      : { status: "executed", intentId: intent.id, policyResult: finalResult, value };
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

  private async appendBestEffort(
    type: Parameters<AuditLedger["append"]>[0],
    data: unknown,
    refs: { intentId: string; agentId: string },
  ): Promise<void> {
    try {
      await this.ledger.append(type, data, refs);
    } catch {
      // Swallow: the money-affecting decision has already been made and must
      // be reported truthfully even if this particular audit write failed.
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
 */
export function ledgerSpendHistory(ledger: AuditLedger): SpendHistory {
  return {
    async totalsSince(_agentId, sinceIso, currency) {
      const entries = await ledger.all();
      let totalMinor = 0;
      let count = 0;
      const wantCurrency = currency.toUpperCase();
      for (const entry of entries) {
        if (entry.type !== "execution_result") continue;
        if (entry.timestamp < sinceIso) continue;
        const data = entry.data as {
          success?: boolean;
          amountMinor?: number;
          currency?: string;
        };
        if (data.success !== true) continue;
        if ((data.currency ?? "").toUpperCase() !== wantCurrency) continue;
        totalMinor += data.amountMinor ?? 0;
        count += 1;
      }
      return { totalMinor, count };
    },
  };
}
