import type {
  MerchantRef,
  ReserveRequest,
  ReserveResult,
  SpendLimiter,
  SpendWindow,
} from "../types.js";

/**
 * Atomic spend limiting. See the `SpendLimiter` docblock in types.ts for the
 * contract; this file is the reference semantics every other implementation
 * (file-backed, Postgres, Redis) must reproduce exactly.
 *
 * The rule that makes it correct: evaluating the windows and recording the
 * reservation is ONE indivisible step. Anything that reads totals, awaits, and
 * then writes has reintroduced the check-then-act bug this exists to kill.
 */

/** A single reservation, pending or settled. */
export interface SpendRecord {
  reservationId: string;
  /** Operator-controlled budget scope. NEVER intent.agentId — see ReserveRequest.scope. */
  scope: string;
  currency: string;
  amountMinor: number;
  /** Epoch ms the reservation was taken — this is what windows are measured against. */
  ms: number;
  /**
   * merchantKeyOf() key this spend belongs to. Absent on records written
   * before merchant windows existed — those count toward EVERY merchant
   * window (deny over guess), and the over-hold self-heals as they age out.
   */
  merchantKey?: string;
  /** "reserved" still counts against every cap: over-hold, never overspend. */
  state: "reserved" | "committed";
}

/**
 * The ONE merchant-identity function. The limiter, the policy engine, and any
 * future consumer (a risk scorer, a reporter) must all call THIS — two
 * implementations would eventually disagree about which merchant a spend
 * belongs to, and the disagreement would quietly split one merchant's count
 * across two budgets.
 *
 * The URL host wins when present and parseable ("host:" + lowercased
 * hostname, single trailing dot stripped); otherwise "id:" + trimmed,
 * lowercased id. The two prefix families are disjoint by construction, so an
 * id crafted to LOOK like a host key ("host:evil") still maps into the "id:"
 * family and cannot collide with any URL-derived key.
 *
 * Merchant fields are attacker-controlled, so a per-merchant window keyed on
 * this is a TIGHTENING, not a boundary — see the velocity docs in types.ts.
 */
export function merchantKeyOf(merchant: Pick<MerchantRef, "id" | "url">): string {
  if (merchant.url !== undefined) {
    try {
      const host = new URL(merchant.url).hostname.toLowerCase().replace(/\.$/, "");
      if (host.length > 0) return `host:${host}`;
    } catch {
      // Unparseable URL: fall through to the id family rather than throwing —
      // the key must exist so the record still lands in SOME merchant budget.
    }
  }
  return `id:${merchant.id.trim().toLowerCase()}`;
}

/**
 * Why a window's CONFIGURATION cannot enforce anything, or null if it can.
 *
 * This exists because a malformed window does not fail loudly on its own: a
 * NaN maxCount or a zero-length windowMs makes every comparison in the
 * evaluation loop false, which reads as "allowed". In 0.3.0 a window with
 * `maxCount: NaN` or `windowMs: 0` silently enforced NOTHING — a live
 * fail-open. (`maxCount: 0` did refuse, with the window's own code; it is
 * rejected here as invalid config so "deny everything" is said once, by one
 * code, instead of masquerading as a velocity denial.)
 *
 * Every implementation calls this for EVERY window BEFORE any cap or count
 * check, and a single malformed window refuses the whole request with
 * SPEND_WINDOW_INVALID: corrupted config is a DoS the operator notices,
 * never an uncapped budget.
 */
export function windowConfigError(w: SpendWindow): string | null {
  if (typeof w.windowMs !== "number" || !Number.isFinite(w.windowMs) || w.windowMs <= 0) {
    return `windowMs ${w.windowMs} is not a positive finite number`;
  }
  if (
    w.capMinor !== undefined &&
    (!Number.isSafeInteger(w.capMinor) || w.capMinor < 0)
  ) {
    return `capMinor ${w.capMinor} is not a non-negative safe integer`;
  }
  if (
    w.maxCount !== undefined &&
    (!Number.isSafeInteger(w.maxCount) || w.maxCount < 1)
  ) {
    return `maxCount ${w.maxCount} is not a positive integer`;
  }
  if (w.capMinor === undefined && w.maxCount === undefined) {
    return "neither capMinor nor maxCount is set — the window would enforce nothing";
  }
  if (
    w.dimension !== undefined &&
    w.dimension !== "scope" &&
    w.dimension !== "merchant"
  ) {
    // An unrecognized dimension must not degrade to scope-wide counting: the
    // operator asked for a partition this code does not implement.
    return `dimension ${JSON.stringify(w.dimension)} is not "scope" or "merchant"`;
  }
  return null;
}

/**
 * Evaluate every window against existing records. Returns the code of the
 * first window that refuses, or null if all pass.
 *
 * Shared by every implementation so the semantics cannot drift between stores.
 * A store's only job is to make the call to this function, plus the insert
 * that follows it, atomic.
 */
export function firstViolatedWindow(
  windows: SpendWindow[],
  existing: ReadonlyArray<Pick<SpendRecord, "amountMinor" | "ms" | "merchantKey">>,
  amountMinor: number,
  nowMs: number,
  merchantKey?: string,
): { code: string; message: string } | null {
  // EVERY window's configuration is validated BEFORE any cap or count check.
  // A malformed window (NaN maxCount, windowMs 0) turns every comparison
  // below false — silently enforcing nothing — so it must refuse everything
  // instead. See windowConfigError().
  for (const w of windows) {
    const problem = windowConfigError(w);
    if (problem) {
      return {
        code: "SPEND_WINDOW_INVALID",
        message: `window "${w.code}" is misconfigured (${problem}); refusing everything under this policy rather than enforcing nothing`,
      };
    }
  }

  // Fail closed on an unusable amount rather than letting NaN comparisons
  // silently evaluate to false and admit the spend.
  if (!Number.isSafeInteger(amountMinor) || amountMinor < 0) {
    return {
      code: "SPEND_AMOUNT_INVALID",
      message: `amount ${amountMinor} is not a non-negative safe integer`,
    };
  }

  for (const w of windows) {
    const perMerchant = w.dimension === "merchant";
    if (perMerchant && merchantKey === undefined) {
      // A merchant window that cannot attribute this spend must refuse it —
      // skipping would let any caller opt out of the window by omission.
      return {
        code: "MERCHANT_KEY_MISSING",
        message: `window "${w.code}" counts per merchant but the request carries no merchantKey`,
      };
    }
    const since = nowMs - w.windowMs;
    let totalMinor = 0;
    let count = 0;
    for (const r of existing) {
      if (r.ms <= since) continue;
      // A keyless record (written before merchant windows existed) counts
      // toward EVERY merchant: bounded over-hold, deny over guess, and it
      // self-heals as the record ages out of the window.
      if (perMerchant && r.merchantKey !== undefined && r.merchantKey !== merchantKey) {
        continue;
      }
      totalMinor += r.amountMinor;
      count += 1;
    }

    if (w.capMinor !== undefined) {
      if (!Number.isSafeInteger(totalMinor) || totalMinor + amountMinor > w.capMinor) {
        return {
          code: w.code,
          message: `spent ${totalMinor} in window; +${amountMinor} would exceed limit ${w.capMinor}`,
        };
      }
    }

    if (w.maxCount !== undefined && count + 1 > w.maxCount) {
      return {
        code: w.code,
        message: `${count} transactions in window; limit is ${w.maxCount}`,
      };
    }
  }

  return null;
}

/**
 * Records for one (scope, currency) pair — the budget a cap applies to.
 *
 * Length-prefixed so ("a b", "c") and ("a", "b c") cannot collide into one
 * budget, which would silently merge two separate caps.
 */
export function scopeKey(scope: string, currency: string): string {
  return `${scope.length}:${scope}:${currency}`;
}

/**
 * Single-process limiter, and the default. Correct within one process because
 * the critical section below contains no `await` — JavaScript cannot interleave
 * it. That property is exactly what a multi-process store has to buy with a
 * lock or a transaction.
 *
 * Does NOT hold across processes. Two MemorySpendLimiters are two separate
 * budgets; use FileSpendLimiter (one box) or a DB-backed limiter for that.
 */
export class MemorySpendLimiter implements SpendLimiter {
  private readonly byScope = new Map<string, SpendRecord[]>();
  private readonly byId = new Map<string, SpendRecord>();

  async reserve(req: ReserveRequest): Promise<ReserveResult> {
    // ---- critical section: no await from here to the insert ----
    const existingClaim = this.byId.get(req.reservationId);
    if (existingClaim) {
      // A retry of the same intent must not consume budget twice.
      return {
        ok: true,
        reservationId: req.reservationId,
        replayed: true,
        state: existingClaim.state,
      };
    }

    const key = scopeKey(req.scope, req.currency);
    const records = this.byScope.get(key) ?? [];
    const violated = firstViolatedWindow(
      req.windows,
      records,
      req.amountMinor,
      req.nowMs,
      req.merchantKey,
    );
    if (violated) return { ok: false, ...violated };

    const record: SpendRecord = {
      reservationId: req.reservationId,
      scope: req.scope,
      currency: req.currency,
      amountMinor: req.amountMinor,
      ms: req.nowMs,
      ...(req.merchantKey !== undefined ? { merchantKey: req.merchantKey } : {}),
      state: "reserved",
    };
    records.push(record);
    this.byScope.set(key, records);
    this.byId.set(req.reservationId, record);
    // ---- end critical section ----

    return { ok: true, reservationId: req.reservationId, replayed: false };
  }

  async commit(reservationId: string): Promise<void> {
    const r = this.byId.get(reservationId);
    if (r) r.state = "committed";
  }

  async release(reservationId: string): Promise<void> {
    const r = this.byId.get(reservationId);
    if (!r) return;
    // Releasing a COMMITTED reservation would un-count real money. Refuse.
    if (r.state === "committed") return;
    this.byId.delete(reservationId);
    const key = scopeKey(r.scope, r.currency);
    const records = this.byScope.get(key);
    if (!records) return;
    const i = records.indexOf(r);
    if (i >= 0) records.splice(i, 1);
  }

  async pruneBefore(beforeMs: number): Promise<number> {
    let removed = 0;
    for (const [key, records] of this.byScope) {
      const keep = records.filter((r) => {
        if (r.ms >= beforeMs) return true;
        this.byId.delete(r.reservationId);
        removed += 1;
        return false;
      });
      if (keep.length === 0) this.byScope.delete(key);
      else this.byScope.set(key, keep);
    }
    return removed;
  }

  /** NOTE: the first argument is the SCOPE (policy id), not an agent id. */
  async totalsSince(
    scope: string,
    sinceIso: string,
    currency: string,
  ): Promise<{ totalMinor: number; count: number }> {
    const since = Date.parse(sinceIso);
    const records = this.byScope.get(scopeKey(scope, currency)) ?? [];
    let totalMinor = 0;
    let count = 0;
    for (const r of records) {
      if (!Number.isFinite(since) || r.ms <= since) continue;
      totalMinor += r.amountMinor;
      count += 1;
    }
    return { totalMinor, count };
  }

  /** Seed history on startup (e.g. from a ledger replay). Counts as committed. */
  hydrate(records: ReadonlyArray<Omit<SpendRecord, "state">>): void {
    for (const r of records) {
      if (this.byId.has(r.reservationId)) continue;
      const rec: SpendRecord = { ...r, state: "committed" };
      const key = scopeKey(r.scope, r.currency);
      const list = this.byScope.get(key) ?? [];
      list.push(rec);
      this.byScope.set(key, list);
      this.byId.set(rec.reservationId, rec);
    }
  }
}
