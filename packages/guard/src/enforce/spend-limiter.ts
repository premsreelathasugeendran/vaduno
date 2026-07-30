import type {
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
  /** "reserved" still counts against every cap: over-hold, never overspend. */
  state: "reserved" | "committed";
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
  existing: ReadonlyArray<Pick<SpendRecord, "amountMinor" | "ms">>,
  amountMinor: number,
  nowMs: number,
): { code: string; message: string } | null {
  // Fail closed on an unusable amount rather than letting NaN comparisons
  // silently evaluate to false and admit the spend.
  if (!Number.isSafeInteger(amountMinor) || amountMinor < 0) {
    return {
      code: "SPEND_AMOUNT_INVALID",
      message: `amount ${amountMinor} is not a non-negative safe integer`,
    };
  }

  for (const w of windows) {
    const since = nowMs - w.windowMs;
    let totalMinor = 0;
    let count = 0;
    for (const r of existing) {
      if (r.ms <= since) continue;
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
    );
    if (violated) return { ok: false, ...violated };

    const record: SpendRecord = {
      reservationId: req.reservationId,
      scope: req.scope,
      currency: req.currency,
      amountMinor: req.amountMinor,
      ms: req.nowMs,
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
