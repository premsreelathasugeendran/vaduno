import {
  firstViolatedWindow,
  type ReserveRequest,
  type ReserveResult,
  type SpendLimiter,
} from "@vaduno/guard";
import { inTransaction, toSafeInt, type PgPool } from "./pg.js";

interface SpendRow {
  amount_minor: string | number;
  occurred_ms: string | number;
}

/**
 * Postgres-backed SpendLimiter — rolling spend caps that hold across MULTIPLE
 * INSTANCES, not just multiple processes on one box.
 *
 * HOW IT IS ATOMIC. The dangerous shape is read-totals → decide → insert, with
 * anything at all in between: two instances both read "spent $0", both pass a
 * $50 check, and the pair spends $100. Two things close it here:
 *
 *  1. `pg_advisory_xact_lock` on (scope, currency), taken as the FIRST
 *     statement of the transaction. Every reserve for that scope is serialized
 *     for the life of the transaction, so the read and the insert cannot
 *     interleave with another instance's.
 *  2. The transaction runs on a DEDICATED pooled connection. Advisory
 *     transaction locks belong to one backend; taking the lock on one pooled
 *     connection and inserting on another would guard nothing.
 *
 * The window arithmetic itself is deliberately NOT reimplemented in SQL — it
 * calls the same `firstViolatedWindow` the in-memory and file limiters use, so
 * the four implementations cannot disagree about what a cap means. The lock is
 * what makes calling it from here safe.
 *
 * Trade-off, stated plainly: an advisory lock serializes reserves per
 * (scope, currency). That is a deliberate choice — correctness over
 * throughput on the path where being wrong means spending someone's money
 * twice. Different scopes never contend.
 */
export class PostgresSpendLimiter implements SpendLimiter {
  constructor(private readonly pool: PgPool) {}

  private static lockKey(scope: string, currency: string): string {
    // Length-prefixed so ("a:b", "c") and ("a", "b:c") cannot collide onto one
    // lock — which would serialize unrelated budgets, or worse, fail to.
    return `vaduno-spend/${scope.length}:${scope}:${currency}`;
  }

  async reserve(req: ReserveRequest): Promise<ReserveResult> {
    return inTransaction(this.pool, async (client) => {
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
        PostgresSpendLimiter.lockKey(req.scope, req.currency),
      ]);

      const dup = await client.query<{ state: "reserved" | "committed" }>(
        "SELECT state FROM vaduno_spend WHERE reservation_id = $1",
        [req.reservationId],
      );
      const dupRow = dup.rows[0];
      if (dupRow) {
        // A retry of the same intent must not consume budget twice.
        return {
          ok: true as const,
          reservationId: req.reservationId,
          replayed: true,
          state: dupRow.state,
        };
      }

      // Only rows that could still be inside SOME window matter. With no
      // windows there is no rolling limit, so nothing needs loading.
      const widest = req.windows.reduce((m, w) => Math.max(m, w.windowMs), 0);
      const existing: Array<{ amountMinor: number; ms: number }> = [];
      if (req.windows.length > 0) {
        const rows = await client.query<SpendRow>(
          `SELECT amount_minor, occurred_ms
             FROM vaduno_spend
            WHERE scope = $1 AND currency = $2 AND occurred_ms > $3`,
          [req.scope, req.currency, req.nowMs - widest],
        );
        for (const r of rows.rows) {
          existing.push({
            amountMinor: toSafeInt(r.amount_minor, "amount_minor"),
            ms: toSafeInt(r.occurred_ms, "occurred_ms"),
          });
        }
      }

      const violated = firstViolatedWindow(
        req.windows,
        existing,
        req.amountMinor,
        req.nowMs,
      );
      if (violated) return { ok: false as const, ...violated };

      await client.query(
        `INSERT INTO vaduno_spend
           (reservation_id, scope, currency, amount_minor, occurred_ms, state)
         VALUES ($1, $2, $3, $4, $5, 'reserved')`,
        [
          req.reservationId,
          req.scope,
          req.currency,
          req.amountMinor,
          req.nowMs,
        ],
      );
      return { ok: true as const, reservationId: req.reservationId, replayed: false };
    });
  }

  async commit(reservationId: string): Promise<void> {
    await this.pool.query(
      "UPDATE vaduno_spend SET state = 'committed' WHERE reservation_id = $1",
      [reservationId],
    );
  }

  async release(reservationId: string): Promise<void> {
    // The state predicate is the safety property: committed spend is real
    // money and must never be un-counted, even by a mistaken call.
    await this.pool.query(
      "DELETE FROM vaduno_spend WHERE reservation_id = $1 AND state = 'reserved'",
      [reservationId],
    );
  }

  async pruneBefore(beforeMs: number): Promise<number> {
    const res = await this.pool.query(
      "DELETE FROM vaduno_spend WHERE occurred_ms < $1",
      [beforeMs],
    );
    return res.rowCount ?? 0;
  }

  /** NOTE: the first argument is the SCOPE (policy id), not an agent id. */
  async totalsSince(
    scope: string,
    sinceIso: string,
    currency: string,
  ): Promise<{ totalMinor: number; count: number }> {
    const since = Date.parse(sinceIso);
    const rows = await this.pool.query<{ total: string | null; n: string }>(
      `SELECT COALESCE(SUM(amount_minor), 0) AS total, COUNT(*) AS n
         FROM vaduno_spend
        WHERE scope = $1 AND currency = $2 AND occurred_ms > $3`,
      [scope, currency, Number.isFinite(since) ? since : 0],
    );
    const row = rows.rows[0];
    if (!row) return { totalMinor: 0, count: 0 };
    return {
      totalMinor: toSafeInt(row.total ?? 0, "sum(amount_minor)"),
      count: toSafeInt(row.n, "count"),
    };
  }
}
