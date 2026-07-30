import type {
  ClaimResult,
  ConsumeStore,
  StoredOutcome,
  UseClaim,
} from "@vaduno/guard";
import { inTransaction, toSafeInt, type PgPool } from "./pg.js";

interface ClaimRow {
  mandate_id: string;
  use_key: string;
  intent_digest: string;
  claimed_at: string;
  status: "pending" | "settled";
  outcome: StoredOutcome | null;
}

function toClaim(row: ClaimRow): UseClaim {
  return {
    mandateId: row.mandate_id,
    useKey: row.use_key,
    intentDigest: row.intent_digest,
    claimedAt: row.claimed_at,
    status: row.status,
    ...(row.outcome ? { outcome: row.outcome } : {}),
  };
}

/**
 * Postgres-backed ConsumeStore — consume-once mandates that hold across
 * MULTIPLE INSTANCES.
 *
 * Two constraints have to hold together inside one `claim()`, and getting only
 * the first is the classic mistake:
 *
 *  - UNIQUENESS: the same (mandate, intent id) claims at most one use. The
 *    PRIMARY KEY gives this for free.
 *  - BUDGET: N *different* intents against one mandate cannot jointly exceed
 *    `maxUses`. A primary key does nothing here, and counting before inserting
 *    is a TOCTOU: two instances both count `used = 0`, both see room under
 *    maxUses = 1, and both win. That was a real shipped bug in this project.
 *
 * So the count and the insert run under `pg_advisory_xact_lock` on the mandate
 * id, on a dedicated pooled connection, in one transaction — the same
 * structure `PostgresSpendLimiter` uses, for the same reason.
 */
export class PostgresConsumeStore implements ConsumeStore {
  constructor(private readonly pool: PgPool) {}

  private static scope(mandateId: string): string {
    return `vaduno-consume/${mandateId}`;
  }

  async claim(claim: UseClaim, maxUses: number): Promise<ClaimResult> {
    return inTransaction(this.pool, async (client) => {
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
        PostgresConsumeStore.scope(claim.mandateId),
      ]);

      const dup = await client.query<ClaimRow>(
        "SELECT * FROM vaduno_consume WHERE mandate_id = $1 AND use_key = $2",
        [claim.mandateId, claim.useKey],
      );
      const existingRow = dup.rows[0];
      if (existingRow) {
        return {
          winner: false as const,
          reason: "duplicate" as const,
          existing: toClaim(existingRow),
        };
      }

      const counted = await client.query<{ n: string }>(
        "SELECT COUNT(*) AS n FROM vaduno_consume WHERE mandate_id = $1",
        [claim.mandateId],
      );
      const used = toSafeInt(counted.rows[0]?.n ?? 0, "count");
      if (used >= maxUses) {
        return { winner: false as const, reason: "exhausted" as const, used };
      }

      await client.query(
        `INSERT INTO vaduno_consume
           (mandate_id, use_key, intent_digest, claimed_at, status, outcome)
         VALUES ($1, $2, $3, $4, 'pending', NULL)`,
        [claim.mandateId, claim.useKey, claim.intentDigest, claim.claimedAt],
      );
      return { winner: true as const, used: used + 1 };
    });
  }

  async settle(
    mandateId: string,
    useKey: string,
    outcome: StoredOutcome,
  ): Promise<void> {
    // First terminal outcome wins: a later write must never downgrade an
    // executed charge to failed, which would let a retry re-run the rail.
    await this.pool.query(
      `UPDATE vaduno_consume
          SET status = 'settled', outcome = $3::jsonb
        WHERE mandate_id = $1 AND use_key = $2 AND status = 'pending'`,
      [mandateId, useKey, JSON.stringify(outcome)],
    );
  }

  async get(mandateId: string, useKey: string): Promise<UseClaim | null> {
    const rows = await this.pool.query<ClaimRow>(
      "SELECT * FROM vaduno_consume WHERE mandate_id = $1 AND use_key = $2",
      [mandateId, useKey],
    );
    const row = rows.rows[0];
    return row ? toClaim(row) : null;
  }

  async pruneMandates(mandateIds: readonly string[]): Promise<number> {
    if (mandateIds.length === 0) return 0;
    const res = await this.pool.query(
      "DELETE FROM vaduno_consume WHERE mandate_id = ANY($1::text[])",
      [[...mandateIds]],
    );
    return res.rowCount ?? 0;
  }

  async countClaims(mandateId: string): Promise<number> {
    const rows = await this.pool.query<{ n: string }>(
      "SELECT COUNT(*) AS n FROM vaduno_consume WHERE mandate_id = $1",
      [mandateId],
    );
    return toSafeInt(rows.rows[0]?.n ?? 0, "count");
  }
}
