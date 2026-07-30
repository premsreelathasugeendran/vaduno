import type {
  AgentBlock,
  RegistrySnapshot,
  RevocationRecord,
  RevocationStore,
  StatusPurpose,
} from "@vaduno/revocation";
import { inTransaction, toSafeInt, type PgPool } from "./pg.js";

/** Advisory-lock scope for index allocation. One namespace, one counter. */
const ALLOC_LOCK = "vaduno-revocation-alloc/v1";

interface IndexRow {
  mandate_id: string;
  idx: string | number;
  agent_id: string | null;
}

interface RecordRow {
  mandate_id: string;
  idx: string | number | null;
  purpose: StatusPurpose;
  revoked_at: string;
  reason: string | null;
  revoked_by: string | null;
  agent_id: string | null;
}

function toRecord(r: RecordRow): RevocationRecord {
  return {
    mandateId: r.mandate_id,
    index: r.idx === null ? null : toSafeInt(r.idx, "idx"),
    purpose: r.purpose,
    revokedAt: r.revoked_at,
    reason: r.reason,
    by: r.revoked_by,
    agentId: r.agent_id,
  };
}

/**
 * Postgres-backed RevocationStore — status-list bit indices that stay unique
 * across INSTANCES.
 *
 * WHY THIS EXISTS, and why it is not merely a nice-to-have:
 * `MemoryRevocationStore` allocates indices from `private next = 0`. That is
 * correct inside one process — it never awaits between checking and assigning —
 * and completely wrong across two. Two replicas each hand out index 0, to
 * DIFFERENT mandates. The damage does not stay internal: the index is a bit
 * position in a published W3C Bitstring Status List, so revoking one mandate
 * flips a bit that a third-party verifier reads as revoking the other. A
 * revocation that revokes the wrong credential is worse than one that fails,
 * because it looks like it worked.
 *
 * Two mechanisms, deliberately overlapping:
 *  1. `pg_advisory_xact_lock` serializes allocation, so the read of MAX(idx)
 *     and the insert that follows cannot interleave with another instance's.
 *  2. A UNIQUE constraint on `idx` in the schema. Belt and braces on purpose —
 *     the lock is what makes allocation correct, and the constraint is what
 *     makes a mistake in the lock LOUD instead of silent. This project has
 *     already shipped one check-then-act bug that every sequential test passed;
 *     a database-level invariant is the thing that would have caught it.
 */
export class PostgresRevocationStore implements RevocationStore {
  constructor(private readonly pool: PgPool) {}

  async allocate(
    mandateId: string,
    agentId: string | null,
    capacity: number,
  ): Promise<number | null> {
    return inTransaction(this.pool, async (client) => {
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
        ALLOC_LOCK,
      ]);

      // Idempotent: a mandate that already holds an index keeps it. Allocating
      // a second index for the same mandate would orphan the first bit forever.
      const existing = await client.query<{ idx: string | number }>(
        "SELECT idx FROM vaduno_revocation_index WHERE mandate_id = $1",
        [mandateId],
      );
      const held = existing.rows[0];
      if (held) {
        if (agentId !== null) {
          await client.query(
            "UPDATE vaduno_revocation_index SET agent_id = $2 WHERE mandate_id = $1",
            [mandateId, agentId],
          );
        }
        return toSafeInt(held.idx, "idx");
      }

      // MAX + 1 rather than a sequence: the bit space is a fixed-capacity
      // window that must be densely packed, and a sequence would leak numbers
      // on every rolled-back transaction.
      const max = await client.query<{ next: string | null }>(
        "SELECT MAX(idx) AS next FROM vaduno_revocation_index",
      );
      const next = max.rows[0]?.next === null || max.rows[0]?.next === undefined
        ? 0
        : toSafeInt(max.rows[0].next, "max(idx)") + 1;

      // Exhausted. The caller revokes locally and flags the record
      // `unpublishable` — a full list must never silently reuse a bit.
      if (next >= capacity) return null;

      await client.query(
        "INSERT INTO vaduno_revocation_index (mandate_id, idx, agent_id) VALUES ($1, $2, $3)",
        [mandateId, next, agentId],
      );
      return next;
    });
  }

  async indexOf(mandateId: string): Promise<number | null> {
    const rows = await this.pool.query<{ idx: string | number }>(
      "SELECT idx FROM vaduno_revocation_index WHERE mandate_id = $1",
      [mandateId],
    );
    const row = rows.rows[0];
    return row ? toSafeInt(row.idx, "idx") : null;
  }

  async link(mandateId: string, agentId: string): Promise<void> {
    // A mandate may be linked before it holds an index, so this upserts a row
    // with a NULL-free idx only when one exists; otherwise it records the
    // association on the record side. Keep both in step.
    await this.pool.query(
      `UPDATE vaduno_revocation_index SET agent_id = $2 WHERE mandate_id = $1`,
      [mandateId, agentId],
    );
    await this.pool.query(
      `UPDATE vaduno_revocation_record SET agent_id = $2 WHERE mandate_id = $1`,
      [mandateId, agentId],
    );
  }

  async agentOf(mandateId: string): Promise<string | null> {
    const rows = await this.pool.query<{ agent_id: string | null }>(
      "SELECT agent_id FROM vaduno_revocation_index WHERE mandate_id = $1",
      [mandateId],
    );
    return rows.rows[0]?.agent_id ?? null;
  }

  async mandatesFor(agentId: string): Promise<string[]> {
    const rows = await this.pool.query<IndexRow>(
      "SELECT mandate_id FROM vaduno_revocation_index WHERE agent_id = $1",
      [agentId],
    );
    return rows.rows.map((r) => r.mandate_id);
  }

  async revoke(record: RevocationRecord): Promise<void> {
    await this.pool.query(
      `INSERT INTO vaduno_revocation_record
         (mandate_id, idx, purpose, revoked_at, reason, revoked_by, agent_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (mandate_id) DO UPDATE SET
         idx = EXCLUDED.idx, purpose = EXCLUDED.purpose,
         revoked_at = EXCLUDED.revoked_at, reason = EXCLUDED.reason,
         revoked_by = EXCLUDED.revoked_by, agent_id = EXCLUDED.agent_id`,
      [
        record.mandateId,
        record.index,
        record.purpose,
        record.revokedAt,
        record.reason,
        record.by,
        record.agentId,
      ],
    );
  }

  async clear(mandateId: string): Promise<void> {
    // Clears the REVOCATION, never the index assignment — the bit stays owned
    // by this mandate. Reissuing it to another would make a future revocation
    // flip a bit a verifier already associates with something else.
    await this.pool.query("DELETE FROM vaduno_revocation_record WHERE mandate_id = $1", [
      mandateId,
    ]);
  }

  async get(mandateId: string): Promise<RevocationRecord | null> {
    const rows = await this.pool.query<RecordRow>(
      "SELECT * FROM vaduno_revocation_record WHERE mandate_id = $1",
      [mandateId],
    );
    const row = rows.rows[0];
    return row ? toRecord(row) : null;
  }

  async blockAgent(agentId: string, block: AgentBlock): Promise<void> {
    // Never downgrade a permanent revocation to a liftable suspension — the
    // WHERE clause is the safety property, not an optimization.
    await this.pool.query(
      `INSERT INTO vaduno_agent_block (agent_id, reason, blocked_by, blocked_at, purpose)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (agent_id) DO UPDATE SET
         reason = EXCLUDED.reason, blocked_by = EXCLUDED.blocked_by,
         blocked_at = EXCLUDED.blocked_at, purpose = EXCLUDED.purpose
       WHERE vaduno_agent_block.purpose <> 'revocation'`,
      [agentId, block.reason, block.by, block.at, block.purpose],
    );
  }

  async getAgentBlock(agentId: string): Promise<AgentBlock | null> {
    const rows = await this.pool.query<{
      reason: string | null;
      blocked_by: string | null;
      blocked_at: string;
      purpose: StatusPurpose;
    }>("SELECT reason, blocked_by, blocked_at, purpose FROM vaduno_agent_block WHERE agent_id = $1", [
      agentId,
    ]);
    const row = rows.rows[0];
    return row
      ? { reason: row.reason, by: row.blocked_by, at: row.blocked_at, purpose: row.purpose }
      : null;
  }

  async unblockAgent(agentId: string): Promise<void> {
    await this.pool.query("DELETE FROM vaduno_agent_block WHERE agent_id = $1", [agentId]);
  }

  async isAgentBlocked(agentId: string): Promise<boolean> {
    const rows = await this.pool.query<{ n: string }>(
      "SELECT COUNT(*) AS n FROM vaduno_agent_block WHERE agent_id = $1",
      [agentId],
    );
    return toSafeInt(rows.rows[0]?.n ?? 0, "count") > 0;
  }

  async snapshot(): Promise<RegistrySnapshot> {
    const records = await this.pool.query<RecordRow>(
      "SELECT * FROM vaduno_revocation_record",
    );
    const blocked = await this.pool.query<{ agent_id: string }>(
      "SELECT agent_id FROM vaduno_agent_block",
    );
    const assigned = await this.pool.query<{ n: string | null }>(
      "SELECT MAX(idx) AS n FROM vaduno_revocation_index",
    );
    const maxIdx = assigned.rows[0]?.n;
    return {
      records: records.rows.map(toRecord),
      blockedAgents: blocked.rows.map((r) => r.agent_id),
      assigned: maxIdx === null || maxIdx === undefined ? 0 : toSafeInt(maxIdx, "max(idx)") + 1,
    };
  }
}
