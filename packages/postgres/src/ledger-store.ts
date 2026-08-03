import { GENESIS_HASH } from "@vaduno/guard";
import type {
  ExpectedTip,
  LedgerAppendResult,
  LedgerEntry,
  LedgerStore,
  LedgerTip,
} from "@vaduno/guard";
import { inTransaction, toSafeInt, type PgPool } from "./pg.js";

interface LedgerRow {
  seq: string | number;
  timestamp: string;
  type: LedgerEntry["type"];
  intent_id: string | null;
  agent_id: string | null;
  data: unknown;
  prev_hash: string;
  hash: string;
}

function toEntry(row: LedgerRow): LedgerEntry {
  return {
    seq: toSafeInt(row.seq, "seq"),
    timestamp: row.timestamp,
    type: row.type,
    ...(row.intent_id != null ? { intentId: row.intent_id } : {}),
    ...(row.agent_id != null ? { agentId: row.agent_id } : {}),
    data: row.data,
    prevHash: row.prev_hash,
    hash: row.hash,
  };
}

/** node-postgres surfaces the SQLSTATE as `code`; 23505 = unique_violation. */
function isUniqueViolation(err: unknown): boolean {
  return (err as { code?: string } | null)?.code === "23505";
}

/**
 * Postgres-backed LedgerStore — the audit ledger for multi-instance
 * deployments. This package shipped shared spend caps and shared consume-once
 * with NO shared ledger: the one backend with real transactions was the one
 * backend the ledger could not use. 0.3.0 closes that.
 *
 * Correctness does not come from the code below — it comes from the schema:
 * `seq` PRIMARY KEY admits one row per position and `unique (prev_hash)`
 * admits one child per parent, so a fork is unrepresentable even to a writer
 * that bypasses this class. The hash chain stays CLIENT-SIDE (AuditLedger
 * computes it); this store never assigns seq or hashes anything, which is
 * what keeps server-side tampering detectable by any client.
 *
 * The advisory lock + tip check inside append() exist only to make CAS
 * retries RARE — cooperating writers serialize and mostly succeed first try.
 * A writer that skips the lock still cannot fork; it can only lose to the
 * constraints (23505), which append() reports as a CAS miss with the real
 * tip so AuditLedger re-chains and retries.
 */
export class PostgresLedgerStore implements LedgerStore {
  constructor(private readonly pool: PgPool) {}

  private async tip(): Promise<LedgerTip | null> {
    const res = await this.pool.query<Pick<LedgerRow, "seq" | "hash">>(
      "SELECT seq, hash FROM vaduno_ledger ORDER BY seq DESC LIMIT 1",
    );
    const row = res.rows[0];
    return row ? { seq: toSafeInt(row.seq, "seq"), hash: row.hash } : null;
  }

  async append(
    entry: LedgerEntry,
    expected: ExpectedTip,
  ): Promise<LedgerAppendResult> {
    try {
      return await inTransaction(this.pool, async (client) => {
        await client.query(
          "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
          ["vaduno-ledger"],
        );
        const res = await client.query<Pick<LedgerRow, "seq" | "hash">>(
          "SELECT seq, hash FROM vaduno_ledger ORDER BY seq DESC LIMIT 1",
        );
        const row = res.rows[0];
        const tail = row
          ? { seq: toSafeInt(row.seq, "seq"), hash: row.hash }
          : null;
        const tipSeq = tail ? tail.seq : -1;
        const tipHash = tail ? tail.hash : GENESIS_HASH;
        if (tipSeq !== expected.prevSeq || tipHash !== expected.prevHash) {
          return { ok: false as const, tip: tail };
        }
        await client.query(
          `INSERT INTO vaduno_ledger
             (seq, timestamp, type, intent_id, agent_id, data, prev_hash, hash)
           VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)`,
          [
            entry.seq,
            entry.timestamp,
            entry.type,
            entry.intentId ?? null,
            entry.agentId ?? null,
            JSON.stringify(entry.data),
            entry.prevHash,
            entry.hash,
          ],
        );
        return { ok: true as const };
      });
    } catch (err) {
      // A writer that did not take the advisory lock (hostile, buggy, or a
      // different tool on the same table) beat us to a constraint. That is
      // contention, not store failure: report the real tip and let the
      // caller re-chain. Anything else propagates — an error on a security
      // path must never read as "appended".
      if (isUniqueViolation(err)) {
        return { ok: false, tip: await this.tip() };
      }
      throw err;
    }
  }

  async last(): Promise<LedgerEntry | null> {
    const res = await this.pool.query<LedgerRow>(
      "SELECT * FROM vaduno_ledger ORDER BY seq DESC LIMIT 1",
    );
    const row = res.rows[0];
    return row ? toEntry(row) : null;
  }

  async all(): Promise<LedgerEntry[]> {
    const res = await this.pool.query<LedgerRow>(
      "SELECT * FROM vaduno_ledger ORDER BY seq ASC",
    );
    return res.rows.map(toEntry);
  }
}
