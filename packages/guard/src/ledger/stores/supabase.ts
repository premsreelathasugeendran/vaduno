import type {
  ExpectedTip,
  LedgerAppendResult,
  LedgerEntry,
  LedgerStore,
} from "../ledger.js";

/**
 * Minimal structural type for a Supabase client so this package keeps zero
 * runtime dependencies — pass your own `createClient(...)` instance.
 *
 * `code` is PostgREST's pass-through of the Postgres SQLSTATE (supabase-js
 * surfaces it as `PostgrestError.code`); optional so hand-rolled clients and
 * older doubles still satisfy the type.
 *
 * `range(from, to)` mirrors PostgREST's inclusive range pagination.
 */
export interface SupabaseLikeClient {
  from(table: string): {
    insert(
      values: unknown,
    ): PromiseLike<{ error: { message: string; code?: string } | null }>;
    select(columns?: string): {
      order(
        column: string,
        opts?: { ascending?: boolean },
      ): {
        limit(n: number): PromiseLike<QueryResult>;
        range(from: number, to: number): PromiseLike<QueryResult>;
      } & PromiseLike<QueryResult>;
    };
  };
}

interface QueryResult {
  data: unknown[] | null;
  error: { message: string } | null;
}

const PAGE_SIZE = 1000;

/** SQLSTATE 23505 = unique_violation: some writer already holds that seq or
 * that parent. */
const UNIQUE_VIOLATION = "23505";

/**
 * Contention (another writer won the tip) vs genuine failure (store down,
 * schema wrong, RLS denies). Getting this wrong in the strict direction turns
 * every lost race into an AUDIT_WRITE_FAILED deny storm; in the loose
 * direction it burns bounded retries on a dead store, then fails closed
 * anyway — so the loose direction is the safe misread, and the message match
 * exists for clients that drop `code`.
 *
 * Error shape, determined from PostgREST's documented behavior (a failed
 * INSERT returns the Postgres error with its SQLSTATE in `code`; supabase-js
 * surfaces that as `PostgrestError.code`) and NOT verified against a live
 * Supabase instance from this environment — the injected-client contract
 * below is what the tests pin.
 */
function isContention(error: { message: string; code?: string }): boolean {
  if (error.code !== undefined) return error.code === UNIQUE_VIOLATION;
  return /duplicate key value violates unique constraint/i.test(error.message);
}

/**
 * Supabase-backed store. See supabase/schema.sql for the table definition.
 * The hash chain makes server-side tampering detectable by any client that
 * re-runs verify().
 *
 * COMPARE-AND-APPEND lives in the schema, not in client code — PostgREST
 * cannot run a client callback inside a transaction, so this store could
 * never lock-check-insert the way JsonlLedgerStore does. It does not need
 * to: `seq bigint primary key` admits one row per position, and
 * `unique (prev_hash)` admits one child per parent. Together a fork is
 * unrepresentable AT THE DATABASE, even to a buggy or hostile client that
 * ignores `expected` entirely — which is why `expected` is not re-checked
 * here. A losing insert comes back 23505; this store answers with the real
 * tip so AuditLedger can re-chain and retry. Before 0.3.0 that same 23505
 * was rethrown, and on the final `execution_result` append it was swallowed
 * into `auditDegraded`: money moved, the record was DROPPED, and verify()
 * stayed green. The quiet failure this contract exists to kill.
 */
export class SupabaseLedgerStore implements LedgerStore {
  constructor(
    private readonly client: SupabaseLikeClient,
    private readonly table: string = "vaduno_ledger",
  ) {}

  async append(
    entry: LedgerEntry,
    _expected: ExpectedTip,
  ): Promise<LedgerAppendResult> {
    const { error } = await this.client.from(this.table).insert({
      seq: entry.seq,
      timestamp: entry.timestamp,
      type: entry.type,
      intent_id: entry.intentId ?? null,
      agent_id: entry.agentId ?? null,
      data: entry.data,
      prev_hash: entry.prevHash,
      hash: entry.hash,
    });
    if (!error) return { ok: true };
    if (isContention(error)) {
      const tail = await this.last();
      return {
        ok: false,
        tip: tail ? { seq: tail.seq, hash: tail.hash } : null,
      };
    }
    throw new Error(`SupabaseLedgerStore.append: ${error.message}`);
  }

  async last(): Promise<LedgerEntry | null> {
    const { data, error } = await this.client
      .from(this.table)
      .select("*")
      .order("seq", { ascending: false })
      .limit(1);
    if (error) throw new Error(`SupabaseLedgerStore.last: ${error.message}`);
    const row = (data ?? [])[0];
    return row ? rowToEntry(row) : null;
  }

  async all(): Promise<LedgerEntry[]> {
    const out: LedgerEntry[] = [];
    let from = 0;
    for (;;) {
      const { data, error } = await this.client
        .from(this.table)
        .select("*")
        .order("seq", { ascending: true })
        .range(from, from + PAGE_SIZE - 1);
      if (error) throw new Error(`SupabaseLedgerStore.all: ${error.message}`);
      const rows = data ?? [];
      for (const row of rows) out.push(rowToEntry(row));
      if (rows.length < PAGE_SIZE) break;
      from += PAGE_SIZE;
    }

    // Fail closed on any truncation/gap: the seq run must be 0..n-1 contiguous.
    for (let i = 0; i < out.length; i++) {
      if (out[i]!.seq !== i) {
        throw new Error(
          `SupabaseLedgerStore.all: non-contiguous ledger at index ${i} (seq ${out[i]!.seq}); refusing to return a partial chain`,
        );
      }
    }
    return out;
  }
}

function rowToEntry(row: unknown): LedgerEntry {
  const r = row as Record<string, unknown>;
  return {
    seq: r.seq as number,
    timestamp: r.timestamp as string,
    type: r.type as LedgerEntry["type"],
    ...(r.intent_id != null ? { intentId: r.intent_id as string } : {}),
    ...(r.agent_id != null ? { agentId: r.agent_id as string } : {}),
    data: r.data,
    prevHash: r.prev_hash as string,
    hash: r.hash as string,
  };
}
