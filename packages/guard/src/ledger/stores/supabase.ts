import type { LedgerEntry, LedgerStore } from "../ledger.js";

/**
 * Minimal structural type for a Supabase client so this package keeps zero
 * runtime dependencies — pass your own `createClient(...)` instance.
 *
 * `range(from, to)` mirrors PostgREST's inclusive range pagination.
 */
export interface SupabaseLikeClient {
  from(table: string): {
    insert(values: unknown): PromiseLike<{ error: { message: string } | null }>;
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

/**
 * Supabase-backed store. See supabase/schema.sql for the table definition.
 * The hash chain makes server-side tampering detectable by any client that
 * re-runs verify().
 *
 * `all()` pages through the ENTIRE table (PostgREST caps a single response at
 * ~1000 rows). Silent truncation here would make spend limits and verify()
 * fail OPEN, so a short/duplicate page ends paging and the assembled result is
 * checked for a contiguous seq run.
 */
export class SupabaseLedgerStore implements LedgerStore {
  constructor(
    private readonly client: SupabaseLikeClient,
    private readonly table: string = "vaduno_ledger",
  ) {}

  async append(entry: LedgerEntry): Promise<void> {
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
    if (error) throw new Error(`SupabaseLedgerStore.append: ${error.message}`);
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
