/**
 * Runs the ledger concurrent-writer conformance suite against every store
 * that ships with the guard. A new store (Postgres, Redis, SQLite) should be
 * added here — or run the suite from its own repo. See CONTRIBUTING.md.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { AuditLedger } from "../src/ledger/ledger.js";
import { JsonlLedgerStore } from "../src/ledger/stores/jsonl.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import { SupabaseLedgerStore } from "../src/ledger/stores/supabase.js";
import type { SupabaseLikeClient } from "../src/ledger/stores/supabase.js";
import { runLedgerConcurrencyConformance } from "./ledger-concurrency.conformance.js";

// Memory: the store object IS the backing resource — no second process can
// exist, so several AuditLedger instances over one object is the honest
// analogue of "several writers".
runLedgerConcurrencyConformance<MemoryLedgerStore>("MemoryLedgerStore", {
  freshResource: () => new MemoryLedgerStore(),
  handle: (store) => new AuditLedger(store),
  reader: (store) => store,
});

// Jsonl: the PATH is the backing resource. Every handle mints its own store,
// exactly as two processes on one box would — which is why a queue moved into
// the store object (it serializes only handles that share the object) still
// fails here, as it must.
runLedgerConcurrencyConformance<string>("JsonlLedgerStore", {
  freshResource: async () => {
    const dir = await mkdtemp(join(tmpdir(), "vaduno-ledger-conc-"));
    return join(dir, "ledger.jsonl");
  },
  handle: (path) => new AuditLedger(new JsonlLedgerStore(path)),
  reader: (path) => new JsonlLedgerStore(path),
  dispose: (path) => rm(dirname(path), { recursive: true, force: true }),
});

// Supabase: the TABLE is the backing resource; each handle gets its own store
// and its own client over the shared row array. The fake enforces exactly the
// two constraints supabase/schema.sql declares — seq primary key, unique
// prev_hash — atomically (one synchronous body), answering the loser with
// SQLSTATE 23505 the way PostgREST passes it through. What this proves is the
// CLIENT side: that SupabaseLedgerStore classifies 23505 as contention and
// AuditLedger re-chains instead of dropping the entry — the quiet pre-0.3.0
// failure where the losing insert was rethrown, swallowed into auditDegraded,
// and verify() stayed green over a missing payment record. What it cannot
// prove is the constraints' own atomicity; that is Postgres's guarantee,
// exercised for real by the env-gated @vaduno/postgres conformance run.
interface FakeRow {
  seq: number;
  timestamp: string;
  type: string;
  intent_id: string | null;
  agent_id: string | null;
  data: unknown;
  prev_hash: string;
  hash: string;
}

function fakePostgrest(table: FakeRow[]): SupabaseLikeClient {
  const query = (rows: FakeRow[]) =>
    Promise.resolve({ data: rows as unknown[], error: null });
  return {
    from: () => ({
      insert: (values: unknown) => {
        const row = values as FakeRow;
        // Constraint checks and the push in one synchronous body — the
        // fake's stand-in for the database's real atomicity.
        const dup = table.some((r) => r.seq === row.seq)
          ? "vaduno_ledger_pkey"
          : table.some((r) => r.prev_hash === row.prev_hash)
            ? "vaduno_ledger_prev_hash_key"
            : null;
        if (dup) {
          return Promise.resolve({
            error: {
              message: `duplicate key value violates unique constraint "${dup}"`,
              code: "23505",
            },
          });
        }
        table.push(row);
        return Promise.resolve({ error: null });
      },
      select: () => ({
        order: (_col: string, opts?: { ascending?: boolean }) => {
          const asc = opts?.ascending !== false;
          const sorted = [...table].sort((a, b) =>
            asc ? a.seq - b.seq : b.seq - a.seq,
          );
          return Object.assign(query(sorted), {
            limit: (n: number) => query(sorted.slice(0, n)),
            range: (from: number, to: number) =>
              query(sorted.slice(from, to + 1)),
          });
        },
      }),
    }),
  };
}

runLedgerConcurrencyConformance<FakeRow[]>(
  "SupabaseLedgerStore (schema-faithful fake)",
  {
    freshResource: () => [],
    handle: (table) => new AuditLedger(new SupabaseLedgerStore(fakePostgrest(table))),
    reader: (table) => new SupabaseLedgerStore(fakePostgrest(table)),
  },
);
