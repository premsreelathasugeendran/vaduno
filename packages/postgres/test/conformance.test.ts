/**
 * Runs the shared conformance suites against a REAL Postgres.
 *
 * There is no mock here on purpose. The entire value of this package is its
 * atomicity under concurrency, and that property lives in Postgres — in
 * `pg_advisory_xact_lock`, in transaction boundaries, in what a pooled
 * connection actually is. A fake that returned the right rows would prove
 * nothing about the only thing worth proving.
 *
 * Set VADUNO_TEST_POSTGRES_URL to run these. CI provides a Postgres service
 * container; see .github/workflows/ci.yml. Without the URL the suite SKIPS —
 * and says so, loudly, because a silent skip reads as a pass.
 */
import { describe, it } from "vitest";
// The class the conformance suite's handles are typed as. Imported from guard
// SOURCE (like the suites themselves), not "@vaduno/guard": AuditLedger has
// private fields, so the dist declaration is not assignable to the src one.
import { AuditLedger } from "../../guard/src/ledger/ledger.js";
import { runSpendLimiterConformance } from "../../guard/test/spend-limiter-conformance.js";
import { runConsumeStoreConformance } from "../../guard/test/consume-store-conformance.js";
import { runLedgerConcurrencyConformance } from "../../guard/test/ledger-concurrency.conformance.js";
import { runRevocationStoreConformance } from "../../revocation/test/revocation-store-conformance.js";
import { PostgresSpendLimiter } from "../src/spend-limiter.js";
import { PostgresConsumeStore } from "../src/consume-store.js";
import { PostgresRevocationStore } from "../src/revocation-store.js";
import { PostgresLedgerStore } from "../src/ledger-store.js";
import { migrate } from "../src/schema.js";
import type { PgPool } from "../src/pg.js";

const URL = process.env.VADUNO_TEST_POSTGRES_URL;

type EndablePool = PgPool & { end(): Promise<void> };

if (!URL) {
  describe("@vaduno/postgres conformance", () => {
    it.skip(
      "SKIPPED — set VADUNO_TEST_POSTGRES_URL to verify against a real Postgres. " +
        "These suites are the only evidence this package is atomic; without them " +
        "it is unverified, not proven.",
      () => {},
    );
  });
} else {
  // Imported lazily so `pg` is only needed when actually testing against it.
  const { Pool } = (await import("pg")) as unknown as {
    Pool: new (cfg: { connectionString: string; max?: number }) => EndablePool;
  };

  /**
   * TWO SEPARATE POOLS on the same database.
   *
   * Two pools rather than two clients of one pool is the whole point: they are
   * independent connection sets, which is what "two instances" means. A single
   * shared pool could mask a bug by happening to serialize work onto one
   * backend.
   */
  const poolA = new Pool({ connectionString: URL, max: 8 });
  const poolB = new Pool({ connectionString: URL, max: 8 });
  await migrate(poolA);

  /** Every harness starts from an empty table pair. */
  async function reset(): Promise<void> {
    await poolA.query(
      "TRUNCATE vaduno_spend, vaduno_consume, vaduno_revocation_index, " +
        "vaduno_revocation_record, vaduno_agent_block",
    );
  }

  runSpendLimiterConformance({
    name: "PostgresSpendLimiter",
    async create() {
      await reset();
      return {
        limiters: [
          new PostgresSpendLimiter(poolA),
          new PostgresSpendLimiter(poolB),
        ],
      };
    },
  });

  runConsumeStoreConformance({
    name: "PostgresConsumeStore",
    async create() {
      await reset();
      return {
        stores: [
          new PostgresConsumeStore(poolA),
          new PostgresConsumeStore(poolB),
        ],
      };
    },
  });

  runRevocationStoreConformance({
    name: "PostgresRevocationStore",
    async create() {
      await reset();
      return {
        stores: [
          new PostgresRevocationStore(poolA),
          new PostgresRevocationStore(poolB),
        ],
      };
    },
  });

  // The ledger's backing RESOURCE is the shared table; each handle gets its
  // own store on its own pool, alternating, so "two handles" really is two
  // independent connection sets — the same two-instances discipline as above.
  runLedgerConcurrencyConformance<{ nextPool: number }>("PostgresLedgerStore", {
    freshResource: async () => {
      await poolA.query("TRUNCATE vaduno_ledger");
      return { nextPool: 0 };
    },
    handle: (r) =>
      new AuditLedger(
        new PostgresLedgerStore(r.nextPool++ % 2 === 0 ? poolA : poolB),
      ),
    reader: () => new PostgresLedgerStore(poolA),
  });
}
