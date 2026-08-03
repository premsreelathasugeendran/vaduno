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
import { describe, expect, it } from "vitest";
// The class the conformance suite's handles are typed as. Imported from guard
// SOURCE (like the suites themselves), not "@vaduno/guard": AuditLedger has
// private fields, so the dist declaration is not assignable to the src one.
import { AuditLedger } from "../../guard/src/ledger/ledger.js";
import { VadunoGuard } from "../../guard/src/guard.js";
import { MemoryLedgerStore } from "../../guard/src/ledger/stores/memory.js";
import { runSpendLimiterConformance } from "../../guard/test/spend-limiter-conformance.js";
import { runConsumeStoreConformance } from "../../guard/test/consume-store-conformance.js";
import { runLedgerConcurrencyConformance } from "../../guard/test/ledger-concurrency.conformance.js";
import { runFreezeConformance } from "../../guard/test/freeze.conformance.js";
import { makePolicy } from "../../guard/test/helpers.js";
import { runRevocationStoreConformance } from "../../revocation/test/revocation-store-conformance.js";
import { createFreezeCheck } from "../../revocation/src/guard-hook.js";
import { PostgresSpendLimiter } from "../src/spend-limiter.js";
import { PostgresConsumeStore } from "../src/consume-store.js";
import { PostgresRevocationStore } from "../src/revocation-store.js";
import { PostgresLedgerStore } from "../src/ledger-store.js";
import { PostgresFreezeStore } from "../src/freeze-store.js";
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

  describe("merchant_key migration over an EXISTING vaduno_spend", () => {
    const HOUR_MS = 3_600_000;
    const merchantWindow = {
      code: "MERCHANT_VELOCITY_EXCEEDED",
      windowMs: HOUR_MS,
      maxCount: 1,
      dimension: "merchant" as const,
    };

    it("ADD COLUMN IF NOT EXISTS upgrades a pre-velocity table in place", async () => {
      await reset();
      // Recreate the 0.3.0 shape: the table exists, the column does not.
      await poolA.query("ALTER TABLE vaduno_spend DROP COLUMN IF EXISTS merchant_key");
      await migrate(poolA);
      const cols = await poolA.query<{ column_name: string }>(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'vaduno_spend'",
      );
      expect(cols.rows.map((r) => r.column_name)).toContain("merchant_key");
    });

    it("NULL (pre-upgrade) rows count toward EVERY merchant window", async () => {
      await reset();
      const T0 = 1_700_000_000_000;
      // A row exactly as 0.3.0 wrote it: no merchant_key value at all.
      await poolA.query(
        `INSERT INTO vaduno_spend
           (reservation_id, scope, currency, amount_minor, occurred_ms, state)
         VALUES ('legacy-1', 'policy-1', 'USD', 100, $1, 'committed')`,
        [T0],
      );
      const limiter = new PostgresSpendLimiter(poolB);
      const refused = await limiter.reserve({
        scope: "policy-1",
        currency: "USD",
        amountMinor: 100,
        reservationId: "new-1",
        windows: [merchantWindow],
        merchantKey: "host:never-seen.example",
        nowMs: T0 + 1,
      });
      expect(refused.ok).toBe(false);
      if (!refused.ok) expect(refused.code).toBe("MERCHANT_VELOCITY_EXCEEDED");
    });

    it("merchant_key round-trips: written by one handle, enforced by the other", async () => {
      await reset();
      const T0 = 1_700_000_000_000;
      const a = new PostgresSpendLimiter(poolA);
      const b = new PostgresSpendLimiter(poolB);
      const ok = await a.reserve({
        scope: "policy-1",
        currency: "USD",
        amountMinor: 100,
        reservationId: "rt-1",
        windows: [merchantWindow],
        merchantKey: "host:rt.example",
        nowMs: T0,
      });
      expect(ok.ok).toBe(true);
      const stored = await poolA.query<{ merchant_key: string | null }>(
        "SELECT merchant_key FROM vaduno_spend WHERE reservation_id = 'rt-1'",
      );
      expect(stored.rows[0]?.merchant_key).toBe("host:rt.example");

      const same = await b.reserve({
        scope: "policy-1",
        currency: "USD",
        amountMinor: 100,
        reservationId: "rt-2",
        windows: [merchantWindow],
        merchantKey: "host:rt.example",
        nowMs: T0 + 1,
      });
      expect(same.ok).toBe(false);
      const other = await b.reserve({
        scope: "policy-1",
        currency: "USD",
        amountMinor: 100,
        reservationId: "rt-3",
        windows: [merchantWindow],
        merchantKey: "host:other.example",
        nowMs: T0 + 1,
      });
      expect(other.ok).toBe(true);
    });
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

  // Freeze: the shared TABLE (its one global row) is the resource; each
  // handle gets its own PostgresFreezeStore on its own pool, alternating —
  // two independent connection sets, the same two-instances discipline as
  // above. The outage simulation severs at the pool: every query throws, and
  // the guard must turn that into a denial on EVERY handle (an unreachable
  // freeze store is never "not frozen").
  runFreezeConformance<{ severed: boolean; nextPool: number }>("PostgresFreezeStore", {
    freshResource: async () => {
      await poolA.query("TRUNCATE vaduno_freeze");
      return { severed: false, nextPool: 0 };
    },
    handle: (r, opts) => {
      const base = r.nextPool++ % 2 === 0 ? poolA : poolB;
      const pool: PgPool = {
        connect: () => {
          if (r.severed) throw new Error("freeze backend unreachable (simulated outage)");
          return base.connect();
        },
        query: <R = Record<string, unknown>>(text: string, values?: unknown[]) => {
          if (r.severed) throw new Error("freeze backend unreachable (simulated outage)");
          return base.query<R>(text, values);
        },
      };
      const store = new PostgresFreezeStore(pool);
      const guard = new VadunoGuard({
        policy: makePolicy(),
        // Per-handle ledger, per the suite contract: freeze state must ride
        // the freeze resource, never a shared audit ledger.
        ledger: opts?.ledger ?? new AuditLedger(new MemoryLedgerStore()),
        revocationCheck: createFreezeCheck(store),
      });
      return {
        guard,
        freeze: async (reason) => {
          const snap = await store.freeze(reason);
          // The operator's other hand: also flip the local flag of the one
          // process they stand in. The peer's denial rides on the store.
          await guard.freeze(reason);
          return snap;
        },
        unfreeze: async (expectedEpoch) => {
          const outcome = await store.unfreeze(expectedEpoch);
          if (outcome.ok) await guard.unfreeze();
          return outcome;
        },
        read: () => store.read(),
      };
    },
    breakResource: (r) => {
      r.severed = true;
    },
    healResource: (r) => {
      r.severed = false;
    },
  });
}
