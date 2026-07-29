/**
 * ConsumeStore conformance suite.
 *
 * WHY THIS EXISTS: the ConsumeStore contract is the single place where this
 * project touches a genuine distributed-systems problem, and the bug that
 * shipped it was a TOCTOU double-spend that every sequential test passed. So
 * "implement the interface" is not a contribution anyone can be confident in —
 * the interface's types are satisfied by an implementation that double-spends.
 * This suite is the oracle. If your store passes it, the atomicity contract
 * holds; if it does not, you have the failing case in your hand.
 *
 * To write a store (Postgres, Redis, DynamoDB, SQLite):
 *
 * This file is NOT published to npm — @vaduno/guard ships only dist/. Copy it
 * into your repo (it imports only vitest and the package types), or open a PR
 * adding your store here:
 *
 *   import { runConsumeStoreConformance } from "./vendor/consume-store-conformance.js";
 *
 *   runConsumeStoreConformance({
 *     name: "PostgresConsumeStore",
 *     async create() {
 *       const url = await freshDatabase();
 *       return {
 *         // TWO handles on the SAME backing store. This is the point: a
 *         // single handle cannot exercise the cross-process contract, and a
 *         // single handle is exactly how the original bug hid.
 *         stores: [new PostgresConsumeStore(url), new PostgresConsumeStore(url)],
 *         cleanup: () => dropDatabase(url),
 *       };
 *     },
 *   });
 *
 * A single-process store (MemoryConsumeStore) supplies one handle and the
 * cross-handle cases skip themselves.
 */
import { describe, expect, it } from "vitest";
import {
  UNBOUNDED_USES,
  type ConsumeStore,
  type UseClaim,
} from "../src/enforce/consume-store.js";

export interface ConsumeStoreHarness {
  name: string;
  /**
   * Build a FRESH, EMPTY store and return one or more independent handles to
   * the same backing state. Two or more handles stand in for two processes.
   */
  create(): Promise<{ stores: ConsumeStore[]; cleanup?: () => Promise<void> }>;
}

function mkClaim(mandateId: string, useKey: string, digest = "d".repeat(64)): UseClaim {
  return {
    mandateId,
    useKey,
    intentDigest: digest,
    claimedAt: new Date().toISOString(),
    status: "pending",
  };
}

export function runConsumeStoreConformance(harness: ConsumeStoreHarness): void {
  describe(`ConsumeStore conformance: ${harness.name}`, () => {
    async function withStore(
      fn: (stores: ConsumeStore[]) => Promise<void>,
    ): Promise<void> {
      const { stores, cleanup } = await harness.create();
      if (stores.length === 0) throw new Error("harness returned no stores");
      try {
        await fn(stores);
      } finally {
        await cleanup?.();
      }
    }

    // ---- single-claim semantics -------------------------------------------

    it("an unclaimed use is won, and reports a used count of 1", async () => {
      await withStore(async ([s]) => {
        const r = await s.claim(mkClaim("m", "i-1"), 5);
        expect(r.winner).toBe(true);
        if (r.winner) expect(r.used).toBe(1);
      });
    });

    it("get() returns null for a use that was never claimed", async () => {
      await withStore(async ([s]) => {
        expect(await s.get("m", "nope")).toBeNull();
        expect(await s.countClaims("m")).toBe(0);
      });
    });

    it("re-claiming the same (mandateId, useKey) is a duplicate, not a second use", async () => {
      await withStore(async ([s]) => {
        await s.claim(mkClaim("m", "i-1"), 5);
        const again = await s.claim(mkClaim("m", "i-1"), 5);
        expect(again.winner).toBe(false);
        if (!again.winner) {
          expect(again.reason).toBe("duplicate");
          if (again.reason === "duplicate") expect(again.existing.useKey).toBe("i-1");
        }
        // A duplicate must NOT inflate the used count.
        expect(await s.countClaims("m")).toBe(1);
      });
    });

    it("a claim beyond maxUses is refused as exhausted", async () => {
      await withStore(async ([s]) => {
        expect((await s.claim(mkClaim("m", "i-1"), 1)).winner).toBe(true);
        const r = await s.claim(mkClaim("m", "i-2"), 1);
        expect(r.winner).toBe(false);
        if (!r.winner) expect(r.reason).toBe("exhausted");
      });
    });

    it("a PENDING claim still counts against the budget (over-hold, never overspend)", async () => {
      await withStore(async ([s]) => {
        await s.claim(mkClaim("m", "i-1"), 1); // never settled
        const r = await s.claim(mkClaim("m", "i-2"), 1);
        expect(r.winner).toBe(false);
        expect((await s.get("m", "i-1"))?.status).toBe("pending");
      });
    });

    it("mandates have independent budgets", async () => {
      await withStore(async ([s]) => {
        expect((await s.claim(mkClaim("m-a", "i-1"), 1)).winner).toBe(true);
        expect((await s.claim(mkClaim("m-b", "i-1"), 1)).winner).toBe(true);
        expect(await s.countClaims("m-a")).toBe(1);
        expect(await s.countClaims("m-b")).toBe(1);
      });
    });

    it("UNBOUNDED_USES admits replay of history without hitting a budget", async () => {
      await withStore(async ([s]) => {
        for (let i = 0; i < 50; i += 1) {
          expect((await s.claim(mkClaim("m", `h-${i}`), UNBOUNDED_USES)).winner).toBe(true);
        }
        expect(await s.countClaims("m")).toBe(50);
      });
    });

    // ---- settle ------------------------------------------------------------

    it("settle records a terminal outcome that get() replays", async () => {
      await withStore(async ([s]) => {
        await s.claim(mkClaim("m", "i-1"), 1);
        await s.settle("m", "i-1", {
          status: "executed",
          settledAt: new Date().toISOString(),
        });
        const got = await s.get("m", "i-1");
        expect(got?.status).toBe("settled");
        expect(got?.outcome?.status).toBe("executed");
      });
    });

    it("settle is idempotent — the FIRST terminal outcome wins", async () => {
      await withStore(async ([s]) => {
        await s.claim(mkClaim("m", "i-1"), 1);
        await s.settle("m", "i-1", { status: "executed", settledAt: "2020-01-01T00:00:00.000Z" });
        await s.settle("m", "i-1", { status: "failed", settledAt: "2020-01-02T00:00:00.000Z" });
        // A later write must never downgrade an executed charge to failed:
        // that would let a retry re-run a rail that already moved money.
        expect((await s.get("m", "i-1"))?.outcome?.status).toBe("executed");
      });
    });

    it("settling does not change the used count", async () => {
      await withStore(async ([s]) => {
        await s.claim(mkClaim("m", "i-1"), 2);
        await s.settle("m", "i-1", { status: "executed", settledAt: new Date().toISOString() });
        expect(await s.countClaims("m")).toBe(1);
      });
    });

    // ---- concurrency: the part that actually matters -----------------------

    it("CONCURRENCY: N parallel claims of the SAME use yield exactly one winner", async () => {
      await withStore(async (stores) => {
        const N = 8;
        const results = await Promise.all(
          Array.from({ length: N }, (_, i) =>
            stores[i % stores.length].claim(mkClaim("m", "same-intent"), 4),
          ),
        );
        expect(results.filter((r) => r.winner)).toHaveLength(1);
        for (const r of results) {
          if (!r.winner) expect(r.reason).toBe("duplicate");
        }
        expect(await stores[0].countClaims("m")).toBe(1);
      });
    });

    it("CONCURRENCY: N parallel claims of DIFFERENT uses never exceed maxUses", async () => {
      // THE regression. The original bug was a check-then-act maxUses gate:
      // every caller counted, saw room, then inserted. Sequential tests all
      // passed. Two racing processes both won a single-use budget.
      await withStore(async (stores) => {
        const N = 10;
        const maxUses = 3;
        const results = await Promise.all(
          Array.from({ length: N }, (_, i) =>
            stores[i % stores.length].claim(mkClaim("m", `intent-${i}`), maxUses),
          ),
        );
        expect(results.filter((r) => r.winner)).toHaveLength(maxUses);
        expect(await stores[0].countClaims("m")).toBe(maxUses);
        for (const r of results) {
          if (!r.winner) expect(r.reason).toBe("exhausted");
        }
      });
    });

    it("CONCURRENCY: a single-use budget raced by different intents admits exactly one", async () => {
      await withStore(async (stores) => {
        const results = await Promise.all(
          Array.from({ length: 6 }, (_, i) =>
            stores[i % stores.length].claim(mkClaim("m", `intent-${i}`), 1),
          ),
        );
        expect(results.filter((r) => r.winner)).toHaveLength(1);
      });
    });

    it("CONCURRENCY: parallel settles of one claim leave one coherent outcome", async () => {
      await withStore(async (stores) => {
        await stores[0].claim(mkClaim("m", "i-1"), 1);
        await Promise.all(
          Array.from({ length: 6 }, (_, i) =>
            stores[i % stores.length].settle("m", "i-1", {
              status: "executed",
              settledAt: new Date().toISOString(),
            }),
          ),
        );
        const got = await stores[0].get("m", "i-1");
        expect(got?.status).toBe("settled");
        expect(got?.outcome?.status).toBe("executed");
        expect(await stores[0].countClaims("m")).toBe(1);
      });
    });

    // ---- cross-handle (i.e. cross-process) ---------------------------------

    it("CROSS-PROCESS: a claim on one handle is visible from another", async () => {
      await withStore(async (stores) => {
        if (stores.length < 2) return; // single-process store: not applicable
        const [a, b] = stores;
        await a.claim(mkClaim("m", "i-1"), 2);
        expect((await b.get("m", "i-1"))?.useKey).toBe("i-1");
        expect(await b.countClaims("m")).toBe(1);
      });
    });

    it("CROSS-PROCESS: a budget exhausted on one handle is exhausted on the other", async () => {
      await withStore(async (stores) => {
        if (stores.length < 2) return;
        const [a, b] = stores;
        expect((await a.claim(mkClaim("m", "i-1"), 1)).winner).toBe(true);
        const r = await b.claim(mkClaim("m", "i-2"), 1);
        expect(r.winner).toBe(false);
        if (!r.winner) expect(r.reason).toBe("exhausted");
      });
    });

    it("CROSS-PROCESS: an outcome settled on one handle replays on the other", async () => {
      await withStore(async (stores) => {
        if (stores.length < 2) return;
        const [a, b] = stores;
        await a.claim(mkClaim("m", "i-1"), 1);
        await a.settle("m", "i-1", {
          status: "executed",
          settledAt: new Date().toISOString(),
        });
        const dup = await b.claim(mkClaim("m", "i-1"), 1);
        expect(dup.winner).toBe(false);
        if (!dup.winner && dup.reason === "duplicate") {
          expect(dup.existing.outcome?.status).toBe("executed");
        }
      });
    });
  });
}
