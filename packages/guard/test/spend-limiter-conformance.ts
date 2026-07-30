/**
 * SpendLimiter conformance suite.
 *
 * WHY THIS EXISTS: `SpendLimiter` is the interface that makes "total spend ≤
 * cap" hold across processes. Its types are satisfied by an implementation
 * that reads totals, awaits, and then inserts — which silently lets two
 * workers spend twice the cap. That is the exact bug this interface replaced,
 * and it is invisible to every sequential test. So an implementation is not
 * "done" when it compiles; it is done when it passes this.
 *
 * To write a limiter (Postgres, Redis, DynamoDB):
 *
 * This file is NOT published to npm — @vaduno/guard ships only dist/. Copy it
 * into your repo (it imports only vitest and the package types), or open a PR
 * adding your store here:
 *
 *   import { runSpendLimiterConformance } from "./vendor/spend-limiter-conformance.js";
 *
 *   runSpendLimiterConformance({
 *     name: "PostgresSpendLimiter",
 *     async create() {
 *       const url = await freshDatabase();
 *       return {
 *         // TWO handles on the SAME backing store. A single handle cannot
 *         // exercise the cross-process contract — and a single handle is
 *         // exactly how the original bug hid.
 *         limiters: [new PostgresSpendLimiter(url), new PostgresSpendLimiter(url)],
 *         cleanup: () => dropDatabase(url),
 *       };
 *     },
 *   });
 */
import { describe, expect, it } from "vitest";
import type { ReserveRequest, SpendLimiter, SpendWindow } from "../src/types.js";

export interface SpendLimiterHarness {
  name: string;
  /** Fresh, EMPTY limiter; one or more independent handles on the same state. */
  create(): Promise<{ limiters: SpendLimiter[]; cleanup?: () => Promise<void> }>;
}

const DAY_MS = 24 * 60 * 60 * 1000;
const SCOPE = "policy-1";
const CUR = "USD";

/** A $50/day cap, in minor units. */
const dayCap = (capMinor: number): SpendWindow => ({
  code: "PER_DAY_LIMIT_EXCEEDED",
  windowMs: DAY_MS,
  capMinor,
});

function req(
  id: string,
  amountMinor: number,
  windows: SpendWindow[],
  nowMs: number,
): ReserveRequest {
  return {
    scope: SCOPE,
    currency: CUR,
    amountMinor,
    reservationId: id,
    windows,
    nowMs,
  };
}

export function runSpendLimiterConformance(harness: SpendLimiterHarness): void {
  describe(`SpendLimiter conformance: ${harness.name}`, () => {
    // A fixed clock: these are budget semantics, not timing tests.
    const T0 = 1_700_000_000_000;

    async function withLimiter(
      fn: (limiters: SpendLimiter[]) => Promise<void>,
    ): Promise<void> {
      const { limiters, cleanup } = await harness.create();
      if (limiters.length === 0) throw new Error("harness returned no limiters");
      try {
        await fn(limiters);
      } finally {
        await cleanup?.();
      }
    }

    // ---- basic budget semantics -------------------------------------------

    it("a reservation inside the cap succeeds", async () => {
      await withLimiter(async ([l]) => {
        const r = await l.reserve(req("a", 900, [dayCap(5_000)], T0));
        expect(r.ok).toBe(true);
      });
    });

    it("a reservation that would exceed the cap is refused with the window's code", async () => {
      await withLimiter(async ([l]) => {
        expect((await l.reserve(req("a", 4_500, [dayCap(5_000)], T0))).ok).toBe(true);
        const r = await l.reserve(req("b", 900, [dayCap(5_000)], T0));
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe("PER_DAY_LIMIT_EXCEEDED");
      });
    });

    it("a reservation exactly ON the cap is allowed (inclusive)", async () => {
      await withLimiter(async ([l]) => {
        expect((await l.reserve(req("a", 5_000, [dayCap(5_000)], T0))).ok).toBe(true);
        expect((await l.reserve(req("b", 1, [dayCap(5_000)], T0))).ok).toBe(false);
      });
    });

    it("re-reserving the same id is idempotent and does NOT consume budget twice", async () => {
      await withLimiter(async ([l]) => {
        const first = await l.reserve(req("same", 3_000, [dayCap(5_000)], T0));
        expect(first.ok).toBe(true);
        if (first.ok) expect(first.replayed).toBe(false);

        const again = await l.reserve(req("same", 3_000, [dayCap(5_000)], T0));
        expect(again.ok).toBe(true);
        if (again.ok) expect(again.replayed).toBe(true);

        // Budget consumed once, so 2_000 still fits under 5_000.
        expect((await l.reserve(req("other", 2_000, [dayCap(5_000)], T0))).ok).toBe(true);
      });
    });

    it("spend outside the window no longer counts", async () => {
      await withLimiter(async ([l]) => {
        expect((await l.reserve(req("old", 5_000, [dayCap(5_000)], T0))).ok).toBe(true);
        // One day and change later, the old spend has aged out.
        const later = T0 + DAY_MS + 60_000;
        expect((await l.reserve(req("new", 5_000, [dayCap(5_000)], later))).ok).toBe(true);
      });
    });

    it("different SCOPES have independent budgets", async () => {
      await withLimiter(async ([l]) => {
        expect((await l.reserve(req("a", 5_000, [dayCap(5_000)], T0))).ok).toBe(true);
        const other = { ...req("b", 5_000, [dayCap(5_000)], T0), scope: "policy-2" };
        expect((await l.reserve(other)).ok).toBe(true);
      });
    });

    it("different currencies have independent budgets", async () => {
      await withLimiter(async ([l]) => {
        expect((await l.reserve(req("a", 5_000, [dayCap(5_000)], T0))).ok).toBe(true);
        const other = { ...req("b", 5_000, [dayCap(5_000)], T0), currency: "EUR" };
        expect((await l.reserve(other)).ok).toBe(true);
      });
    });

    it("every window must pass, not just the first", async () => {
      await withLimiter(async ([l]) => {
        const windows: SpendWindow[] = [
          dayCap(100_000),
          { code: "PER_WEEK_LIMIT_EXCEEDED", windowMs: 7 * DAY_MS, capMinor: 5_000 },
        ];
        expect((await l.reserve(req("a", 4_000, windows, T0))).ok).toBe(true);
        const r = await l.reserve(req("b", 4_000, windows, T0));
        expect(r.ok).toBe(false);
        // The DAY cap has room; the WEEK cap is what refuses.
        if (!r.ok) expect(r.code).toBe("PER_WEEK_LIMIT_EXCEEDED");
      });
    });

    it("a count-only window enforces velocity", async () => {
      await withLimiter(async ([l]) => {
        const v: SpendWindow[] = [
          { code: "VELOCITY_EXCEEDED", windowMs: 60_000, maxCount: 2 },
        ];
        expect((await l.reserve(req("a", 1, v, T0))).ok).toBe(true);
        expect((await l.reserve(req("b", 1, v, T0))).ok).toBe(true);
        const third = await l.reserve(req("c", 1, v, T0));
        expect(third.ok).toBe(false);
        if (!third.ok) expect(third.code).toBe("VELOCITY_EXCEEDED");
      });
    });

    it("no windows means no rolling limit", async () => {
      await withLimiter(async ([l]) => {
        for (let i = 0; i < 20; i += 1) {
          expect((await l.reserve(req(`x-${i}`, 1_000_000, [], T0))).ok).toBe(true);
        }
      });
    });

    it("fails closed on a non-integer or negative amount", async () => {
      await withLimiter(async ([l]) => {
        expect((await l.reserve(req("nan", Number.NaN, [dayCap(5_000)], T0))).ok).toBe(false);
        expect((await l.reserve(req("neg", -100, [dayCap(5_000)], T0))).ok).toBe(false);
      });
    });

    // ---- reserved / commit / release ---------------------------------------

    it("a PENDING reservation counts against the cap (over-hold, never overspend)", async () => {
      await withLimiter(async ([l]) => {
        await l.reserve(req("held", 5_000, [dayCap(5_000)], T0)); // never settled
        expect((await l.reserve(req("next", 1, [dayCap(5_000)], T0))).ok).toBe(false);
      });
    });

    it("a COMMITTED reservation still counts", async () => {
      await withLimiter(async ([l]) => {
        await l.reserve(req("a", 5_000, [dayCap(5_000)], T0));
        await l.commit("a");
        expect((await l.reserve(req("b", 1, [dayCap(5_000)], T0))).ok).toBe(false);
      });
    });

    it("a RELEASED reservation frees its budget", async () => {
      await withLimiter(async ([l]) => {
        await l.reserve(req("a", 5_000, [dayCap(5_000)], T0));
        await l.release("a");
        expect((await l.reserve(req("b", 5_000, [dayCap(5_000)], T0))).ok).toBe(true);
      });
    });

    it("releasing a COMMITTED reservation must NOT un-count real money", async () => {
      await withLimiter(async ([l]) => {
        await l.reserve(req("a", 5_000, [dayCap(5_000)], T0));
        await l.commit("a");
        await l.release("a"); // must be refused/ignored
        expect((await l.reserve(req("b", 1, [dayCap(5_000)], T0))).ok).toBe(false);
      });
    });

    it("commit and release are idempotent and safe on unknown ids", async () => {
      await withLimiter(async ([l]) => {
        await l.commit("nope");
        await l.release("nope");
        await l.reserve(req("a", 1_000, [dayCap(5_000)], T0));
        await l.commit("a");
        await l.commit("a");
        expect((await l.reserve(req("b", 4_000, [dayCap(5_000)], T0))).ok).toBe(true);
      });
    });

    it("totalsSince reports reserved + committed spend", async () => {
      await withLimiter(async ([l]) => {
        await l.reserve(req("a", 1_500, [dayCap(50_000)], T0));
        await l.reserve(req("b", 2_500, [dayCap(50_000)], T0));
        await l.commit("b");
        const t = await l.totalsSince(SCOPE, new Date(T0 - DAY_MS).toISOString(), CUR);
        expect(t.totalMinor).toBe(4_000);
        expect(t.count).toBe(2);
      });
    });

    // ---- pruning -----------------------------------------------------------

    it("pruneBefore removes only reservations older than the cutoff", async () => {
      await withLimiter(async ([l]) => {
        await l.reserve(req("old", 1_000, [dayCap(50_000)], T0));
        await l.reserve(req("new", 1_000, [dayCap(50_000)], T0 + DAY_MS));
        expect(await l.pruneBefore(T0 + 1)).toBe(1);
        const t = await l.totalsSince(SCOPE, new Date(T0 - DAY_MS).toISOString(), CUR);
        expect(t.count).toBe(1);
      });
    });

    it("pruning outside every window cannot change a decision", async () => {
      // Safe WITHOUT a caller-supplied condition, unlike consume-store pruning:
      // a reservation already outside the window contributes nothing to any cap,
      // so removing it is unobservable.
      await withLimiter(async ([l]) => {
        await l.reserve(req("aged", 5_000, [dayCap(5_000)], T0));
        const later = T0 + DAY_MS + 60_000;
        // Already aged out, so a fresh reservation fits either way.
        expect((await l.reserve(req("a", 5_000, [dayCap(5_000)], later))).ok).toBe(true);
        await l.pruneBefore(later - DAY_MS);
        expect((await l.reserve(req("b", 1, [dayCap(5_000)], later))).ok).toBe(false);
      });
    });

    // ---- concurrency: the reason this interface exists ---------------------

    it("CONCURRENCY: N parallel reserves never exceed the cap", async () => {
      // THE regression. A check-then-act limiter passes every sequential test
      // above and fails this one: each caller reads "spent 0", sees room, and
      // inserts. Ten workers then spend ten times the cap.
      await withLimiter(async (limiters) => {
        const N = 10;
        const CAP = 5_000;
        const EACH = 1_000; // exactly 5 fit
        const results = await Promise.all(
          Array.from({ length: N }, (_, i) =>
            limiters[i % limiters.length].reserve(
              req(`intent-${i}`, EACH, [dayCap(CAP)], T0),
            ),
          ),
        );
        const won = results.filter((r) => r.ok);
        expect(won).toHaveLength(CAP / EACH);

        const totals = await limiters[0].totalsSince(
          SCOPE,
          new Date(T0 - DAY_MS).toISOString(),
          CUR,
        );
        // The invariant the whole package promises.
        expect(totals.totalMinor).toBeLessThanOrEqual(CAP);
      });
    });

    it("CONCURRENCY: N parallel reserves of the SAME id consume budget once", async () => {
      await withLimiter(async (limiters) => {
        const results = await Promise.all(
          Array.from({ length: 8 }, (_, i) =>
            limiters[i % limiters.length].reserve(
              req("one-intent", 3_000, [dayCap(5_000)], T0),
            ),
          ),
        );
        expect(results.every((r) => r.ok)).toBe(true);
        const totals = await limiters[0].totalsSince(
          SCOPE,
          new Date(T0 - DAY_MS).toISOString(),
          CUR,
        );
        expect(totals.totalMinor).toBe(3_000);
        expect(totals.count).toBe(1);
      });
    });

    it("CONCURRENCY: a velocity window holds under parallel load", async () => {
      await withLimiter(async (limiters) => {
        const v: SpendWindow[] = [
          { code: "VELOCITY_EXCEEDED", windowMs: 60_000, maxCount: 3 },
        ];
        const results = await Promise.all(
          Array.from({ length: 9 }, (_, i) =>
            limiters[i % limiters.length].reserve(req(`v-${i}`, 1, v, T0)),
          ),
        );
        expect(results.filter((r) => r.ok)).toHaveLength(3);
      });
    });

    // ---- cross-handle (i.e. cross-process) ---------------------------------

    it("CROSS-PROCESS: a reservation on one handle is visible to another", async () => {
      await withLimiter(async (limiters) => {
        if (limiters.length < 2) return; // single-process limiter: N/A
        const [a, b] = limiters;
        expect((await a.reserve(req("a", 4_500, [dayCap(5_000)], T0))).ok).toBe(true);
        const r = await b.reserve(req("b", 900, [dayCap(5_000)], T0));
        expect(r.ok).toBe(false);
      });
    });

    it("CROSS-PROCESS: THE HEADLINE — two handles cannot jointly exceed one cap", async () => {
      // Two guard processes, one $50/day cap, each trying to spend $50.
      // With a per-instance limiter this spends $100. It must spend $50.
      await withLimiter(async (limiters) => {
        if (limiters.length < 2) return;
        const [a, b] = limiters;
        const CAP = 5_000;
        const [r1, r2] = await Promise.all([
          a.reserve(req("worker-a", CAP, [dayCap(CAP)], T0)),
          b.reserve(req("worker-b", CAP, [dayCap(CAP)], T0)),
        ]);
        expect([r1.ok, r2.ok].filter(Boolean)).toHaveLength(1);

        const totals = await a.totalsSince(
          SCOPE,
          new Date(T0 - DAY_MS).toISOString(),
          CUR,
        );
        expect(totals.totalMinor).toBe(CAP);
      });
    });

    it("CROSS-PROCESS: a commit on one handle is seen by the other", async () => {
      await withLimiter(async (limiters) => {
        if (limiters.length < 2) return;
        const [a, b] = limiters;
        await a.reserve(req("a", 5_000, [dayCap(5_000)], T0));
        await a.commit("a");
        await b.release("a"); // must not un-count committed money
        expect((await b.reserve(req("b", 1, [dayCap(5_000)], T0))).ok).toBe(false);
      });
    });
  });
}
