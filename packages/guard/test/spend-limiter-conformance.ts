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
const HOUR_MS = 60 * 60 * 1000;
const SCOPE = "policy-1";
const CUR = "USD";

/** A $50/day cap, in minor units. */
const dayCap = (capMinor: number): SpendWindow => ({
  code: "PER_DAY_LIMIT_EXCEEDED",
  windowMs: DAY_MS,
  capMinor,
});

/** A scope-wide transaction-count window. */
const countWindow = (maxCount: number, windowMs = HOUR_MS): SpendWindow => ({
  code: "VELOCITY_EXCEEDED",
  windowMs,
  maxCount,
});

/** A per-merchant transaction-count window. */
const merchantWindow = (maxCount: number, windowMs = HOUR_MS): SpendWindow => ({
  code: "MERCHANT_VELOCITY_EXCEEDED",
  windowMs,
  maxCount,
  dimension: "merchant",
});

function req(
  id: string,
  amountMinor: number,
  windows: SpendWindow[],
  nowMs: number,
  merchantKey?: string,
): ReserveRequest {
  return {
    scope: SCOPE,
    currency: CUR,
    amountMinor,
    reservationId: id,
    windows,
    ...(merchantKey !== undefined ? { merchantKey } : {}),
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

    it("a reservation id that names an Object.prototype slot is DATA, not a lookup hit", async () => {
      // REGRESSION. reservationId is `intent.id`, a field the threat model
      // assumes the caller controls. An implementation that indexes a plain
      // JS object by it reads `reservations["__proto__"]` back as
      // Object.prototype — TRUTHY — and answers "already reserved" while
      // recording nothing, so the amount never counts against any cap.
      // Measured on FileSpendLimiter before its store was given a null
      // prototype: reserve("__proto__") returned
      // {"ok":true,"reservationId":"__proto__","replayed":true} on an EMPTY
      // limiter, where MemorySpendLimiter (Map-backed, the reference
      // semantics) returned replayed:false. Every Object.prototype member is
      // an instance of this: constructor, toString, valueOf, hasOwnProperty.
      for (const id of ["__proto__", "constructor", "toString", "valueOf"]) {
        await withLimiter(async ([l]) => {
          const first = await l.reserve(req(id, 3_000, [dayCap(5_000)], T0));
          expect(first.ok).toBe(true);
          // A FIRST reservation is never a replay, whatever it is called.
          if (first.ok) expect(first.replayed).toBe(false);
          // And it must actually be counted: 3_000 of 5_000 is spent.
          const totals = await l.totalsSince(
            SCOPE,
            new Date(T0 - DAY_MS).toISOString(),
            CUR,
          );
          expect(totals.totalMinor).toBe(3_000);
          expect((await l.reserve(req("other", 2_001, [dayCap(5_000)], T0))).ok).toBe(false);
        });
      }
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

    // ---- merchant-dimension windows ----------------------------------------

    it("MERCHANT: the third same-merchant reserve is refused; a different merchant in the same scope still fits", async () => {
      // Kills scope-wide counting: if the window ignored merchantKey, the
      // fourth reserve would be refused too.
      await withLimiter(async ([l]) => {
        const w = [merchantWindow(2)];
        expect((await l.reserve(req("a", 100, w, T0, "host:a.example"))).ok).toBe(true);
        expect((await l.reserve(req("b", 100, w, T0, "host:a.example"))).ok).toBe(true);
        const third = await l.reserve(req("c", 100, w, T0, "host:a.example"));
        expect(third.ok).toBe(false);
        if (!third.ok) expect(third.code).toBe("MERCHANT_VELOCITY_EXCEEDED");
        expect((await l.reserve(req("d", 100, w, T0, "host:b.example"))).ok).toBe(true);
      });
    });

    it("MERCHANT: a merchant window with no merchantKey on the request refuses MERCHANT_KEY_MISSING — deny, never skip", async () => {
      // Kills skip-and-allow: omitting the key must not opt a caller out of
      // the window.
      await withLimiter(async ([l]) => {
        const r = await l.reserve(req("a", 100, [merchantWindow(5)], T0));
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe("MERCHANT_KEY_MISSING");
      });
    });

    it("MERCHANT: a keyless (pre-upgrade) record counts toward EVERY merchant window", async () => {
      await withLimiter(async ([l]) => {
        // Seeded the way a 0.3.0 deployment would have: no merchant windows
        // configured, no merchantKey supplied.
        expect((await l.reserve(req("legacy", 100, [dayCap(50_000)], T0))).ok).toBe(true);
        const w = [merchantWindow(1)];
        const a = await l.reserve(req("a", 100, w, T0, "host:a.example"));
        expect(a.ok).toBe(false);
        if (!a.ok) expect(a.code).toBe("MERCHANT_VELOCITY_EXCEEDED");
        const b = await l.reserve(req("b", 100, w, T0, "host:b.example"));
        expect(b.ok).toBe(false);
        if (!b.ok) expect(b.code).toBe("MERCHANT_VELOCITY_EXCEEDED");
      });
    });

    it("SLOTS: a release frees its slot; a committed slot never frees", async () => {
      // Kills decrement-on-any-release: real (committed) money must keep its
      // slot even through a mistaken release.
      await withLimiter(async ([l]) => {
        const w = [countWindow(2)];
        expect((await l.reserve(req("a", 100, w, T0))).ok).toBe(true);
        expect((await l.reserve(req("b", 100, w, T0))).ok).toBe(true);
        expect((await l.reserve(req("c", 100, w, T0))).ok).toBe(false);
        await l.release("b");
        expect((await l.reserve(req("c", 100, w, T0))).ok).toBe(true);
        await l.commit("a");
        await l.release("a"); // must be refused/ignored
        const d = await l.reserve(req("d", 100, w, T0));
        expect(d.ok).toBe(false);
        if (!d.ok) expect(d.code).toBe("VELOCITY_EXCEEDED");
      });
    });

    it("SLOTS: re-reserving the same id against a FULL count window replays and consumes zero extra slots", async () => {
      await withLimiter(async ([l]) => {
        const w = [countWindow(2)];
        expect((await l.reserve(req("a", 100, w, T0))).ok).toBe(true);
        expect((await l.reserve(req("b", 100, w, T0))).ok).toBe(true);
        const again = await l.reserve(req("a", 100, w, T0));
        expect(again.ok).toBe(true);
        if (again.ok) expect(again.replayed).toBe(true);
        const t = await l.totalsSince(SCOPE, new Date(T0 - DAY_MS).toISOString(), CUR);
        expect(t.count).toBe(2);
      });
    });

    it("MULTI-WINDOW: burst AND sustained count limits are both enforced", async () => {
      await withLimiter(async ([l]) => {
        const w = [countWindow(10, 60_000), countWindow(3, DAY_MS)];
        for (const id of ["a", "b", "c"]) {
          expect((await l.reserve(req(id, 100, w, T0))).ok).toBe(true);
        }
        const fourth = await l.reserve(req("d", 100, w, T0));
        expect(fourth.ok).toBe(false);
        if (!fourth.ok) {
          expect(fourth.code).toBe("VELOCITY_EXCEEDED");
          // The SUSTAINED window (limit 3) is the one that refused, not the
          // burst window with room for 10.
          expect(fourth.message).toContain("limit is 3");
        }
      });
    });

    // ---- malformed window config: the fail-open this build closes ----------

    it("FAIL CLOSED: a malformed window refuses SPEND_WINDOW_INVALID rather than enforcing nothing", async () => {
      // In 0.3.0, maxCount: NaN and windowMs: 0 each silently enforced
      // NOTHING (every NaN/empty-window comparison is false = allowed).
      // maxCount: 0 refused, but with the window's own code; it is invalid
      // config and must say so. This test MUST fail against that code.
      await withLimiter(async ([l]) => {
        const cases: Array<[string, SpendWindow]> = [
          ["maxCount NaN", { code: "VELOCITY_EXCEEDED", windowMs: HOUR_MS, maxCount: Number.NaN }],
          ["windowMs 0", { code: "VELOCITY_EXCEEDED", windowMs: 0, maxCount: 1 }],
          ["maxCount 0", { code: "VELOCITY_EXCEEDED", windowMs: HOUR_MS, maxCount: 0 }],
          ["maxCount 2.5", { code: "VELOCITY_EXCEEDED", windowMs: HOUR_MS, maxCount: 2.5 }],
          ["no cap, no count", { code: "PER_DAY_LIMIT_EXCEEDED", windowMs: DAY_MS }],
        ];
        for (const [note, w] of cases) {
          const r = await l.reserve(req(`bad-${note}`, 100, [w], T0));
          expect(r.ok, note).toBe(false);
          if (!r.ok) expect(r.code, note).toBe("SPEND_WINDOW_INVALID");
        }
      });
    });

    it("FAIL CLOSED: one malformed window poisons the whole request even when other windows would pass", async () => {
      await withLimiter(async ([l]) => {
        const w = [dayCap(50_000), { code: "VELOCITY_EXCEEDED", windowMs: HOUR_MS, maxCount: Number.NaN }];
        const r = await l.reserve(req("a", 100, w, T0));
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe("SPEND_WINDOW_INVALID");
        // The refusal reserved nothing.
        const t = await l.totalsSince(SCOPE, new Date(T0 - DAY_MS).toISOString(), CUR);
        expect(t.count).toBe(0);
      });
    });

    it("FAIL CLOSED: config validation runs before ANY cap check, so a malformed window is reported even behind a window that would itself refuse", async () => {
      // The distinguishing case for "validate EVERY window BEFORE any cap or
      // count check". An implementation that validates each window inline —
      // check window 0, then window 1 — passes every other test in this file:
      // it returns window 0's own refusal and never reaches the malformed
      // window 1. Same deny direction, but the operator is told their spend
      // exceeded a cap when the truth is their config is broken, and they go
      // looking for the wrong thing.
      await withLimiter(async ([l]) => {
        const w: SpendWindow[] = [
          // Would refuse on its own: the request is larger than the cap.
          { code: "PER_DAY_LIMIT_EXCEEDED", windowMs: DAY_MS, capMinor: 50 },
          { code: "VELOCITY_EXCEEDED", windowMs: HOUR_MS, maxCount: Number.NaN },
        ];
        const r = await l.reserve(req("ordering", 100, w, T0));
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe("SPEND_WINDOW_INVALID");
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

    it("CONCURRENCY: a per-merchant count window holds under parallel load", async () => {
      // Counts inherit the same atomicity amounts have: 9 parallel reserves
      // for ONE merchant admit exactly 3 under maxCount 3, across handles.
      await withLimiter(async (limiters) => {
        const w = [merchantWindow(3), countWindow(100)];
        const results = await Promise.all(
          Array.from({ length: 9 }, (_, i) =>
            limiters[i % limiters.length].reserve(
              req(`m-${i}`, 1, w, T0, "host:one.example"),
            ),
          ),
        );
        expect(results.filter((r) => r.ok)).toHaveLength(3);
        for (const r of results) {
          if (!r.ok) expect(r.code).toBe("MERCHANT_VELOCITY_EXCEEDED");
        }
      });
    });

    it("CONCURRENCY: three merchants with three slots each all fit; the scope window is untouched", async () => {
      await withLimiter(async (limiters) => {
        const w = [merchantWindow(3), countWindow(100)];
        const results = await Promise.all(
          Array.from({ length: 9 }, (_, i) =>
            limiters[i % limiters.length].reserve(
              req(`m-${i}`, 1, w, T0, `host:m${i % 3}.example`),
            ),
          ),
        );
        // If merchant counting leaked scope-wide, only 3 of these would win.
        expect(results.filter((r) => r.ok)).toHaveLength(9);
      });
    });

    it("CONCURRENCY: a replay storm on one id against a count window claims exactly one slot", async () => {
      // 100 parallel reserves of ONE reservationId: all ok, exactly one did
      // the reserving, and the window holds one slot — so the rail behind it
      // can run at most once.
      await withLimiter(async (limiters) => {
        const w = [countWindow(5)];
        const results = await Promise.all(
          Array.from({ length: 100 }, (_, i) =>
            limiters[i % limiters.length].reserve(req("one-id", 100, w, T0)),
          ),
        );
        expect(results.every((r) => r.ok)).toBe(true);
        const fresh = results.filter((r) => r.ok && !r.replayed);
        expect(fresh).toHaveLength(1);
        const t = await limiters[0].totalsSince(
          SCOPE,
          new Date(T0 - DAY_MS).toISOString(),
          CUR,
        );
        expect(t.count).toBe(1);
      });
    });

    it("CONCURRENCY FLOOD: admitted total EQUALS the cap — never less, never more", async () => {
      // Strictly stronger than "never exceed": 40 racing reserves of 1000
      // against a 5000 cap must admit EXACTLY 5. An inequality (<= cap) is
      // satisfied by a limiter that panics under contention and refuses
      // everything, or by one that serializes and then miscounts downward;
      // exact equality is not. And a check-then-act limiter under genuine
      // overlap admits far more than 5, so the same assertion catches the
      // overspend direction at 4x the contention of the test above.
      await withLimiter(async (limiters) => {
        const N = 40;
        const CAP = 5_000;
        const EACH = 1_000;
        const results = await Promise.all(
          Array.from({ length: N }, (_, i) =>
            limiters[i % limiters.length].reserve(
              req(`flood-${i}`, EACH, [dayCap(CAP)], T0),
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
        expect(totals.totalMinor).toBe(CAP);
        expect(totals.count).toBe(CAP / EACH);

        // Postcondition probes, so "exactly 5" cannot be an accounting fluke:
        // the budget is FULL (one more minor unit is refused) ...
        expect((await limiters[0].reserve(req("flood-probe", 1, [dayCap(CAP)], T0))).ok).toBe(false);
        // ... and it is full by exactly the winners' spend: releasing one
        // winner frees exactly EACH, no more and no less.
        const winner = won[0];
        if (winner?.ok) {
          await limiters[0].release(winner.reservationId);
          expect(
            (await limiters[0].reserve(req("flood-refill", EACH, [dayCap(CAP)], T0))).ok,
          ).toBe(true);
          expect(
            (await limiters[0].reserve(req("flood-probe-2", 1, [dayCap(CAP)], T0))).ok,
          ).toBe(false);
        }
      });
    });

    // ---- window boundary ----------------------------------------------------

    it("BOUNDARY: spend ages out at EXACTLY windowMs — one ms earlier it still counts", async () => {
      // The cap has an edge and both sides of it are load-bearing. If the
      // implementation ages spend out early (>= where > belongs), a payment
      // is admitted while the previous one still occupies the window —
      // overspend. If it ages spend out late (keeps the boundary row), a
      // valid payment is refused — a livelock at every window turnover. The
      // clock is caller-supplied (nowMs), so this is exact and deterministic.
      await withLimiter(async ([l]) => {
        expect((await l.reserve(req("edge-old", 5_000, [dayCap(5_000)], T0))).ok).toBe(true);
        // One ms before the boundary: the old spend still counts.
        const early = await l.reserve(req("edge-early", 1, [dayCap(5_000)], T0 + DAY_MS - 1));
        expect(early.ok).toBe(false);
        if (!early.ok) expect(early.code).toBe("PER_DAY_LIMIT_EXCEEDED");
        // Exactly AT the boundary: the old spend no longer counts, and the
        // full cap is available again.
        expect(
          (await l.reserve(req("edge-new", 5_000, [dayCap(5_000)], T0 + DAY_MS))).ok,
        ).toBe(true);
        // A LAGGING clock (an instance whose nowMs is behind its peer's) sees
        // BOTH reservations inside its window and is refused: clock skew
        // between instances degrades toward denial, never toward a second
        // admission of the same budget.
        expect(
          (await l.reserve(req("edge-lag", 1, [dayCap(5_000)], T0 + DAY_MS - 1))).ok,
        ).toBe(false);
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
