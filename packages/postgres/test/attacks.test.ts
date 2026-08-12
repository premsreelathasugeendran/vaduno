/**
 * Attacks against the Postgres stores that the shared conformance suites
 * cannot express: session-level isolation overrides, fault injection inside
 * the transaction, backend termination mid-reserve, lock-scope collisions,
 * and window-boundary races across two pools.
 *
 * Same discipline as conformance.test.ts: a REAL Postgres or nothing. Every
 * property here lives in the database — in what `BEGIN` pins, in what a
 * terminated backend rolls back, in which snapshot a waiter reads after it
 * acquires an advisory lock. A fake that returned plausible rows would prove
 * none of it, and a pass against a fake is worse than no test at all.
 *
 * Set VADUNO_TEST_POSTGRES_URL to run these. CI provides a Postgres service
 * container; see .github/workflows/ci.yml. Without the URL the suite SKIPS —
 * and says so, loudly, because a silent skip reads as a pass.
 */
import { afterAll, describe, expect, it } from "vitest";
import type { ReserveRequest, SpendWindow } from "../../guard/src/types.js";
import type { UseClaim } from "../../guard/src/enforce/consume-store.js";
import { PostgresSpendLimiter } from "../src/spend-limiter.js";
import { PostgresConsumeStore } from "../src/consume-store.js";
import { migrate } from "../src/schema.js";
import type { PgClient, PgPool } from "../src/pg.js";

const URL = process.env.VADUNO_TEST_POSTGRES_URL;

type EndablePool = PgPool & { end(): Promise<void> };

if (!URL) {
  describe("@vaduno/postgres attack suite", () => {
    it.skip(
      "SKIPPED — set VADUNO_TEST_POSTGRES_URL to run the fault-injection and " +
        "isolation attacks against a real Postgres. Without them the stores' " +
        "behavior under aborts, killed backends and non-default isolation is " +
        "unverified, not proven.",
      () => {},
    );
  });
} else {
  const { Pool } = (await import("pg")) as unknown as {
    Pool: new (cfg: { connectionString: string; max?: number }) => EndablePool;
  };

  // TWO SEPARATE POOLS — independent connection sets, i.e. two instances.
  // Same reasoning as conformance.test.ts.
  const poolA = new Pool({ connectionString: URL, max: 8 });
  const poolB = new Pool({ connectionString: URL, max: 8 });
  await migrate(poolA);
  // Rows from a previous local run would replay against this run's
  // reservation ids; start from nothing.
  await poolA.query("TRUNCATE vaduno_spend, vaduno_consume");

  afterAll(async () => {
    await Promise.all([poolA.end(), poolB.end()]);
  });

  const DAY_MS = 24 * 60 * 60 * 1000;
  const T0 = 1_700_000_000_000;
  const CUR = "USD";
  const iso = (ms: number): string => new Date(ms).toISOString();
  const dayCap = (capMinor: number): SpendWindow => ({
    code: "PER_DAY_LIMIT_EXCEEDED",
    windowMs: DAY_MS,
    capMinor,
  });

  function req(
    scope: string,
    id: string,
    amountMinor: number,
    capMinor: number,
    nowMs = T0,
    currency = CUR,
  ): ReserveRequest {
    return {
      scope,
      currency,
      amountMinor,
      reservationId: id,
      windows: [dayCap(capMinor)],
      nowMs,
    };
  }

  function mkClaim(mandateId: string, useKey: string): UseClaim {
    return {
      mandateId,
      useKey,
      intentDigest: "d".repeat(64),
      claimedAt: new Date().toISOString(),
      status: "pending",
    };
  }

  /**
   * A pool whose dedicated connections run `setup` on every checkout — how a
   * deployment's session defaults (set per-database or per-role, outside this
   * package's control) reach the stores.
   */
  function sessionPool(base: EndablePool, setup: string): PgPool {
    return {
      query: <R = Record<string, unknown>>(text: string, values?: unknown[]) =>
        base.query<R>(text, values),
      connect: async () => {
        const client = await base.connect();
        await client.query(setup);
        return client;
      },
    };
  }

  /**
   * A pool whose dedicated connections call `intercept` before forwarding
   * each statement. Throwing from `intercept` simulates a failure at exactly
   * that point of the transaction; the intercept may also reach around the
   * client (e.g. to terminate its backend from the other pool).
   */
  function interceptPool(
    base: EndablePool,
    intercept: (sql: string, client: PgClient) => Promise<void>,
  ): PgPool {
    return {
      query: <R = Record<string, unknown>>(text: string, values?: unknown[]) =>
        base.query<R>(text, values),
      connect: async () => {
        const client = await base.connect();
        const wrapped: PgClient = {
          query: async <R = Record<string, unknown>>(text: string, values?: unknown[]) => {
            await intercept(text, client);
            return client.query<R>(text, values);
          },
          release: (err?: boolean) => client.release(err),
        };
        return wrapped;
      },
    };
  }

  describe("@vaduno/postgres attack suite", () => {
    // ---- 1. isolation-level override ---------------------------------------

    it(
      "ISOLATION: the cap holds exactly even when the session default is REPEATABLE READ",
      async () => {
        // The advisory-lock strategy has a documented failure mode: under
        // REPEATABLE READ, a waiter's snapshot is fixed by its FIRST statement
        // — the lock-acquisition SELECT itself, whose snapshot is taken before
        // it blocks — so after acquiring the lock it still cannot see what the
        // previous holder committed, and every queued reserve passes the same
        // cap. `default_transaction_isolation = 'repeatable read'` is a common
        // global setting and the pool is caller-supplied, so this is a real
        // deployment shape, not a contrivance. The store must pin READ
        // COMMITTED in its own BEGIN; if it ever stops (bare BEGIN), this
        // flood admits ~40 instead of 5 and fails here.
        const rawA = new Pool({ connectionString: URL, max: 8 });
        const rawB = new Pool({ connectionString: URL, max: 8 });
        try {
          const SET_RR =
            "SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL REPEATABLE READ";
          const a = new PostgresSpendLimiter(sessionPool(rawA, SET_RR));
          const b = new PostgresSpendLimiter(sessionPool(rawB, SET_RR));
          const SCOPE = "attack-rr-spend";
          const N = 40;
          const CAP = 5_000;
          const EACH = 1_000;
          const results = await Promise.all(
            Array.from({ length: N }, (_, i) =>
              (i % 2 === 0 ? a : b).reserve(req(SCOPE, `rr-${i}`, EACH, CAP)),
            ),
          );
          expect(results.filter((r) => r.ok)).toHaveLength(CAP / EACH);
          const totals = await a.totalsSince(SCOPE, iso(T0 - DAY_MS), CUR);
          expect(totals.totalMinor).toBe(CAP);
          expect(totals.count).toBe(CAP / EACH);
          expect((await a.reserve(req(SCOPE, "rr-probe", 1, CAP))).ok).toBe(false);

          // Same exposure, same mechanism, for the consume budget.
          const ca = new PostgresConsumeStore(sessionPool(rawA, SET_RR));
          const cb = new PostgresConsumeStore(sessionPool(rawB, SET_RR));
          const M = "attack-rr-mandate";
          const claims = await Promise.all(
            Array.from({ length: N }, (_, i) =>
              (i % 2 === 0 ? ca : cb).claim(mkClaim(M, `rr-i-${i}`), 3),
            ),
          );
          expect(claims.filter((c) => c.winner)).toHaveLength(3);
          expect(await ca.countClaims(M)).toBe(3);
        } finally {
          await Promise.all([rawA.end(), rawB.end()]);
        }
      },
      30_000,
    );

    // ---- 2. aborted transactions must leak nothing --------------------------

    it("ABORT: a reserve whose transaction fails mid-flight or at COMMIT leaks no budget, no row, no lock", async () => {
      // The recurring bug class is a failure reported as success. Both
      // injection points must yield a REJECTION (never {ok:true}) and leave
      // the shared state exactly as if the call had never happened: no row
      // visible to the peer, the full budget still available, and the
      // advisory lock released (the peer's reserve below would hang past the
      // test timeout if the aborted transaction still held it).
      const failurePoints: Array<[string, (sql: string) => boolean]> = [
        // Mid-transaction: the INSERT itself errors (constraint, OOM, network).
        ["insert", (sql) => sql.includes("INSERT INTO vaduno_spend")],
        // The last possible moment: everything succeeded except COMMIT.
        ["commit", (sql) => sql === "COMMIT"],
      ];
      for (const [name, failOn] of failurePoints) {
        const SCOPE = `attack-abort-${name}`;
        let armed = true;
        const failing = interceptPool(poolA, async (sql) => {
          if (armed && failOn(sql)) throw new Error(`injected: ${name} failure`);
        });
        const broken = new PostgresSpendLimiter(failing);
        const clean = new PostgresSpendLimiter(poolB);

        await expect(
          broken.reserve(req(SCOPE, `${name}-victim`, 5_000, 5_000)),
        ).rejects.toThrow("injected");
        armed = false;

        // Nothing leaked into the shared state the peer reads.
        const totals = await clean.totalsSince(SCOPE, iso(T0 - DAY_MS), CUR);
        expect(totals.count, `${name}: aborted reserve left a row`).toBe(0);
        // The budget the aborted reserve would have taken is fully available…
        expect(
          (await clean.reserve(req(SCOPE, `${name}-after`, 5_000, 5_000))).ok,
          `${name}: budget not released by the abort`,
        ).toBe(true);
        // …and exactly that much: the cap still binds.
        expect(
          (await clean.reserve(req(SCOPE, `${name}-probe`, 1, 5_000))).ok,
        ).toBe(false);
      }
    }, 20_000);

    it("ABORT (consume): a claim whose transaction aborts consumes nothing and does not block the retry", async () => {
      const M = "attack-abort-consume";
      let armed = true;
      const failing = interceptPool(poolA, async (sql) => {
        if (armed && sql === "COMMIT") throw new Error("injected: commit failure");
      });
      const broken = new PostgresConsumeStore(failing);
      const clean = new PostgresConsumeStore(poolB);

      await expect(broken.claim(mkClaim(M, "k-1"), 1)).rejects.toThrow("injected");
      armed = false;

      expect(await clean.countClaims(M)).toBe(0);
      expect(await clean.get(M, "k-1")).toBeNull();
      // The retry of the SAME intent must win FRESH — not read the aborted
      // attempt back as a duplicate of a claim that never committed.
      const retry = await clean.claim(mkClaim(M, "k-1"), 1);
      expect(retry.winner).toBe(true);
      if (retry.winner) expect(retry.used).toBe(1);
      // And the budget it holds is real.
      const over = await clean.claim(mkClaim(M, "k-2"), 1);
      expect(over.winner).toBe(false);
      if (!over.winner) expect(over.reason).toBe("exhausted");
    }, 20_000);

    // ---- 3. backend killed mid-reserve --------------------------------------

    it("KILL: a backend terminated mid-reserve leaves no partial state, no leaked budget, no held lock", async () => {
      // Connection loss at the worst possible instant: after the lock, after
      // the reads, with the INSERT about to be sent. Postgres must roll the
      // whole transaction back server-side; the caller must see a rejection;
      // the peer must see nothing at all.
      const SCOPE = "attack-kill";
      let killed = false;
      const killing = interceptPool(poolA, async (sql, client) => {
        if (killed || !sql.includes("INSERT INTO vaduno_spend")) return;
        killed = true;
        // The backend death also fires an 'error' event on the checked-out
        // client with no query in flight; without a listener Node treats it
        // as an uncaught exception and kills the test process instead of
        // failing the test.
        (client as unknown as { on?: (ev: string, fn: () => void) => void }).on?.(
          "error",
          () => {},
        );
        const pid = await client.query<{ pid: number }>(
          "SELECT pg_backend_pid() AS pid",
        );
        await poolB.query("SELECT pg_terminate_backend($1)", [pid.rows[0]?.pid]);
        // Wait until the backend is actually gone, so the INSERT below fails
        // deterministically rather than racing the SIGTERM.
        for (let i = 0; i < 100; i += 1) {
          const alive = await poolB.query<{ n: string }>(
            "SELECT COUNT(*) AS n FROM pg_stat_activity WHERE pid = $1",
            [pid.rows[0]?.pid],
          );
          if (Number(alive.rows[0]?.n ?? "0") === 0) break;
          await new Promise((r) => setTimeout(r, 20));
        }
      });
      const broken = new PostgresSpendLimiter(killing);
      const clean = new PostgresSpendLimiter(poolB);

      await expect(broken.reserve(req(SCOPE, "kill-victim", 5_000, 5_000))).rejects.toThrow();
      expect(killed).toBe(true);

      // No partial state visible to the other instance, no budget held, and
      // the advisory lock died with its backend (this reserve would hang past
      // the timeout otherwise).
      const totals = await clean.totalsSince(SCOPE, iso(T0 - DAY_MS), CUR);
      expect(totals.count).toBe(0);
      expect((await clean.reserve(req(SCOPE, "kill-after", 5_000, 5_000))).ok).toBe(true);
      expect((await clean.reserve(req(SCOPE, "kill-probe", 1, 5_000))).ok).toBe(false);
    }, 20_000);

    // ---- 4. instance death AFTER a successful reserve ------------------------

    it("ORPHAN: a reservation from a dead instance holds budget (over-hold) and is releasable by a peer", async () => {
      // The contract for a crash BETWEEN reserve and settle: the reservation
      // persists, counts against every cap on every instance (over-hold,
      // never overspend), and a peer — an operator's cleanup job — can
      // release it without having created it.
      const SCOPE = "attack-orphan";
      const a = new PostgresSpendLimiter(poolA);
      const b = new PostgresSpendLimiter(poolB);
      expect((await a.reserve(req(SCOPE, "orphan", 5_000, 5_000))).ok).toBe(true);
      // Instance A "dies" here — nothing more happens on poolA.
      const held = await b.totalsSince(SCOPE, iso(T0 - DAY_MS), CUR);
      expect(held.totalMinor).toBe(5_000);
      expect((await b.reserve(req(SCOPE, "blocked", 1, 5_000))).ok).toBe(false);
      await b.release("orphan");
      expect((await b.reserve(req(SCOPE, "recovered", 5_000, 5_000))).ok).toBe(true);
    });

    // ---- 5. lock scope -------------------------------------------------------

    it("LOCK SCOPE: scopes crafted to collide under naive key concatenation keep exact, independent budgets", async () => {
      // lockKey is length-prefixed precisely so ("…a:b", "c") and ("…a",
      // "b:c") cannot map onto one another. Flood both pairs SIMULTANEOUSLY
      // and assert each side's cap EXACTLY: if any layer — the lock key, the
      // row filter, the totals query — confused the two pairs, one side
      // would see the other's spend and admit fewer than its own cap, or a
      // shared lock miskeyed per-request would let one side overspend.
      // Exact equality on both sides catches both directions.
      const S1 = { scope: "attack-lock/a:b", currency: "c" };
      const S2 = { scope: "attack-lock/a", currency: "b:c" };
      const CAP = 3_000;
      const EACH = 1_000;
      const N = 12; // per side
      const mk = (s: typeof S1, id: string): ReserveRequest =>
        req(s.scope, id, EACH, CAP, T0, s.currency);
      const results = await Promise.all(
        Array.from({ length: 2 * N }, (_, i) => {
          const side = i % 2 === 0 ? S1 : S2;
          const limiter = new PostgresSpendLimiter(i % 4 < 2 ? poolA : poolB);
          return limiter
            .reserve(mk(side, `lk-${i}`))
            .then((r) => ({ side, r }));
        }),
      );
      const wins1 = results.filter((x) => x.side === S1 && x.r.ok);
      const wins2 = results.filter((x) => x.side === S2 && x.r.ok);
      expect(wins1).toHaveLength(CAP / EACH);
      expect(wins2).toHaveLength(CAP / EACH);
      const l = new PostgresSpendLimiter(poolA);
      const t1 = await l.totalsSince(S1.scope, iso(T0 - DAY_MS), S1.currency);
      const t2 = await l.totalsSince(S2.scope, iso(T0 - DAY_MS), S2.currency);
      expect(t1.totalMinor).toBe(CAP);
      expect(t2.totalMinor).toBe(CAP);
    }, 20_000);

    // ---- 6. window boundary raced across two instances -----------------------

    it("BOUNDARY RACE: two instances racing at the exact window edge admit the freed budget ONCE", async () => {
      // At T0 the cap is fully spent. At exactly T0+windowMs that spend ages
      // out and the full cap frees — once. Two instances both submitting the
      // full cap at that instant must admit exactly ONE: an implementation
      // whose boundary comparison or lock lets both through has doubled the
      // budget at every window turnover, a scheduled, repeatable overspend.
      const SCOPE = "attack-boundary";
      const a = new PostgresSpendLimiter(poolA);
      const b = new PostgresSpendLimiter(poolB);
      expect((await a.reserve(req(SCOPE, "bd-old", 5_000, 5_000, T0))).ok).toBe(true);
      const edge = T0 + DAY_MS;
      const [r1, r2] = await Promise.all([
        a.reserve(req(SCOPE, "bd-a", 5_000, 5_000, edge)),
        b.reserve(req(SCOPE, "bd-b", 5_000, 5_000, edge)),
      ]);
      expect([r1.ok, r2.ok].filter(Boolean)).toHaveLength(1);
      // Rows strictly inside the new window: exactly the one winner.
      const fresh = await a.totalsSince(SCOPE, iso(T0), CUR);
      expect(fresh.totalMinor).toBe(5_000);
      expect(fresh.count).toBe(1);
    });
  });
}
