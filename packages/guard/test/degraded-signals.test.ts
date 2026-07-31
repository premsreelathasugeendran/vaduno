/**
 * The two degradation signals, and why they must stay apart.
 *
 * `isAuditDegraded()` is the one an operator alarms on — docs/SECURITY-MODEL.md
 * now tells them to. So it has to mean exactly one thing: a durable audit
 * record did not land. It previously also fired when a spend-limiter COMMIT
 * failed, which this code documents as benign (the reservation stays held, so
 * the amount still counts against every cap). A benign condition raising the
 * severe alarm is how the severe alarm gets ignored.
 */
import { describe, expect, it } from "vitest";
import { AuditLedger } from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import { MemorySpendLimiter } from "../src/enforce/spend-limiter.js";
import { VadunoGuard } from "../src/guard.js";
import type { LedgerEntry, LedgerStore } from "../src/ledger/ledger.js";
import type { SpendLimiter } from "../src/types.js";
import { makeIntent, makePolicy } from "./helpers.js";

/** A store that appends fine until told to start failing. */
class FlakyLedgerStore implements LedgerStore {
  failing = false;
  private readonly entries: LedgerEntry[] = [];

  async append(entry: LedgerEntry): Promise<void> {
    if (this.failing) throw new Error("ledger store unavailable");
    this.entries.push(entry);
  }
  async all(): Promise<LedgerEntry[]> {
    return [...this.entries];
  }
  async last(): Promise<LedgerEntry | null> {
    return this.entries[this.entries.length - 1] ?? null;
  }
}

/** A limiter whose commit/release fail, but whose reserve works. */
function limiterWithBrokenCommit(): SpendLimiter {
  const inner = new MemorySpendLimiter();
  return {
    reserve: inner.reserve.bind(inner),
    totalsSince: inner.totalsSince.bind(inner),
    pruneBefore: inner.pruneBefore?.bind(inner),
    async commit() {
      throw new Error("limiter store unavailable");
    },
    async release() {
      throw new Error("limiter store unavailable");
    },
  } as SpendLimiter;
}

const policy = makePolicy();

describe("a failed limiter commit is NOT an audit failure", () => {
  it("sets limiterDegraded, not auditDegraded", async () => {
    const guard = new VadunoGuard({
      policy,
      ledger: new AuditLedger(new MemoryLedgerStore()),
      limiter: limiterWithBrokenCommit(),
    });
    const r = await guard.execute(makeIntent({ id: "i-1" }), async () => ({ ok: true }));

    expect(r.status).toBe("executed");
    expect(guard.isLimiterDegraded()).toBe(true);
    // The load-bearing assertion. If this ever flips true, the severe alarm is
    // firing on a benign over-hold again.
    expect(guard.isAuditDegraded()).toBe(false);
  });

  it("the charge is still counted, which is why the condition is benign", async () => {
    const limiter = limiterWithBrokenCommit();
    const guard = new VadunoGuard({
      policy,
      ledger: new AuditLedger(new MemoryLedgerStore()),
      limiter,
    });
    await guard.execute(makeIntent({ id: "i-1", amount: { amountMinor: 500, currency: "USD" } }),
      async () => ({ ok: true }));
    const t = await limiter.totalsSince(
      policy.id,
      new Date(Date.now() - 86_400_000).toISOString(),
      "USD",
    );
    // Held as a reservation rather than committed — still counted.
    expect(t.totalMinor).toBe(500);
  });

  it("a failed RELEASE also reports limiterDegraded rather than nothing at all", async () => {
    // Note the path: a THROWN executor does not release, it burns — money may
    // have moved. Release is for a payment that provably did not run, which is
    // what releaseSpend() asserts.
    const guard = new VadunoGuard({
      policy,
      ledger: new AuditLedger(new MemoryLedgerStore()),
      limiter: limiterWithBrokenCommit(),
    });
    await guard.authorize(makeIntent({ id: "i-1" }));
    await guard.settle("i-1", { status: "failed", error: "card_declined" });
    await guard.releaseSpend("i-1");

    expect(guard.isLimiterDegraded()).toBe(true);
    expect(guard.isAuditDegraded()).toBe(false);
  });
});

describe("a lost audit record ALWAYS raises the audit alarm", () => {
  it("on the single-call execute() path", async () => {
    const store = new FlakyLedgerStore();
    const guard = new VadunoGuard({
      policy,
      ledger: new AuditLedger(store),
      limiter: new MemorySpendLimiter(),
    });
    const r = await guard.execute(makeIntent({ id: "i-1" }), async () => {
      store.failing = true; // the rail ran; now the audit write fails
      return { ok: true };
    });
    expect(r.status).toBe("executed");
    expect(guard.isAuditDegraded()).toBe(true);
  });

  it("on the TWO-PHASE settle() path — the route every framework integration takes", async () => {
    // This is the case that used to fail silently. @vaduno/agent binds every
    // framework hook to authorize/settle, so a store dropping writes here lost
    // payment records with no signal at all.
    const store = new FlakyLedgerStore();
    const guard = new VadunoGuard({
      policy,
      ledger: new AuditLedger(store),
      limiter: new MemorySpendLimiter(),
    });
    await guard.authorize(makeIntent({ id: "i-1" }));
    store.failing = true;
    await guard.settle("i-1", { status: "executed" });

    expect(guard.isAuditDegraded()).toBe(true);
  });

  it("when the payment FAILED and even that record could not be written", async () => {
    const store = new FlakyLedgerStore();
    const guard = new VadunoGuard({
      policy,
      ledger: new AuditLedger(store),
      limiter: new MemorySpendLimiter(),
    });
    await guard.execute(makeIntent({ id: "i-1" }), async () => {
      store.failing = true;
      throw new Error("rail timeout");
    });
    expect(guard.isAuditDegraded()).toBe(true);
  });

  it("a TOTAL ledger outage denies without executing, and that is not a degradation", async () => {
    // Checked, not assumed: when the very FIRST audit write fails, the guard
    // refuses to operate rather than proceeding blind. No money moved, so no
    // record was lost — this is a clean refusal, and raising the severe alarm
    // for it would be the same over-alarming this file exists to prevent.
    const store = new FlakyLedgerStore();
    let ranTheRail = false;
    const guard = new VadunoGuard({
      policy,
      ledger: new AuditLedger(store),
      limiter: new MemorySpendLimiter(),
    });
    store.failing = true;
    const r = await guard.execute(makeIntent({ id: "i-1" }), async () => {
      ranTheRail = true;
      return { ok: true };
    });

    expect(r.status).toBe("denied");
    expect(ranTheRail).toBe(false);
    expect(guard.isAuditDegraded()).toBe(false);
  });
});

describe("neither flag is set when everything works", () => {
  it("stays clean on a healthy execute", async () => {
    const guard = new VadunoGuard({
      policy,
      ledger: new AuditLedger(new MemoryLedgerStore()),
      limiter: new MemorySpendLimiter(),
    });
    await guard.execute(makeIntent({ id: "i-1" }), async () => ({ ok: true }));
    expect(guard.isAuditDegraded()).toBe(false);
    expect(guard.isLimiterDegraded()).toBe(false);
  });
});
