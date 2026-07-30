/**
 * Two-phase authorize() / settle().
 *
 * WHY IT EXISTS: `execute(intent, executor)` requires the guard to own the
 * payment call, and every agent framework's hook point is decide-only — Claude
 * Agent SDK `PreToolUse`, Vercel AI SDK `toolApproval`, OpenAI Agents
 * `needsApproval`, LangChain `wrapToolCall`. Without this split, none of them
 * can integrate at all, however correct the policy engine is.
 *
 * THE PROPERTY THAT MATTERS: the two paths must never disagree about money.
 * Both run the same pipeline; the only difference is who calls the rail.
 */
import { describe, expect, it } from "vitest";
import { AuditLedger } from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import { MemorySpendLimiter } from "../src/enforce/spend-limiter.js";
import { VadunoGuard } from "../src/guard.js";
import type { SpendLimiter, SpendPolicy } from "../src/types.js";
import { makeIntent } from "./helpers.js";

const CAP = 5_000;

const policy: SpendPolicy = {
  id: "two-phase",
  version: 1,
  currency: "USD",
  limits: { perTransactionMinor: 5_000, perDayMinor: CAP },
  merchants: { allow: ["openai.com"] },
};

function guardOn(limiter: SpendLimiter, extra: Partial<{ approvalHandler: never }> = {}) {
  return new VadunoGuard({
    policy,
    ledger: new AuditLedger(new MemoryLedgerStore()),
    limiter,
    ...extra,
  });
}

const intent = (id: string, amountMinor = 5_000) =>
  makeIntent({ id, amount: { amountMinor, currency: "USD" } });

const since = () => new Date(Date.now() - 86_400_000).toISOString();

describe("authorize decides without running anything", () => {
  it("returns authorized for a permitted intent", async () => {
    const g = guardOn(new MemorySpendLimiter());
    const r = await g.authorize(intent("i-1", 900));
    expect(r.status).toBe("authorized");
  });

  it("denies exactly as execute would", async () => {
    const g = guardOn(new MemorySpendLimiter());
    const overCap = makeIntent({
      id: "i-1",
      amount: { amountMinor: 999_999, currency: "USD" },
    });
    expect((await g.authorize(overCap)).status).toBe("denied");
  });

  it("denies a disallowed merchant", async () => {
    const g = guardOn(new MemorySpendLimiter());
    const evil = makeIntent({
      id: "i-1",
      merchant: { id: "evil", url: "https://evil-openai.com" },
    });
    expect((await g.authorize(evil)).status).toBe("denied");
  });
});

describe("an authorization holds budget — this is the point", () => {
  it("reserves immediately, so a second authorization cannot pass the same cap", async () => {
    // If authorize() only gave an opinion, two concurrent callers would both be
    // told yes and the cap would mean nothing.
    const g = guardOn(new MemorySpendLimiter());
    expect((await g.authorize(intent("i-1", CAP))).status).toBe("authorized");
    expect((await g.authorize(intent("i-2", CAP))).status).toBe("denied");
  });

  it("holds across guards sharing a limiter", async () => {
    const limiter = new MemorySpendLimiter();
    const a = guardOn(limiter);
    const b = guardOn(limiter);
    expect((await a.authorize(intent("i-1", CAP))).status).toBe("authorized");
    expect((await b.authorize(intent("i-2", CAP))).status).toBe("denied");
  });

  it("CONCURRENCY: N parallel authorizations never exceed the cap", async () => {
    const limiter = new MemorySpendLimiter();
    const guards = [guardOn(limiter), guardOn(limiter)];
    const results = await Promise.all(
      Array.from({ length: 10 }, (_, i) =>
        guards[i % guards.length]!.authorize(intent(`i-${i}`, 1_000)),
      ),
    );
    expect(results.filter((r) => r.status === "authorized")).toHaveLength(CAP / 1_000);
  });
});

describe("settle reports the outcome, and matches execute's money rules", () => {
  it("executed commits the spend", async () => {
    const limiter = new MemorySpendLimiter();
    const g = guardOn(limiter);
    await g.authorize(intent("i-1", 1_000));
    await g.settle("i-1", { status: "executed" });
    const t = await limiter.totalsSince(policy.id, since(), "USD");
    expect(t.totalMinor).toBe(1_000);
  });

  it("failed KEEPS the spend counted — same burn-on-failure rule as execute", async () => {
    // A thrown rail may still have moved money, so the amount stays held. If
    // the two paths disagreed here, a framework integration would quietly have
    // weaker guarantees than the built-in one.
    const limiter = new MemorySpendLimiter();
    const g = guardOn(limiter);
    await g.authorize(intent("i-1", CAP));
    await g.settle("i-1", { status: "failed", error: "timeout after charge" });
    expect((await g.authorize(intent("i-2", CAP))).status).toBe("denied");
  });

  it("releaseSpend reclaims a failed authorization when the rail provably didn't charge", async () => {
    const limiter = new MemorySpendLimiter();
    const g = guardOn(limiter);
    await g.authorize(intent("i-1", CAP));
    await g.settle("i-1", { status: "failed", error: "card_declined" });
    await g.releaseSpend("i-1");
    expect((await g.authorize(intent("i-2", CAP))).status).toBe("authorized");
  });

  it("releaseSpend CANNOT un-count a settled-executed authorization", async () => {
    const limiter = new MemorySpendLimiter();
    const g = guardOn(limiter);
    await g.authorize(intent("i-1", CAP));
    await g.settle("i-1", { status: "executed" });
    await g.releaseSpend("i-1");
    expect((await g.authorize(intent("i-2", CAP))).status).toBe("denied");
  });

  it("settle is idempotent and safe on an unknown id", async () => {
    const limiter = new MemorySpendLimiter();
    const g = guardOn(limiter);
    await g.settle("never-authorized", { status: "executed" });
    await g.authorize(intent("i-1", 1_000));
    await g.settle("i-1", { status: "executed" });
    await g.settle("i-1", { status: "executed" });
    const t = await limiter.totalsSince(policy.id, since(), "USD");
    // A retrying caller must not double-count.
    expect(t.totalMinor).toBe(1_000);
  });

  it("an UNSETTLED authorization keeps holding budget", async () => {
    // Deliberate: over-hold, never overspend. A caller that forgets to settle
    // starves its own cap rather than leaking spend.
    const limiter = new MemorySpendLimiter();
    const g = guardOn(limiter);
    await g.authorize(intent("i-1", CAP));
    expect((await g.authorize(intent("i-2", 1))).status).toBe("denied");
  });
});

describe("the two paths agree about money", () => {
  it("authorize+settle consumes the same budget as execute", async () => {
    const viaExecute = new MemorySpendLimiter();
    const g1 = guardOn(viaExecute);
    await g1.execute(intent("e-1", 1_500), async () => ({ ok: true }));

    const viaTwoPhase = new MemorySpendLimiter();
    const g2 = guardOn(viaTwoPhase);
    await g2.authorize(intent("a-1", 1_500));
    await g2.settle("a-1", { status: "executed" });

    const a = await viaExecute.totalsSince(policy.id, since(), "USD");
    const b = await viaTwoPhase.totalsSince(policy.id, since(), "USD");
    expect(b.totalMinor).toBe(a.totalMinor);
    expect(b.count).toBe(a.count);
  });

  it("a failure consumes the same budget on both paths", async () => {
    const viaExecute = new MemorySpendLimiter();
    const g1 = guardOn(viaExecute);
    await g1.execute(intent("e-1", 1_500), async () => {
      throw new Error("boom");
    });

    const viaTwoPhase = new MemorySpendLimiter();
    const g2 = guardOn(viaTwoPhase);
    await g2.authorize(intent("a-1", 1_500));
    await g2.settle("a-1", { status: "failed", error: "boom" });

    const a = await viaExecute.totalsSince(policy.id, since(), "USD");
    const b = await viaTwoPhase.totalsSince(policy.id, since(), "USD");
    expect(b.totalMinor).toBe(a.totalMinor);
  });
});

describe("the audit trail admits what it does not know", () => {
  it("records the outcome as SELF-REPORTED on the two-phase path", async () => {
    // With execute() the guard watched the executor run. Here it takes the
    // caller's word, and the ledger must say so rather than presenting both as
    // equally observed.
    const ledgerStore = new MemoryLedgerStore();
    const ledger = new AuditLedger(ledgerStore);
    const g = new VadunoGuard({ policy, ledger, limiter: new MemorySpendLimiter() });

    await g.authorize(intent("i-1", 900));
    await g.settle("i-1", { status: "executed" });

    const entries = await ledgerStore.all();
    const result = entries.find((e) => e.type === "execution_result");
    expect((result?.data as { selfReported?: boolean })?.selfReported).toBe(true);
    expect((await ledger.verify()).ok).toBe(true);
  });
});
