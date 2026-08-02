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

describe("the settle row carries the money — two-phase spends survive a restart", () => {
  // THE MEASURED DEFECT this suite pins: settle() used to append
  // {success, selfReported} with NO amountMinor/currency, and both consumers
  // filtered the row out (hydrateFromLedger requires a safe-integer amount and
  // string currency; ledgerSpendHistory's currency match failed on undefined).
  // A restarted guard on the SAME ledger then re-authorized the full budget —
  // a silent caps reset on the path every framework integration takes.
  it("a settled two-phase spend is counted after restart + hydrateFromLedger", async () => {
    const store = new MemoryLedgerStore();
    const g1 = new VadunoGuard({
      policy,
      ledger: new AuditLedger(store),
      limiter: new MemorySpendLimiter(),
    });
    expect((await g1.authorize(intent("i-1", 4_000))).status).toBe("authorized");
    await g1.settle("i-1", { status: "executed" });
    // In-process control: the cap already holds here (the limiter).
    expect((await g1.authorize(intent("i-2", 4_000))).status).toBe("denied");

    // Fresh process: new guard, new (empty) limiter, same ledger.
    const g2 = new VadunoGuard({
      policy,
      ledger: new AuditLedger(store),
      limiter: new MemorySpendLimiter(),
    });
    const report = await g2.hydrateFromLedger();
    expect(report.restoredSpendRows).toBe(1);
    expect(report.skippedUnparseableSpendRows).toBe(0);
    // 4000 restored; +4000 exceeds the 5000/day cap. The unfixed guard
    // AUTHORIZED this — the restart un-counted a real charge.
    expect((await g2.authorize(intent("i-3", 4_000))).status).toBe("denied");
  });

  it("the settle row's economic fields are IDENTICAL to an execute() row's, plus selfReported", async () => {
    const fields = { amount: { amountMinor: 1_500, currency: "USD" } };

    const execStore = new MemoryLedgerStore();
    const g1 = new VadunoGuard({
      policy,
      ledger: new AuditLedger(execStore),
      limiter: new MemorySpendLimiter(),
    });
    await g1.execute(makeIntent({ id: "e-1", ...fields }), async () => ({ ok: true }));

    const twoPhaseStore = new MemoryLedgerStore();
    const g2 = new VadunoGuard({
      policy,
      ledger: new AuditLedger(twoPhaseStore),
      limiter: new MemorySpendLimiter(),
    });
    await g2.authorize(makeIntent({ id: "a-1", ...fields }));
    await g2.settle("a-1", { status: "executed" });

    type Row = {
      success?: boolean;
      selfReported?: boolean;
      amountMinor?: number;
      currency?: string;
      merchantId?: string;
      rail?: string;
    };
    const resultRow = async (s: MemoryLedgerStore) =>
      (await s.all()).find((e) => e.type === "execution_result");
    const executeRow = await resultRow(execStore);
    const settleRow = await resultRow(twoPhaseStore);
    const executeData = executeRow!.data as Row;
    const settleData = settleRow!.data as Row;

    // Same names, same values — a consumer that counts execute() rows counts
    // this row too. That identity IS the fix.
    expect({
      amountMinor: settleData.amountMinor,
      currency: settleData.currency,
      merchantId: settleData.merchantId,
      rail: settleData.rail,
      success: settleData.success,
    }).toEqual({
      amountMinor: executeData.amountMinor,
      currency: executeData.currency,
      merchantId: executeData.merchantId,
      rail: executeData.rail,
      success: executeData.success,
    });
    // Strict superset: the evidence-honesty marker survives.
    expect(settleData.selfReported).toBe(true);
    expect(executeData.selfReported).toBeUndefined();
    // The audit row for a real payment must name the agent — refs.agentId was
    // "" on this path, recovered now from the authorization row.
    expect(settleRow!.agentId).toBe("agent-1");
  });

  it("INTERLEAVE (the attempt-2 blocker): a late-retried failed settle cannot suppress the genuine executed outcome", async () => {
    // authorize -> settle(failed) -> releaseSpend (rail provably didn't charge)
    // -> re-authorize SAME id -> late retry of the old settle(failed)
    // -> settle(executed).
    // Positional dedupe suppressed the final executed row because the retried
    // failure row landed after the new authorization snapshot: the ledger then
    // permanently said success:false for a charge that HAPPENED, the audit
    // alarm stayed clean, and a restarted guard re-authorized the full amount.
    const store = new MemoryLedgerStore();
    const g = new VadunoGuard({
      policy,
      ledger: new AuditLedger(store),
      limiter: new MemorySpendLimiter(),
    });
    expect((await g.authorize(intent("i-1", 4_000))).status).toBe("authorized");
    await g.settle("i-1", { status: "failed", error: "card_declined" });
    await g.releaseSpend("i-1");
    expect((await g.authorize(intent("i-1", 4_000))).status).toBe("authorized");
    await g.settle("i-1", { status: "failed", error: "card_declined" }); // stale retry
    await g.settle("i-1", { status: "executed" });

    // The charge is recorded: exactly one SUCCESS row, carrying the money.
    const successRows = (await store.all()).filter(
      (e) =>
        e.type === "execution_result" &&
        (e.data as { success?: boolean }).success === true,
    );
    expect(successRows).toHaveLength(1);
    expect((successRows[0]!.data as { amountMinor?: number }).amountMinor).toBe(4_000);

    // And it survives a restart: no silent caps reset.
    const g2 = new VadunoGuard({
      policy,
      ledger: new AuditLedger(store),
      limiter: new MemorySpendLimiter(),
    });
    const report = await g2.hydrateFromLedger();
    expect(report.restoredSpendRows).toBe(1);
    // Nothing was lost, so the alarm legitimately reads clean — the point is
    // that the executed outcome is IN the ledger, not flagged as missing.
    expect(report.skippedUnparseableSpendRows).toBe(0);
    expect(g2.isAuditDegraded()).toBe(false);
    expect((await g2.authorize(intent("i-9", 4_000))).status).toBe("denied");
  });

  it("a retried settle(executed) records the spend ONCE", async () => {
    const store = new MemoryLedgerStore();
    const limiter = new MemorySpendLimiter();
    const g = new VadunoGuard({ policy, ledger: new AuditLedger(store), limiter });
    await g.authorize(intent("i-1", 2_000));
    await g.settle("i-1", { status: "executed" });
    await g.settle("i-1", { status: "executed" }); // retry

    const resultRows = (await store.all()).filter((e) => e.type === "execution_result");
    expect(resultRows).toHaveLength(1);
    expect((await limiter.totalsSince(policy.id, since(), "USD")).totalMinor).toBe(2_000);

    // A restarted guard counts it once: 2000 restored, +2500 fits the 5000 cap.
    // A double-counted ledger (4000 restored) would deny this.
    const g2 = new VadunoGuard({
      policy,
      ledger: new AuditLedger(store),
      limiter: new MemorySpendLimiter(),
    });
    expect((await g2.hydrateFromLedger()).restoredSpendRows).toBe(1);
    expect((await g2.authorize(intent("i-2", 2_500))).status).toBe("authorized");
  });

  it("retried settle(failed) appends one row; a failed retry after executed adds nothing", async () => {
    const store = new MemoryLedgerStore();
    const g = new VadunoGuard({
      policy,
      ledger: new AuditLedger(store),
      limiter: new MemorySpendLimiter(),
    });
    await g.authorize(intent("i-1", 1_000));
    await g.settle("i-1", { status: "failed", error: "timeout" });
    await g.settle("i-1", { status: "failed", error: "timeout" }); // retry
    const rowsFor = async (id: string) =>
      (await store.all()).filter((e) => e.type === "execution_result" && e.intentId === id);
    expect(await rowsFor("i-1")).toHaveLength(1);

    await g.authorize(intent("i-2", 1_000));
    await g.settle("i-2", { status: "executed" });
    await g.settle("i-2", { status: "failed", error: "confused retry" });
    const rows = await rowsFor("i-2");
    // The stale failure must not shadow — or join — the recorded success.
    expect(rows).toHaveLength(1);
    expect((rows[0]!.data as { success?: boolean }).success).toBe(true);
  });

  it("settling an id the guard never authorized records no money", async () => {
    const store = new MemoryLedgerStore();
    const g = new VadunoGuard({
      policy,
      ledger: new AuditLedger(store),
      limiter: new MemorySpendLimiter(),
    });
    await g.settle("ghost", { status: "executed" });

    // The row exists (the claim is evidence) but carries no economic fields —
    // there is no authorization snapshot to recover them from, and FABRICATING
    // an amount here would let a bare settle() call mint counted spend.
    const row = (await store.all()).find((e) => e.type === "execution_result");
    expect((row!.data as { amountMinor?: unknown }).amountMinor).toBeUndefined();

    // Hydrate surfaces it as unparseable rather than silently dropping it.
    const g2 = new VadunoGuard({
      policy,
      ledger: new AuditLedger(store),
      limiter: new MemorySpendLimiter(),
    });
    const report = await g2.hydrateFromLedger();
    expect(report.restoredSpendRows).toBe(0);
    expect(report.skippedUnparseableSpendRows).toBe(1);
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
