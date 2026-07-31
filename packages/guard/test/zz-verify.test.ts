import { describe, expect, it } from "vitest";
import { AuditLedger } from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import { MemorySpendLimiter } from "../src/enforce/spend-limiter.js";
import { VadunoGuard } from "../src/guard.js";
import { approvalFingerprint } from "../src/approval/approval.js";
import { makeIntent, makePolicy } from "./helpers.js";

const policy = makePolicy({ limits: { perTransactionMinor: 5_000, perDayMinor: 5_000 } });

describe("FINDING twophase-spend-unrecorded", () => {
  it("does a settle()d spend survive a restart+hydrate?", async () => {
    const store = new MemoryLedgerStore();
    const g1 = new VadunoGuard({
      policy,
      ledger: new AuditLedger(store),
      limiter: new MemorySpendLimiter(),
    });
    // Spend 4000 of a 5000 cap via the TWO-PHASE path (@vaduno/agent's path).
    await g1.authorize(makeIntent({ id: "i-1", amount: { amountMinor: 4_000, currency: "USD" } }));
    await g1.settle("i-1", { status: "executed" });
    const again = await g1.authorize(
      makeIntent({ id: "i-2", amount: { amountMinor: 4_000, currency: "USD" } }),
    );
    console.log("TP same-process second 4000 ->", again.status, "(expect denied)");

    const entry = (await store.all()).find((e) => e.type === "execution_result");
    console.log("TP execution_result data:", JSON.stringify(entry?.data));

    // Restart: fresh guard, same ledger, hydrate.
    const g2 = new VadunoGuard({
      policy,
      ledger: new AuditLedger(store),
      limiter: new MemorySpendLimiter(),
    });
    await g2.hydrateFromLedger();
    const afterRestart = await g2.authorize(
      makeIntent({ id: "i-3", amount: { amountMinor: 4_000, currency: "USD" } }),
    );
    console.log("TP after restart+hydrate ->", afterRestart.status, "(denied = safe)");
  });

  it("CONTROL: does the single-call execute() path survive a restart?", async () => {
    const store = new MemoryLedgerStore();
    const g1 = new VadunoGuard({
      policy,
      ledger: new AuditLedger(store),
      limiter: new MemorySpendLimiter(),
    });
    await g1.execute(
      makeIntent({ id: "e-1", amount: { amountMinor: 4_000, currency: "USD" } }),
      async () => ({ ok: true }),
    );
    const entry = (await store.all()).find((e) => e.type === "execution_result");
    console.log("CTRL execution_result data:", JSON.stringify(entry?.data));

    const g2 = new VadunoGuard({
      policy,
      ledger: new AuditLedger(store),
      limiter: new MemorySpendLimiter(),
    });
    await g2.hydrateFromLedger();
    const r = await g2.execute(
      makeIntent({ id: "e-2", amount: { amountMinor: 4_000, currency: "USD" } }),
      async () => ({ ok: true }),
    );
    console.log("CTRL after restart+hydrate ->", r.status);
  });
});

describe("FINDING approval-fingerprint-separator", () => {
  it("do two different merchants hash to one fingerprint?", () => {
    const a = makeIntent({
      id: "x",
      amount: { amountMinor: 12_000, currency: "USD" },
      merchant: { id: "shop", url: "https://good.com|https://evil.com" },
    });
    const b = makeIntent({
      id: "x",
      amount: { amountMinor: 12_000, currency: "USD" },
      merchant: { id: "shop|https://good.com", url: "https://evil.com" },
    });
    const fa = approvalFingerprint(a);
    const fb = approvalFingerprint(b);
    console.log("FP a:", fa.slice(0, 24));
    console.log("FP b:", fb.slice(0, 24));
    console.log("COLLISION:", fa === fb);
  });
});
