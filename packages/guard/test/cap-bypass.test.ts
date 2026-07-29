/**
 * Regression tests for two cap bypasses found in 0.2.0 AFTER it was published.
 *
 * Both were reproduced against the built dist before being fixed. Both are the
 * same underlying mistake: trusting a field the threat model says the agent
 * controls, and treating an idempotent reservation as if it also made execution
 * idempotent.
 */
import { describe, expect, it } from "vitest";
import { AuditLedger } from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import { MemorySpendLimiter } from "../src/enforce/spend-limiter.js";
import { VadunoGuard } from "../src/guard.js";
import type { PaymentIntent, SpendLimiter, SpendPolicy } from "../src/types.js";

const CAP = 5_000; // $50.00

const policy: SpendPolicy = {
  id: "cap-policy",
  version: 1,
  currency: "USD",
  limits: { perTransactionMinor: 5_000, perDayMinor: CAP },
  merchants: { allow: ["openai.com"] },
};

function intent(id: string, agentId = "agent-1"): PaymentIntent {
  return {
    id,
    agentId,
    merchant: { id: "openai", url: "https://api.openai.com" },
    amount: { amountMinor: 5_000, currency: "USD" },
    rail: "x402",
    requestedAt: new Date().toISOString(),
  };
}

function guardOn(limiter: SpendLimiter): VadunoGuard {
  return new VadunoGuard({
    policy,
    ledger: new AuditLedger(new MemoryLedgerStore()),
    limiter,
  });
}

describe("REGRESSION: cap bypass via agentId rotation", () => {
  it("rotating intent.agentId does NOT mint a fresh budget", async () => {
    // Was: two guards sharing one limiter passed $100 through a $50 cap simply
    // because the reservation was scoped to intent.agentId — a field
    // CONTRIBUTING rule 4 explicitly assumes the attacker controls. The
    // pre-0.2.0 in-memory history ignored agentId for exactly this reason.
    const limiter = new MemorySpendLimiter();
    const a = guardOn(limiter);
    const b = guardOn(limiter);

    let spentMinor = 0;
    const pay = async () => {
      spentMinor += 5_000;
      return { ok: true };
    };

    const first = await a.execute(intent("i-1", "agent-1"), pay);
    const second = await b.execute(intent("i-2", "agent-2"), pay); // ROTATED

    expect(first.status).toBe("executed");
    expect(second.status).toBe("denied");
    expect(spentMinor).toBeLessThanOrEqual(CAP);
  });

  it("the cap is scoped to the policy, so a fixed agentId behaves identically", async () => {
    const limiter = new MemorySpendLimiter();
    const a = guardOn(limiter);
    const b = guardOn(limiter);
    const pay = async () => ({ ok: true });

    expect((await a.execute(intent("i-1", "agent-1"), pay)).status).toBe("executed");
    expect((await b.execute(intent("i-2", "agent-1"), pay)).status).toBe("denied");
  });
});

describe("REGRESSION: reused intent.id must not re-run the rail", () => {
  it("the same intent id twice runs the executor ONCE", async () => {
    // Was: a replayed reservation fell through to the executor, so the rail ran
    // twice while the budget counted one charge. reserve() being idempotent
    // actively HID the double execution.
    const limiter = new MemorySpendLimiter();
    const a = guardOn(limiter);
    const b = guardOn(limiter);

    let railCalls = 0;
    const pay = async () => {
      railCalls += 1;
      return { ok: true };
    };

    const first = await a.execute(intent("SAME"), pay);
    const second = await b.execute(intent("SAME"), pay);

    expect(first.status).toBe("executed");
    expect(second.status).toBe("replayed");
    expect(railCalls).toBe(1);
  });

  it("a replay across two guards reports the original outcome as executed", async () => {
    const limiter = new MemorySpendLimiter();
    const a = guardOn(limiter);
    const b = guardOn(limiter);
    await a.execute(intent("ONE"), async () => ({ ok: true }));
    const again = await b.execute(intent("ONE"), async () => ({ ok: true }));
    expect(again.status).toBe("replayed");
    if (again.status === "replayed") expect(again.original.status).toBe("executed");
  });

  it("on ONE guard the advisory cap denies the retry first — which is also safe", async () => {
    // Worth pinning: the reported status depends on topology. A single guard's
    // in-memory advisory history already counts the first charge, so the retry
    // is refused by the cap before it ever reaches the limiter and comes back
    // "denied" rather than "replayed". Both refuse to run the rail, which is
    // the property that matters; only the reason differs.
    const limiter = new MemorySpendLimiter();
    const g = guardOn(limiter);
    let railCalls = 0;
    const pay = async () => {
      railCalls += 1;
      return { ok: true };
    };
    expect((await g.execute(intent("ONE"), pay)).status).toBe("executed");
    expect((await g.execute(intent("ONE"), pay)).status).toBe("denied");
    expect(railCalls).toBe(1);
  });

  it("a THROWING executor retried under one intent id runs the rail ONCE", async () => {
    // Was: 8 retries = 8 rail calls, all counted as a single $50 charge. That
    // directly contradicted the burn-on-failure guarantee, which exists so an
    // executor that times out AFTER the charge landed cannot be retried past
    // the cap.
    const limiter = new MemorySpendLimiter();
    const g = guardOn(limiter);

    let railCalls = 0;
    const boom = async () => {
      railCalls += 1;
      throw new Error("timeout after the charge landed");
    };

    const first = await g.execute(intent("RETRY"), boom);
    expect(first.status).toBe("failed");

    for (let i = 0; i < 7; i += 1) {
      const r = await g.execute(intent("RETRY"), boom);
      expect(r.status).toBe("replayed");
      // The first attempt never settled, so the outcome is genuinely unknown:
      // money MAY have moved. Never claim it didn't.
      if (r.status === "replayed") expect(r.original.status).toBe("unresolved");
    }

    expect(railCalls).toBe(1);
  });

  it("a distinct intent id after a failure still consumes budget (burn-on-failure holds)", async () => {
    const limiter = new MemorySpendLimiter();
    const g = guardOn(limiter);
    const boom = async () => {
      throw new Error("timeout after the charge landed");
    };

    expect((await g.execute(intent("f-1"), boom)).status).toBe("failed");
    // The failed reservation is still held, so a NEW intent for the same amount
    // must be denied — otherwise a retry loop with fresh ids spends unbounded.
    expect((await g.execute(intent("f-2"), boom)).status).toBe("denied");
  });
});
