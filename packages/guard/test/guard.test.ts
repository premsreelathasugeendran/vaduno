import { describe, expect, it } from "vitest";
import { VadunoGuard } from "../src/guard.js";
import { AuditLedger } from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import {
  MandateManager,
  generateMandateKeyPair,
} from "../src/mandate/mandate.js";
import { makeIntent, makePolicy } from "./helpers.js";

function setup(policyOver = {}, guardOver: Record<string, unknown> = {}) {
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const guard = new VadunoGuard({
    policy: makePolicy(policyOver),
    ledger,
    ...guardOver,
  });
  return { ledger, guard };
}

const paidOk = async () => ({ receipt: "r-1" });

describe("VadunoGuard.execute", () => {
  it("executes an allowed intent and audits the full path", async () => {
    const { guard, ledger } = setup();
    const result = await guard.execute(makeIntent(), paidOk);
    expect(result.status).toBe("executed");
    expect(result.value).toEqual({ receipt: "r-1" });

    const types = (await ledger.all()).map((e) => e.type);
    expect(types).toEqual([
      "intent_received",
      "policy_decision",
      "execution_started",
      "execution_result",
    ]);
    expect((await ledger.verify()).ok).toBe(true);
  });

  it("denies over-limit and never calls the executor", async () => {
    const { guard } = setup();
    let called = false;
    const result = await guard.execute(
      makeIntent({ amount: { amountMinor: 999_999, currency: "USD" } }),
      async () => {
        called = true;
        return null;
      },
    );
    expect(result.status).toBe("denied");
    expect(called).toBe(false);
  });

  it("accumulates executed spend into rolling windows", async () => {
    const { guard } = setup({
      limits: { perTransactionMinor: 6_000, perDayMinor: 10_000 },
    });
    const spend = (n: number) =>
      guard.execute(
        makeIntent({ amount: { amountMinor: n, currency: "USD" } }),
        paidOk,
      );
    expect((await spend(6_000)).status).toBe("executed");
    expect((await spend(3_000)).status).toBe("executed");
    // 9000 spent; 2000 more would cross the 10_000 daily cap.
    const third = await spend(2_000);
    expect(third.status).toBe("denied");
    expect(
      third.policyResult!.reasons.map((r) => r.code),
    ).toContain("PER_DAY_LIMIT_EXCEEDED");
  });

  it("fails closed when approval is required but no handler exists", async () => {
    const { guard } = setup({ approval: { always: true } });
    const result = await guard.execute(makeIntent(), paidOk);
    expect(result.status).toBe("denied");
    expect(result.policyResult!.reasons.map((r) => r.code)).toContain(
      "NO_APPROVAL_HANDLER",
    );
  });

  it("runs the approval flow: approve executes, reject blocks", async () => {
    const approve = setup(
      { approval: { aboveMinor: 100 } },
      { approvalHandler: async () => ({ approved: true, approver: "prem" }) },
    );
    expect((await approve.guard.execute(makeIntent(), paidOk)).status).toBe(
      "executed",
    );

    const reject = setup(
      { approval: { aboveMinor: 100 } },
      { approvalHandler: async () => ({ approved: false }) },
    );
    const rejected = await reject.guard.execute(makeIntent(), paidOk);
    expect(rejected.status).toBe("approval_rejected");
    const types = (await reject.ledger.all()).map((e) => e.type);
    expect(types).toContain("approval_requested");
    expect(types).toContain("approval_resolved");
  });

  it("freeze denies everything until unfreeze", async () => {
    const { guard } = setup();
    await guard.freeze("suspected prompt injection");
    const denied = await guard.execute(makeIntent(), paidOk);
    expect(denied.status).toBe("denied");
    expect(denied.policyResult!.reasons[0]!.code).toBe("GUARD_FROZEN");
    await guard.unfreeze();
    expect((await guard.execute(makeIntent(), paidOk)).status).toBe("executed");
  });

  it("records executor failure as failed and keeps the chain valid", async () => {
    const { guard, ledger } = setup();
    const result = await guard.execute(makeIntent(), async () => {
      throw new Error("rail timeout");
    });
    expect(result.status).toBe("failed");
    expect(result.error).toBe("rail timeout");
    expect((await ledger.verify()).ok).toBe(true);
  });

  it("failed executions do not count against spend limits", async () => {
    const { guard } = setup({
      limits: { perTransactionMinor: 6_000, perDayMinor: 6_000 },
    });
    await guard.execute(
      makeIntent({ amount: { amountMinor: 6_000, currency: "USD" } }),
      async () => {
        throw new Error("boom");
      },
    );
    const after = await guard.execute(
      makeIntent({ amount: { amountMinor: 6_000, currency: "USD" } }),
      paidOk,
    );
    expect(after.status).toBe("executed");
  });

  it("requireMandate: denies without mandate, executes with valid one, blocks reuse", async () => {
    const keys = generateMandateKeyPair();
    const ledger = new AuditLedger(new MemoryLedgerStore());
    const mandates = new MandateManager(
      { publicKeyPem: keys.publicKeyPem, privateKeyPem: keys.privateKeyPem },
      ledger,
    );
    const guard = new VadunoGuard({
      policy: makePolicy(),
      ledger,
      mandates,
      requireMandate: true,
    });

    const noMandate = await guard.execute(makeIntent(), paidOk);
    expect(noMandate.status).toBe("denied");

    const mandate = await mandates.issue({
      issuer: "prem",
      agentId: "agent-1",
      constraints: {
        maxAmountMinor: 1_000,
        currency: "USD",
        validFrom: "2000-01-01T00:00:00.000Z",
        expiresAt: "2100-01-01T00:00:00.000Z",
        maxUses: 1,
      },
    });

    const first = await guard.execute(
      makeIntent({ mandateId: mandate.id }),
      paidOk,
    );
    expect(first.status).toBe("executed");

    const reuse = await guard.execute(
      makeIntent({ mandateId: mandate.id }),
      paidOk,
    );
    expect(reuse.status).toBe("denied");
    expect(
      reuse.policyResult!.reasons[0]!.code.startsWith("MANDATE_"),
    ).toBe(true);

    expect((await ledger.verify()).ok).toBe(true);
  });
});

describe("VadunoGuard concurrency & TOCTOU", () => {
  it("parallel executes cannot jointly exceed the daily cap", async () => {
    const { guard } = setup({
      limits: { perTransactionMinor: 6_000, perDayMinor: 10_000 },
    });
    const mk = () =>
      makeIntent({ amount: { amountMinor: 6_000, currency: "USD" } });
    const results = await Promise.all([
      guard.execute(mk(), paidOk),
      guard.execute(mk(), paidOk),
      guard.execute(mk(), paidOk),
    ]);
    expect(results.filter((r) => r.status === "executed").length).toBe(1);
  });

  it("rolling limits cannot be reset by rotating agentId (global by default)", async () => {
    const { guard } = setup({
      limits: { perTransactionMinor: 6_000, perDayMinor: 10_000 },
    });
    const a1 = await guard.execute(
      makeIntent({ agentId: "a1", amount: { amountMinor: 6_000, currency: "USD" } }),
      paidOk,
    );
    expect(a1.status).toBe("executed");
    const a2 = await guard.execute(
      makeIntent({ agentId: "a2", amount: { amountMinor: 6_000, currency: "USD" } }),
      paidOk,
    );
    expect(a2.status).toBe("denied");
  });
});

describe("VadunoGuard approval races", () => {
  // A controllable approval handler that blocks until we release it.
  function deferredApproval() {
    let release!: (r: { approved: boolean }) => void;
    let reached!: () => void;
    const requested = new Promise<void>((r) => (reached = r));
    const handler = () => {
      reached();
      return new Promise<{ approved: boolean }>((res) => (release = res));
    };
    return { handler, requested, release: () => release };
  }

  it("freeze during pending approval blocks the in-flight execution", async () => {
    const d = deferredApproval();
    const { guard } = setup({ approval: { always: true } }, { approvalHandler: d.handler });
    const pending = guard.execute(makeIntent(), paidOk);
    await d.requested;
    await guard.freeze("prompt injection detected mid-approval");
    d.release()({ approved: true });
    const result = await pending;
    expect(result.status).toBe("denied");
    expect(result.policyResult!.reasons.map((r) => r.code)).toContain(
      "GUARD_FROZEN",
    );
  });

  it("a policy tightened during pending approval governs the outcome", async () => {
    const d = deferredApproval();
    const { guard } = setup(
      { approval: { always: true } },
      { approvalHandler: d.handler },
    );
    const pending = guard.execute(
      makeIntent({ amount: { amountMinor: 4_000, currency: "USD" } }),
      paidOk,
    );
    await d.requested;
    await guard.setPolicy(
      makePolicy({ limits: { perTransactionMinor: 100 }, approval: { always: true } }),
    );
    d.release()({ approved: true });
    const result = await pending;
    expect(result.status).toBe("denied");
    expect(result.policyResult!.reasons.map((r) => r.code)).toContain(
      "PER_TXN_LIMIT_EXCEEDED",
    );
  });
});

describe("VadunoGuard hostile-intent hardening", () => {
  it("pins field values at snapshot time (getter TOCTOU)", async () => {
    const { guard, ledger } = setup();
    let reads = 0;
    const amount = { currency: "USD" } as { currency: string; amountMinor: number };
    Object.defineProperty(amount, "amountMinor", {
      enumerable: true,
      get: () => (++reads <= 1 ? 100 : 999_999),
    });
    const result = await guard.execute(makeIntent({ amount }), paidOk);
    const exec = (await ledger.all()).find((e) => e.type === "execution_result");
    if (result.status === "executed") {
      expect((exec!.data as { amountMinor: number }).amountMinor).toBe(100);
    }
    expect((await ledger.verify()).ok).toBe(true);
  });

  it("day window rolls off with the injected clock", async () => {
    let t = Date.parse("2026-01-01T00:00:00.000Z");
    const now = () => new Date(t);
    const ledger = new AuditLedger(new MemoryLedgerStore(), now);
    const guard = new VadunoGuard({
      policy: makePolicy({ limits: { perTransactionMinor: 10_000, perDayMinor: 10_000 } }),
      ledger,
      now,
    });
    const spend = (n: number) =>
      guard.execute(
        makeIntent({ amount: { amountMinor: n, currency: "USD" } }),
        paidOk,
      );
    expect((await spend(8_000)).status).toBe("executed");
    expect((await spend(8_000)).status).toBe("denied");
    t += 25 * 3600 * 1000; // +25h: first spend rolls out of the window
    expect((await spend(8_000)).status).toBe("executed");
  });

  it("settles with denied (never executes) when the ledger store fails", async () => {
    const failing = {
      append: async () => {
        throw new Error("disk full");
      },
      last: async () => null,
      all: async () => [],
    };
    const guard = new VadunoGuard({
      policy: makePolicy(),
      ledger: new AuditLedger(failing),
    });
    let called = false;
    const result = await guard.execute(makeIntent(), async () => {
      called = true;
      return null;
    });
    expect(result.status).toBe("denied");
    expect(called).toBe(false);
  });

  it("restores freeze state from the ledger on hydrate (survives restart)", async () => {
    const store = new MemoryLedgerStore();
    const ledgerA = new AuditLedger(store);
    const guardA = new VadunoGuard({ policy: makePolicy(), ledger: ledgerA });
    await guardA.freeze("incident");

    // A fresh guard on the same ledger (simulating a restart).
    const guardB = new VadunoGuard({ policy: makePolicy(), ledger: new AuditLedger(store) });
    expect(guardB.isFrozen()).toBe(false); // not yet hydrated
    await guardB.hydrateFromLedger();
    expect(guardB.isFrozen()).toBe(true);
    expect((await guardB.execute(makeIntent(), paidOk)).status).toBe("denied");

    await guardA.unfreeze();
    const guardC = new VadunoGuard({ policy: makePolicy(), ledger: new AuditLedger(store) });
    await guardC.hydrateFromLedger();
    expect(guardC.isFrozen()).toBe(false);
  });

  it("hydrate refuses (throws) on a tampered ledger", async () => {
    const store = new MemoryLedgerStore();
    const guardA = new VadunoGuard({ policy: makePolicy(), ledger: new AuditLedger(store) });
    await guardA.execute(makeIntent(), paidOk);
    // Tamper with a stored entry.
    (store as unknown as { entries: { data: unknown }[] }).entries[1]!.data = { tampered: true };
    const guardB = new VadunoGuard({ policy: makePolicy(), ledger: new AuditLedger(store) });
    await expect(guardB.hydrateFromLedger()).rejects.toThrow(/verification/);
  });

  it("hydrate skips a malformed execution_result instead of NaN-poisoning the counter", async () => {
    const store = new MemoryLedgerStore();
    const ledger = new AuditLedger(store);
    const guardA = new VadunoGuard({
      policy: makePolicy({ limits: { perTransactionMinor: 6_000, perDayMinor: 10_000 } }),
      ledger,
    });
    await guardA.execute(
      makeIntent({ amount: { amountMinor: 6_000, currency: "USD" } }),
      paidOk,
    );
    // A malformed row (non-integer amount) — must be skipped, not turn totals into NaN.
    await ledger.append(
      "execution_result",
      { success: true, amountMinor: "not-a-number", currency: "USD" },
      { intentId: "bad", agentId: "a" },
    );

    const guardB = new VadunoGuard({
      policy: makePolicy({ limits: { perTransactionMinor: 6_000, perDayMinor: 10_000 } }),
      ledger: new AuditLedger(store),
    });
    await guardB.hydrateFromLedger();
    // Valid 6000 counted; +6000 would exceed the 10k/day cap -> denied
    // (a NaN-poisoned total would have let this slip through).
    const after = await guardB.execute(
      makeIntent({ amount: { amountMinor: 6_000, currency: "USD" } }),
      paidOk,
    );
    expect(after.status).toBe("denied");
  });

  it("hydrate is one-shot per instance", async () => {
    const store = new MemoryLedgerStore();
    const guard = new VadunoGuard({ policy: makePolicy(), ledger: new AuditLedger(store) });
    await guard.hydrateFromLedger();
    await expect(guard.hydrateFromLedger()).rejects.toThrow(/already/);
  });

  it("restores the spend counter from the ledger on hydrate", async () => {
    const store = new MemoryLedgerStore();
    const guardA = new VadunoGuard({
      policy: makePolicy({ limits: { perTransactionMinor: 6_000, perDayMinor: 10_000 } }),
      ledger: new AuditLedger(store),
    });
    await guardA.execute(
      makeIntent({ amount: { amountMinor: 6_000, currency: "USD" } }),
      paidOk,
    );

    const guardB = new VadunoGuard({
      policy: makePolicy({ limits: { perTransactionMinor: 6_000, perDayMinor: 10_000 } }),
      ledger: new AuditLedger(store),
    });
    await guardB.hydrateFromLedger();
    // $6000 already spent (per hydrate) -> another $6000 exceeds the $10k/day cap.
    const after = await guardB.execute(
      makeIntent({ amount: { amountMinor: 6_000, currency: "USD" } }),
      paidOk,
    );
    expect(after.status).toBe("denied");
  });

  it("counts executed spend even when the success audit write is lost", async () => {
    // A store that drops the execution_result(success) write — simulating a
    // transient or hostile store. The spend must still count against limits.
    const inner = new MemoryLedgerStore();
    const flaky = {
      append: async (e: { type: string; data: unknown }) => {
        if (e.type === "execution_result" && (e.data as { success?: boolean }).success === true) {
          throw new Error("write lost");
        }
        return inner.append(e as never);
      },
      last: () => inner.last(),
      all: () => inner.all(),
    };
    const guard = new VadunoGuard({
      policy: makePolicy({ limits: { perTransactionMinor: 6_000, perDayMinor: 10_000 } }),
      ledger: new AuditLedger(flaky),
    });
    const usd = (n: number) => ({ amountMinor: n, currency: "USD" });

    const first = await guard.execute(makeIntent({ amount: usd(6_000) }), paidOk);
    expect(first.status).toBe("executed");
    expect(first.status === "executed" && first.auditDegraded).toBe(true);
    expect(guard.isAuditDegraded()).toBe(true);

    // The lost write must NOT un-count the spend: 6000 + 6000 > 10000/day.
    const second = await guard.execute(makeIntent({ amount: usd(6_000) }), paidOk);
    expect(second.status).toBe("denied");
    expect(second.policyResult!.reasons.map((r) => r.code)).toContain(
      "PER_DAY_LIMIT_EXCEEDED",
    );
  });
});
