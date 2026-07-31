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

  it("a failed execution KEEPS counting against spend limits (over-hold, never overspend)", async () => {
    // Changed in 0.2.0. Previously a throw freed the whole budget, which meant
    // an executor that times out AFTER the charge lands could be retried past
    // any cap: N timeouts = N real charges, none of them counted. A thrown
    // executor may have moved money, so the amount stays held.
    const { guard } = setup({
      limits: { perTransactionMinor: 6_000, perDayMinor: 6_000 },
    });
    const failed = await guard.execute(
      makeIntent({ amount: { amountMinor: 6_000, currency: "USD" } }),
      async () => {
        throw new Error("boom");
      },
    );
    expect(failed.status).toBe("failed");

    const after = await guard.execute(
      makeIntent({ amount: { amountMinor: 6_000, currency: "USD" } }),
      paidOk,
    );
    expect(after.status).toBe("denied");
  });

  it("releaseSpend reclaims a failed execution's budget when no money moved", async () => {
    const { guard } = setup({
      limits: { perTransactionMinor: 6_000, perDayMinor: 6_000 },
    });
    const intent = makeIntent({ amount: { amountMinor: 6_000, currency: "USD" } });
    await guard.execute(intent, async () => {
      throw new Error("card_declined — nothing was charged");
    });

    await guard.releaseSpend(intent.id);

    const after = await guard.execute(
      makeIntent({ amount: { amountMinor: 6_000, currency: "USD" } }),
      paidOk,
    );
    expect(after.status).toBe("executed");
  });

  it("releaseSpend CANNOT un-count a successful execution", async () => {
    const { guard } = setup({
      limits: { perTransactionMinor: 6_000, perDayMinor: 6_000 },
    });
    const intent = makeIntent({ amount: { amountMinor: 6_000, currency: "USD" } });
    expect((await guard.execute(intent, paidOk)).status).toBe("executed");

    // A mistaken call must not free real spend.
    await guard.releaseSpend(intent.id);

    const after = await guard.execute(
      makeIntent({ amount: { amountMinor: 6_000, currency: "USD" } }),
      paidOk,
    );
    expect(after.status).toBe("denied");
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

  it("requireHydration denies every intent until hydrateFromLedger succeeds", async () => {
    const store = new MemoryLedgerStore();
    const guard = new VadunoGuard({
      policy: makePolicy(),
      ledger: new AuditLedger(store),
      requireHydration: true,
    });
    let called = false;
    const before = await guard.execute(makeIntent(), async () => {
      called = true;
      return null;
    });
    expect(before.status).toBe("denied");
    expect(before.policyResult!.reasons[0]!.code).toBe("HYDRATION_REQUIRED");
    expect(called).toBe(false);

    await guard.hydrateFromLedger();
    expect((await guard.execute(makeIntent(), paidOk)).status).toBe("executed");
  });

  it("requireHydration keeps denying after a FAILED hydrate (tampered ledger cannot fail open)", async () => {
    const store = new MemoryLedgerStore();
    const guardA = new VadunoGuard({ policy: makePolicy(), ledger: new AuditLedger(store) });
    await guardA.execute(makeIntent(), paidOk);
    (store as unknown as { entries: { data: unknown }[] }).entries[1]!.data = { tampered: true };

    const guardB = new VadunoGuard({
      policy: makePolicy(),
      ledger: new AuditLedger(store),
      requireHydration: true,
    });
    await expect(guardB.hydrateFromLedger()).rejects.toThrow(/verification/);
    // Without requireHydration this guard would now run with EMPTY state —
    // no freeze, zero counted spend — i.e. the tampered ledger failed OPEN.
    let called = false;
    const result = await guardB.execute(makeIntent(), async () => {
      called = true;
      return null;
    });
    expect(result.status).toBe("denied");
    expect(result.policyResult!.reasons[0]!.code).toBe("HYDRATION_REQUIRED");
    expect(called).toBe(false);
  });

  it("an ATTEMPTED-and-failed hydrate denies by default — no requireHydration needed", async () => {
    const store = new MemoryLedgerStore();
    const guardA = new VadunoGuard({ policy: makePolicy(), ledger: new AuditLedger(store) });
    await guardA.execute(makeIntent(), paidOk);
    const entries = (store as unknown as { entries: { data: unknown }[] }).entries;
    const originalData = entries[1]!.data;
    entries[1]!.data = { tampered: true };

    // Plain defaults — no requireHydration.
    const guardB = new VadunoGuard({ policy: makePolicy(), ledger: new AuditLedger(store) });
    await expect(guardB.hydrateFromLedger()).rejects.toThrow(/verification/);

    // This guard has SEEN its ledger fail verification. Serving anyway with
    // fresh, empty state (no freeze, zero counted spend) is fail-open.
    let called = false;
    const result = await guardB.execute(makeIntent(), async () => {
      called = true;
      return null;
    });
    expect(result.status).toBe("denied");
    expect(result.policyResult!.reasons[0]!.code).toBe("HYDRATION_REQUIRED");
    expect(called).toBe(false);

    // Deny-until-a-retry-succeeds, not deny-forever: repair the ledger,
    // re-hydrate, and service resumes.
    entries[1]!.data = originalData;
    await guardB.hydrateFromLedger();
    expect((await guardB.execute(makeIntent(), paidOk)).status).toBe("executed");
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

describe("VadunoGuard freeze semantics", () => {
  // A store whose Nth all() call captures its row snapshot, then PARKS until
  // the test opens the gate — a real slow read that already paged its rows.
  // Appends landing while it is parked are not in the returned snapshot.
  function gatedStore(inner: MemoryLedgerStore, holdAllCall: number) {
    let calls = 0;
    let open!: () => void;
    const gate = new Promise<void>((r) => (open = r));
    let reached!: () => void;
    const held = new Promise<void>((r) => (reached = r));
    const store = {
      append: (e: never) => inner.append(e),
      last: () => inner.last(),
      all: async () => {
        calls += 1;
        const snapshot = await inner.all();
        if (calls === holdAllCall) {
          reached();
          await gate;
        }
        return snapshot;
      },
    };
    return { store, held, open: () => open() };
  }

  it("a freeze issued while hydrate is in flight survives hydrate (no clobber)", async () => {
    const inner = new MemoryLedgerStore();
    // hydrate reads the store twice: verify() is call 1, its own all() is
    // call 2. Park the second so the freeze lands mid-hydrate.
    const g = gatedStore(inner, 2);
    const guard = new VadunoGuard({ policy: makePolicy(), ledger: new AuditLedger(g.store) });
    const hydrating = guard.hydrateFromLedger();
    await g.held;
    const freezing = guard.freeze("incident mid-hydrate");
    g.open();
    await hydrating;
    await freezing;

    // Before the fix: hydrate's unconditional assignment overwrote the live
    // freeze — freeze() resolved cleanly, the ledger showed guard_frozen, and
    // the guard kept authorizing.
    expect(guard.isFrozen()).toBe(true);
    const denied = await guard.execute(makeIntent(), paidOk);
    expect(denied.status).toBe("denied");
    expect(denied.policyResult!.reasons[0]!.code).toBe("GUARD_FROZEN");
  });

  it("an unfreeze issued while hydrate is in flight is not resurrected by hydrate", async () => {
    const inner = new MemoryLedgerStore();
    // Seed a durable freeze from a previous run.
    const seeder = new VadunoGuard({ policy: makePolicy(), ledger: new AuditLedger(inner) });
    await seeder.freeze("incident");

    const g = gatedStore(inner, 2);
    const guard = new VadunoGuard({ policy: makePolicy(), ledger: new AuditLedger(g.store) });
    const hydrating = guard.hydrateFromLedger();
    await g.held;
    const unfreezing = guard.unfreeze();
    g.open();
    await hydrating;
    await unfreezing;

    expect(guard.isFrozen()).toBe(false);
    expect((await guard.execute(makeIntent(), paidOk)).status).toBe("executed");
  });

  it("a freeze landing inside the critical section denies before the executor and releases the budget", async () => {
    let guardRef!: VadunoGuard;
    let armed = true;
    const { guard, ledger } = setup(
      { limits: { perTransactionMinor: 6_000, perDayMinor: 6_000 } },
      {
        // Fires INSIDE the critical section, after the top-of-section freeze
        // check has already passed. AWAITED on purpose: freeze() takes no
        // lock, so awaiting it from inside the section must complete rather
        // than deadlock on the guard mutex (0.2.x allowed this pattern).
        revocationCheck: async () => {
          if (armed) {
            armed = false;
            await guardRef.freeze("kill switch mid-decision");
          }
          return { allowed: true as const };
        },
      },
    );
    guardRef = guard;
    let called = false;
    const result = await guard.execute(
      makeIntent({ amount: { amountMinor: 6_000, currency: "USD" } }),
      async () => {
        called = true;
        return null;
      },
    );
    expect(result.status).toBe("denied");
    expect(result.policyResult!.reasons[0]!.code).toBe("GUARD_FROZEN");
    expect(called).toBe(false);
    expect((await ledger.all()).map((e) => e.type)).not.toContain("execution_started");

    expect(guard.isFrozen()).toBe(true);

    // The denied payment's reservation must have been released: after
    // unfreeze the full 6000/day budget is still available.
    await guard.unfreeze();
    const after = await guard.execute(
      makeIntent({ amount: { amountMinor: 6_000, currency: "USD" } }),
      paidOk,
    );
    expect(after.status).toBe("executed");
  });

  it("a mid-section freeze burns the consumed mandate use (over-hold) and settles it 'failed'", async () => {
    const keys = generateMandateKeyPair();
    const ledger = new AuditLedger(new MemoryLedgerStore());
    const mandates = new MandateManager(
      { publicKeyPem: keys.publicKeyPem, privateKeyPem: keys.privateKeyPem },
      ledger,
    );
    let guardRef!: VadunoGuard;
    let armed = true;
    const guard = new VadunoGuard({
      policy: makePolicy(),
      ledger,
      mandates,
      requireMandate: true,
      revocationCheck: async () => {
        if (armed) {
          armed = false;
          await guardRef.freeze("kill switch mid-decision");
        }
        return { allowed: true as const };
      },
    });
    guardRef = guard;
    const mandate = await mandates.issue({
      issuer: "prem",
      agentId: "agent-1",
      constraints: {
        maxAmountMinor: 1_000,
        currency: "USD",
        validFrom: "2000-01-01T00:00:00.000Z",
        expiresAt: "2100-01-01T00:00:00.000Z",
        // 2, not 1: with the burned use counting, a maxUses-1 mandate is
        // denied USES_EXHAUSTED at preflight — which would hide the replay
        // path this test exists to observe.
        maxUses: 2,
      },
    });
    const intent = makeIntent({ mandateId: mandate.id });
    let called = false;
    const result = await guard.execute(intent, async () => {
      called = true;
      return null;
    });
    expect(result.status).toBe("denied");
    expect(result.policyResult!.reasons[0]!.code).toBe("GUARD_FROZEN");
    expect(called).toBe(false);
    await guard.unfreeze();

    // The use is BURNED — the documented over-hold direction (ConsumeStore
    // has no un-claim). A retry of the same intent id replays the terminal
    // "failed" outcome rather than executing or hanging on "unresolved".
    const retry = await guard.execute(intent, paidOk);
    expect(retry.status).toBe("replayed");
    expect(retry.status === "replayed" && retry.original.status).toBe("failed");
  });

  it("freeze holds locally and flags isFreezeDegraded when the guard_frozen append fails", async () => {
    const inner = new MemoryLedgerStore();
    const store = {
      append: async (e: { type: string }) => {
        if (e.type === "guard_frozen") throw new Error("disk full");
        return inner.append(e as never);
      },
      last: () => inner.last(),
      all: () => inner.all(),
    };
    const guard = new VadunoGuard({ policy: makePolicy(), ledger: new AuditLedger(store) });
    expect(guard.isFreezeDegraded()).toBe(false);

    // Must NOT throw: the local freeze standing is the safe direction. The
    // degradation flag is the honest signal that a restart would come back
    // unfrozen.
    await guard.freeze("incident");
    expect(guard.isFrozen()).toBe(true);
    expect(guard.isFreezeDegraded()).toBe(true);

    let called = false;
    const denied = await guard.execute(makeIntent(), async () => {
      called = true;
      return null;
    });
    expect(denied.status).toBe("denied");
    expect(called).toBe(false);
  });

  it("hydrate does not lift a live freeze whose durable record was lost", async () => {
    // The guard_frozen append failed (isFreezeDegraded), so the verified
    // ledger legitimately has no record of the freeze. A hydrate that trusts
    // the ledger over the live flag would lift a real freeze — fail open.
    const inner = new MemoryLedgerStore();
    const store = {
      append: async (e: { type: string }) => {
        if (e.type === "guard_frozen") throw new Error("disk full");
        return inner.append(e as never);
      },
      last: () => inner.last(),
      all: () => inner.all(),
    };
    const guard = new VadunoGuard({ policy: makePolicy(), ledger: new AuditLedger(store) });
    await guard.freeze("incident");
    expect(guard.isFreezeDegraded()).toBe(true);

    await guard.hydrateFromLedger();
    expect(guard.isFrozen()).toBe(true);
    const denied = await guard.execute(makeIntent(), paidOk);
    expect(denied.status).toBe("denied");
    expect(denied.policyResult!.reasons[0]!.code).toBe("GUARD_FROZEN");
  });

  it("hydrate waits for an in-flight unfreeze write, so a just-lifted freeze is not resurrected", async () => {
    const inner = new MemoryLedgerStore();
    const seeder = new VadunoGuard({ policy: makePolicy(), ledger: new AuditLedger(inner) });
    await seeder.freeze("incident");

    // The guard_unfrozen append parks until released: the unfreeze has been
    // ISSUED but its record is not yet readable when hydrate snapshots.
    let releaseAppend!: () => void;
    const appendGate = new Promise<void>((r) => (releaseAppend = r));
    const store = {
      append: async (e: { type: string }) => {
        if (e.type === "guard_unfrozen") await appendGate;
        return inner.append(e as never);
      },
      last: () => inner.last(),
      all: () => inner.all(),
    };
    const guard = new VadunoGuard({ policy: makePolicy(), ledger: new AuditLedger(store) });
    const unfreezing = guard.unfreeze(); // deliberately not awaited first
    const hydrating = guard.hydrateFromLedger();
    await new Promise((r) => setImmediate(r));
    releaseAppend();
    await Promise.all([unfreezing, hydrating]);

    // A hydrate that snapshotted before the record landed would read the
    // seeded guard_frozen as the last word and re-assert a freeze the
    // operator already lifted.
    expect(guard.isFrozen()).toBe(false);
    expect((await guard.execute(makeIntent(), paidOk)).status).toBe("executed");
  });

  it("a freeze issued after an unfreeze always wins: no stale unfreeze lets a queued payment through", async () => {
    const { guard } = setup();
    // Hold the critical section open with a payment parked inside its
    // executor, so freeze-state changes and a rival payment pile up behind
    // the mutex in a controlled order.
    let releaseFirst!: () => void;
    const parked = new Promise<void>((r) => (releaseFirst = r));
    const first = guard.execute(makeIntent(), async () => {
      await parked;
      return null;
    });
    await new Promise((r) => setImmediate(r));

    // Operator flip-flop while the mutex is busy: freeze, lift it, a rival
    // payment arrives in the unfrozen gap, then the switch is pulled AGAIN.
    const f1 = guard.freeze("first alarm");
    const u = guard.unfreeze();
    let called = false;
    const rival = guard.execute(makeIntent(), async () => {
      called = true;
      return null;
    });
    // The rival passes the entry freeze check (the guard IS unfrozen here)
    // and queues on the mutex behind the parked payment.
    await new Promise((r) => setImmediate(r));
    const f2 = guard.freeze("second alarm — this one must stick");

    releaseFirst();
    const [firstResult, rivalResult] = await Promise.all([first, rival]);
    await Promise.all([f1, u, f2]);

    // The parked payment was already past the last freeze exit — in-flight
    // work is never recalled.
    expect(firstResult.status).toBe("executed");
    // The regression this pins down: a deferred unfreeze re-assertion ran
    // AFTER freeze #2 flipped the flag, un-freezing the guard long enough
    // for the queued rival to pass BOTH freeze checks and run the rail.
    // The newest call must win: frozen, rival denied, executor never runs.
    expect(guard.isFrozen()).toBe(true);
    expect(called).toBe(false);
    expect(rivalResult.status).toBe("denied");
    expect(rivalResult.policyResult!.reasons[0]!.code).toBe("GUARD_FROZEN");
  });

  it("await guard.freeze() inside the executor completes (no mutex cycle) and the freeze lands durably", async () => {
    const { guard, ledger } = setup();
    // "This charge looks hostile — stop the guard" from inside the rail
    // call. 0.2.x supported this; a freeze that queues on the critical-
    // section mutex deadlocks here and wedges the guard forever.
    const result = await guard.execute(makeIntent(), async () => {
      await guard.freeze("halted from inside the rail call");
      return "charged";
    });
    // The freezing payment itself completes — it was already executing.
    expect(result.status).toBe("executed");
    expect(guard.isFrozen()).toBe(true);
    expect((await ledger.all()).map((e) => e.type)).toContain("guard_frozen");

    // Frozen, not wedged: the next payment gets a prompt denial, and
    // service resumes after unfreeze.
    const denied = await guard.execute(makeIntent(), paidOk);
    expect(denied.status).toBe("denied");
    expect(denied.policyResult!.reasons[0]!.code).toBe("GUARD_FROZEN");
    await guard.unfreeze();
    expect((await guard.execute(makeIntent(), paidOk)).status).toBe("executed");
  });

  it("a freeze landing mid-decision on the authorize() path denies instead of handing back an authorization", async () => {
    // Two-phase is the path every framework integration takes, and an
    // authorization handed back is beyond recall — the CALLER runs the rail.
    // So the last freeze exit must fire before "authorized" is returned.
    let guardRef!: VadunoGuard;
    let armed = true;
    const { guard, ledger } = setup(
      { limits: { perTransactionMinor: 6_000, perDayMinor: 6_000 } },
      {
        revocationCheck: async () => {
          if (armed) {
            armed = false;
            await guardRef.freeze("kill switch mid-authorize");
          }
          return { allowed: true as const };
        },
      },
    );
    guardRef = guard;
    const result = await guard.authorize(
      makeIntent({ amount: { amountMinor: 6_000, currency: "USD" } }),
    );
    expect(result.status).toBe("denied");
    expect(result.policyResult!.reasons[0]!.code).toBe("GUARD_FROZEN");
    // Nothing was handed to a caller, so nothing may claim execution began.
    expect((await ledger.all()).map((e) => e.type)).not.toContain("execution_started");

    // The denied authorization's reservation went back: the full 6000/day
    // budget must be available again after unfreeze.
    await guard.unfreeze();
    const after = await guard.authorize(
      makeIntent({ amount: { amountMinor: 6_000, currency: "USD" } }),
    );
    expect(after.status).toBe("authorized");
  });
});
