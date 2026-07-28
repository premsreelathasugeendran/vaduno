import { describe, expect, it, vi } from "vitest";
import {
  MemoryApprovalStore,
  createQueuedApprovalHandler,
} from "../src/approval/approval.js";
import { SwaleGuard } from "../src/guard.js";
import { AuditLedger } from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import { makeIntent, makePolicy } from "./helpers.js";
import type { ApprovalRequest } from "../src/types.js";

function req(intentId = "i-1"): ApprovalRequest {
  return {
    intent: makeIntent({ id: intentId }),
    policyResult: {
      decision: "require_approval",
      reasons: [{ code: "APPROVAL_ALWAYS", message: "x" }],
      policyId: "p",
      policyVersion: 1,
    },
    requestedAt: new Date().toISOString(),
  };
}

describe("MemoryApprovalStore", () => {
  it("enqueues, lists, resolves, and reads decisions", async () => {
    const store = new MemoryApprovalStore();
    await store.enqueue({
      intentId: "i-1",
      agentId: "a",
      amount: { amountMinor: 100, currency: "USD" },
      merchant: { id: "m" },
      policyReasons: [],
      requestedAt: new Date().toISOString(),
    });
    expect((await store.listPending()).map((p) => p.intentId)).toEqual(["i-1"]);
    expect(await store.getDecision("i-1")).toBeNull();

    await store.resolve("i-1", { approved: true, approver: "prem" });
    expect(await store.listPending()).toHaveLength(0);
    expect((await store.getDecision("i-1"))?.approved).toBe(true);
  });
});

describe("createQueuedApprovalHandler", () => {
  it("resolves when a decision is written out-of-band", async () => {
    const store = new MemoryApprovalStore();
    const handler = createQueuedApprovalHandler(store, { pollMs: 1, timeoutMs: 5000 });

    const pending = handler(req("i-1"));
    await vi.waitFor(async () => expect(await store.listPending()).toHaveLength(1));
    await store.resolve("i-1", { approved: true, approver: "prem" });

    const res = await pending;
    expect(res.approved).toBe(true);
    expect(res.approver).toBe("prem");
  });

  it("fails closed (rejects) on timeout", async () => {
    const store = new MemoryApprovalStore();
    const handler = createQueuedApprovalHandler(store, {
      pollMs: 1000,
      timeoutMs: 0,
      now: () => new Date(0),
    });
    const res = await handler(req("i-2"));
    expect(res.approved).toBe(false);
    expect(res.note).toBe("approval timed out");
    // Also recorded as resolved.
    expect((await store.getDecision("i-2"))?.approved).toBe(false);
  });
});

describe("SwaleGuard + queued approval", () => {
  function setup() {
    const store = new MemoryApprovalStore();
    const ledger = new AuditLedger(new MemoryLedgerStore());
    const guard = new SwaleGuard({
      policy: makePolicy({ approval: { always: true } }),
      ledger,
      approvalHandler: createQueuedApprovalHandler(store, { pollMs: 1, timeoutMs: 5000 }),
    });
    return { store, guard };
  }

  it("executes once a dashboard approves the pending item", async () => {
    const { store, guard } = setup();
    const exec = guard.execute(makeIntent(), async () => ({ ok: true }));
    const pending = await vi.waitFor(async () => {
      const list = await store.listPending();
      expect(list).toHaveLength(1);
      return list[0]!;
    });
    await store.resolve(pending.intentId, { approved: true, approver: "prem" });
    const result = await exec;
    expect(result.status).toBe("executed");
  });

  it("rejects when the dashboard declines", async () => {
    const { store, guard } = setup();
    const exec = guard.execute(makeIntent(), async () => ({ ok: true }));
    const pending = await vi.waitFor(async () => {
      const list = await store.listPending();
      expect(list).toHaveLength(1);
      return list[0]!;
    });
    await store.resolve(pending.intentId, { approved: false, note: "too risky" });
    const result = await exec;
    expect(result.status).toBe("approval_rejected");
  });

  it("does not let an approval be replayed to a different payment (same intentId, different merchant)", async () => {
    const { store, guard } = setup();
    // Approve a charge to openai under intentId "reuse".
    const exec1 = guard.execute(
      makeIntent({ id: "reuse", merchant: { id: "openai" } }),
      async () => ({ ok: true }),
    );
    const p1 = await vi.waitFor(async () => {
      const l = await store.listPending();
      expect(l).toHaveLength(1);
      return l[0]!;
    });
    await store.resolve(p1.intentId, { approved: true, approver: "prem" });
    expect((await exec1).status).toBe("executed");

    // Replay the SAME id for a DIFFERENT merchant — the prior approval's
    // fingerprint must not authorize it.
    const r2 = await guard.execute(
      makeIntent({ id: "reuse", merchant: { id: "evil-merchant" } }),
      async () => ({ ok: true }),
    );
    expect(r2.status).toBe("approval_rejected");
  });
});
