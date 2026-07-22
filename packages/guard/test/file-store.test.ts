import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FileApprovalStore } from "../src/approval/file-store.js";
import type { PendingApproval } from "../src/approval/approval.js";

const dirs: string[] = [];
function tempFile(): string {
  const dir = mkdtempSync(join(tmpdir(), "paygent-approvals-"));
  dirs.push(dir);
  return join(dir, "approvals.json");
}
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

function mkPending(intentId: string): PendingApproval {
  return {
    intentId,
    agentId: "a",
    amount: { amountMinor: 4200, currency: "USD" },
    merchant: { id: "aws" },
    policyReasons: [{ code: "APPROVAL_THRESHOLD", message: "x" }],
    requestedAt: new Date().toISOString(),
  };
}

describe("FileApprovalStore", () => {
  it("round-trips enqueue -> resolve -> getDecision", async () => {
    const store = new FileApprovalStore(tempFile());
    await store.enqueue(mkPending("i1"));
    expect((await store.listPending()).map((p) => p.intentId)).toEqual(["i1"]);
    await store.resolve("i1", { approved: true, approver: "prem" });
    expect(await store.listPending()).toHaveLength(0);
    expect((await store.getDecision("i1"))?.approved).toBe(true);
  });

  it("refuses to resolve an id that is not currently pending (no pre-approval plant)", async () => {
    const store = new FileApprovalStore(tempFile());
    await store.resolve("never-enqueued", { approved: true });
    expect(await store.getDecision("never-enqueued")).toBeNull();
  });

  it("does not re-enqueue an already-decided id", async () => {
    const store = new FileApprovalStore(tempFile());
    await store.enqueue(mkPending("i1"));
    await store.resolve("i1", { approved: true });
    await store.enqueue(mkPending("i1")); // agent retries / re-asks
    expect(await store.listPending()).toHaveLength(0);
    expect((await store.getDecision("i1"))?.approved).toBe(true);
  });

  it("treats an existing decision as immutable", async () => {
    const store = new FileApprovalStore(tempFile());
    await store.enqueue(mkPending("i1"));
    await store.resolve("i1", { approved: true, approver: "prem" });
    // A second resolve must not flip it (also it is no longer pending).
    await store.resolve("i1", { approved: false });
    expect((await store.getDecision("i1"))?.approved).toBe(true);
  });

  it("serializes interleaved enqueue/resolve without losing a decision", async () => {
    // Two store handles on ONE file (agent + dashboard). The lost-update bug
    // would let a stale enqueue clobber a fresh decision; with locking it must
    // not. Fire an enqueue(Y) and a resolve(X) concurrently.
    const file = tempFile();
    const agent = new FileApprovalStore(file);
    const dash = new FileApprovalStore(file);
    await agent.enqueue(mkPending("X"));

    await Promise.all([agent.enqueue(mkPending("Y")), dash.resolve("X", { approved: true })]);

    // X's approval survives; Y is pending; nothing was lost.
    expect((await dash.getDecision("X"))?.approved).toBe(true);
    const pendingIds = (await agent.listPending()).map((p) => p.intentId).sort();
    expect(pendingIds).toEqual(["Y"]);
  });
});
