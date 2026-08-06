/**
 * ApprovalStore conformance suite.
 *
 * WHY THIS EXISTS. `ApprovalStore` had no Memory-vs-File conformance suite —
 * unlike SpendLimiter and ConsumeStore, whose suites are what caught THEIR
 * prototype-named-key bugs. That absence is exactly where the third instance
 * of the same defect hid: `FileApprovalStore` kept `pending`/`decisions` on
 * plain objects while both sibling file stores had already moved to
 * null-prototype records and documented why. The record is keyed on
 * caller-controlled `intentId`, so an id named after an Object.prototype
 * member read back the PROTOTYPE MEMBER as store state:
 *
 *   - enqueue("__proto__")   -> decisions["__proto__"] is truthy -> silently
 *                               dropped; listPending() never shows it;
 *   - getDecision("constructor") -> returns a FUNCTION with no `.approved`,
 *                               which the queued handler compares by
 *                               fingerprint and records as "approval does not
 *                               match this payment" — a FALSE audit row about
 *                               a human decision that never existed.
 *
 * It fails closed on money, but a silently-dropped approval and a false audit
 * row are audit-integrity defects, which in this project are the product.
 *
 * MemoryApprovalStore (Map-backed) is the reference semantics; every
 * implementation must be indistinguishable from it under these probes. To add
 * a store (Postgres, Redis), copy this file (it imports only vitest and the
 * package types) and register a harness with one or more handles on the SAME
 * backing state — decisions made through one handle must be visible through
 * the others.
 */
import { describe, expect, it } from "vitest";
import type {
  ApprovalStore,
  PendingApproval,
} from "../src/approval/approval.js";

export interface ApprovalStoreHarness {
  name: string;
  /**
   * Fresh, EMPTY store; one or more independent handles on the same state.
   * A single-handle store (in-memory) may return the same handle twice.
   */
  create(): Promise<{ stores: ApprovalStore[]; cleanup?: () => Promise<void> }>;
}

function mkPending(intentId: string): PendingApproval {
  return {
    intentId,
    agentId: "agent-1",
    amount: { amountMinor: 4200, currency: "USD" },
    merchant: { id: "aws" },
    policyReasons: [{ code: "APPROVAL_THRESHOLD", message: "over threshold" }],
    requestedAt: new Date().toISOString(),
    fingerprint: "f".repeat(64),
  };
}

/**
 * Ids named after Object.prototype members. On a plain-object record these
 * read back inherited members (truthy functions/objects) instead of "absent",
 * and assigning "__proto__" mutates a prototype instead of storing anything.
 */
const PROTOTYPE_IDS = [
  "__proto__",
  "constructor",
  "prototype",
  "toString",
  "valueOf",
  "hasOwnProperty",
  "__defineGetter__",
] as const;

export function runApprovalStoreConformance(harness: ApprovalStoreHarness): void {
  const withStores = async (
    fn: (stores: ApprovalStore[]) => Promise<void>,
  ): Promise<void> => {
    const { stores, cleanup } = await harness.create();
    try {
      await fn(stores);
    } finally {
      await cleanup?.();
    }
  };

  describe(`ApprovalStore conformance: ${harness.name}`, () => {
    it("round-trips enqueue -> listPending -> resolve -> getDecision", async () => {
      await withStores(async ([a]) => {
        await a!.enqueue(mkPending("i1"));
        expect((await a!.listPending()).map((p) => p.intentId)).toEqual(["i1"]);
        expect(await a!.getDecision("i1")).toBeNull();
        await a!.resolve("i1", { approved: true, approver: "human" });
        expect(await a!.listPending()).toHaveLength(0);
        const d = await a!.getDecision("i1");
        expect(d?.approved).toBe(true);
        expect(typeof d?.decidedAt).toBe("string");
      });
    });

    it("refuses to resolve an id that is not pending (no pre-approval plant)", async () => {
      await withStores(async ([a]) => {
        await a!.resolve("never-enqueued", { approved: true });
        expect(await a!.getDecision("never-enqueued")).toBeNull();
      });
    });

    it("does not re-enqueue an already-decided id", async () => {
      await withStores(async ([a]) => {
        await a!.enqueue(mkPending("i1"));
        await a!.resolve("i1", { approved: true });
        await a!.enqueue(mkPending("i1"));
        expect(await a!.listPending()).toHaveLength(0);
        expect((await a!.getDecision("i1"))?.approved).toBe(true);
      });
    });

    it("treats an existing decision as immutable", async () => {
      await withStores(async ([a]) => {
        await a!.enqueue(mkPending("i1"));
        await a!.resolve("i1", { approved: true });
        await a!.resolve("i1", { approved: false });
        expect((await a!.getDecision("i1"))?.approved).toBe(true);
      });
    });

    it("a decision made through one handle is visible through another", async () => {
      await withStores(async (stores) => {
        const a = stores[0]!;
        const b = stores[stores.length - 1]!;
        await a.enqueue(mkPending("shared"));
        expect((await b.listPending()).map((p) => p.intentId)).toEqual(["shared"]);
        await b.resolve("shared", { approved: false, note: "rejected" });
        expect((await a.getDecision("shared"))?.approved).toBe(false);
        expect(await a.listPending()).toHaveLength(0);
      });
    });

    for (const id of PROTOTYPE_IDS) {
      it(`treats the id ${JSON.stringify(id)} as data: pending is listed, decision is a real decision`, async () => {
        await withStores(async ([a]) => {
          // Empty store: nothing is decided, whatever the id is named.
          expect(await a!.getDecision(id)).toBeNull();

          await a!.enqueue(mkPending(id));
          const pending = await a!.listPending();
          expect(pending.map((p) => p.intentId)).toEqual([id]);
          // Enqueued-but-undecided must still read as undecided — an
          // inherited prototype member here becomes a "decision" with no
          // .approved, which the queued handler audits as a mismatched
          // human decision that never existed.
          expect(await a!.getDecision(id)).toBeNull();

          await a!.resolve(id, { approved: true, approver: "human" });
          const d = await a!.getDecision(id);
          expect(d).not.toBeNull();
          expect(typeof d).toBe("object");
          expect(d?.approved).toBe(true);
          expect(typeof d?.decidedAt).toBe("string");
          expect(await a!.listPending()).toHaveLength(0);
        });
      });
    }

    it("prototype-named ids coexist with ordinary ids without cross-talk", async () => {
      await withStores(async ([a]) => {
        await a!.enqueue(mkPending("ordinary"));
        await a!.enqueue(mkPending("__proto__"));
        await a!.enqueue(mkPending("toString"));
        const ids = (await a!.listPending()).map((p) => p.intentId).sort();
        expect(ids).toEqual(["__proto__", "ordinary", "toString"]);
        await a!.resolve("__proto__", { approved: false });
        expect((await a!.getDecision("__proto__"))?.approved).toBe(false);
        expect(await a!.getDecision("ordinary")).toBeNull();
        expect((await a!.listPending()).map((p) => p.intentId).sort()).toEqual([
          "ordinary",
          "toString",
        ]);
      });
    });
  });
}
