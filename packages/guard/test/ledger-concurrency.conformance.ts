/**
 * Conformance suite: an audit ledger under CONCURRENT WRITERS.
 *
 * Run against TWO INDEPENDENT `AuditLedger` HANDLES ON ONE BACKING STORE. That
 * is the entire point and it is not negotiable — every one of these assertions
 * passes trivially against a single handle, which is exactly how this defect
 * survived to 0.2.2. The same shape caught the SpendLimiter and ConsumeStore
 * bugs before it.
 *
 * WHY TWO HANDLES: `AuditLedger.append` derives `seq = last.seq + 1` inside a
 * promise queue scoped to ONE INSTANCE. Two instances over one store both read
 * seq N and both write N+1. Measured before any fix: 30 concurrent appends
 * across three handles produced 10 distinct sequence numbers, each written
 * three times.
 *
 * A naive (check-then-act) implementation passes every SEQUENTIAL test here and
 * fails the concurrent ones. If a change ever makes these pass without touching
 * the append path, suspect the test before believing the fix.
 */
import { describe, expect, it } from "vitest";
import { AuditLedger } from "../src/ledger/ledger.js";
import type { LedgerStore } from "../src/ledger/ledger.js";

export interface ConcurrencyHarness {
  /** A fresh, empty backing store. */
  freshStore(): Promise<LedgerStore> | LedgerStore;
  /**
   * A NEW handle over that same store — a distinct AuditLedger, as a separate
   * process would have. Never return a cached instance.
   */
  handle(store: LedgerStore): AuditLedger;
  /** Cleanup, if the store holds a file or connection. */
  dispose?(store: LedgerStore): Promise<void> | void;
}

export function runLedgerConcurrencyConformance(
  name: string,
  harness: ConcurrencyHarness,
): void {
  describe(`ledger concurrency conformance: ${name}`, () => {
    async function twoHandles(n = 2) {
      const store = await harness.freshStore();
      return {
        store,
        handles: Array.from({ length: n }, () => harness.handle(store)),
        dispose: () => harness.dispose?.(store),
      };
    }

    const seqsOf = async (store: LedgerStore) =>
      (await store.all()).map((e) => e.seq);

    describe("sequence numbers are unique and gapless", () => {
      it("SEQUENTIAL appends alternating between two handles", async () => {
        // A naive implementation PASSES this. It is here to prove the suite is
        // testing concurrency and not merely multi-instance use.
        const { store, handles, dispose } = await twoHandles();
        for (let i = 0; i < 6; i += 1) {
          await handles[i % 2]!.append("policy_decision", { i });
        }
        expect(await seqsOf(store)).toEqual([0, 1, 2, 3, 4, 5]);
        await dispose();
      });

      it("CONCURRENT appends from two handles produce no duplicate seq", async () => {
        const { store, handles, dispose } = await twoHandles();
        await Promise.all(
          Array.from({ length: 8 }, (_, i) =>
            handles[i % 2]!.append("policy_decision", { i }),
          ),
        );
        const seqs = await seqsOf(store);
        expect(new Set(seqs).size).toBe(seqs.length);
        await dispose();
      });

      it("CONCURRENT appends leave no gaps", async () => {
        const { store, handles, dispose } = await twoHandles();
        await Promise.all(
          Array.from({ length: 8 }, (_, i) =>
            handles[i % 2]!.append("policy_decision", { i }),
          ),
        );
        const seqs = (await seqsOf(store)).slice().sort((a, b) => a - b);
        expect(seqs).toEqual(seqs.map((_, i) => i));
        await dispose();
      });

      it("HEAVY: 30 concurrent appends across three handles", async () => {
        // The exact shape that measured 10 distinct seqs before the fix.
        const { store, handles, dispose } = await twoHandles(3);
        await Promise.all(
          Array.from({ length: 30 }, (_, i) =>
            handles[i % 3]!.append("policy_decision", { i }),
          ),
        );
        const seqs = await seqsOf(store);
        expect(seqs).toHaveLength(30);
        expect(new Set(seqs).size).toBe(30);
        await dispose();
      });

      it("EVERY append is durably recorded — none silently dropped", async () => {
        // Distinct from uniqueness: a store with a PRIMARY KEY on seq rejects
        // the loser instead of duplicating it, so the chain looks pristine
        // while an entry is simply gone. That is the quiet failure, and the
        // one that matters most on the execution_result path.
        const { store, handles, dispose } = await twoHandles(3);
        const ids = Array.from({ length: 30 }, (_, i) => `entry-${i}`);
        await Promise.all(
          ids.map((id, i) => handles[i % 3]!.append("policy_decision", { id })),
        );
        const written = (await store.all()).map(
          (e) => (e.data as { id: string }).id,
        );
        expect(new Set(written)).toEqual(new Set(ids));
        await dispose();
      });
    });

    describe("the hash chain survives concurrency", () => {
      it("verify() passes after concurrent appends", async () => {
        // The sharpest assertion in this file. A chain broken by your OWN
        // writers is worse than merely untidy: an honest system now reports
        // itself as tampered, and you can no longer tell an attack from a
        // second worker. The tamper-evidence signal is destroyed by noise.
        const { store, handles, dispose } = await twoHandles(3);
        await Promise.all(
          Array.from({ length: 24 }, (_, i) =>
            handles[i % 3]!.append("policy_decision", { i }),
          ),
        );
        const result = await harness.handle(store).verify();
        expect(result.ok).toBe(true);
        await dispose();
      });

      it("verify() passes when concurrency is interleaved with sequential work", async () => {
        const { store, handles, dispose } = await twoHandles();
        await handles[0]!.append("policy_decision", { phase: "before" });
        await Promise.all(
          Array.from({ length: 10 }, (_, i) =>
            handles[i % 2]!.append("policy_decision", { i }),
          ),
        );
        await handles[1]!.append("policy_decision", { phase: "after" });
        expect((await harness.handle(store).verify()).ok).toBe(true);
        await dispose();
      });

      it("a handle that never wrote can still verify the whole chain", async () => {
        // The auditor's view: a third party reads the store and checks it.
        const { store, handles, dispose } = await twoHandles();
        await Promise.all(
          Array.from({ length: 10 }, (_, i) =>
            handles[i % 2]!.append("policy_decision", { i }),
          ),
        );
        const auditor = harness.handle(store);
        expect((await auditor.verify()).ok).toBe(true);
        await dispose();
      });
    });

    describe("head() agrees with the store after concurrent writes", () => {
      it("reports the true tip", async () => {
        const { store, handles, dispose } = await twoHandles();
        await Promise.all(
          Array.from({ length: 10 }, (_, i) =>
            handles[i % 2]!.append("policy_decision", { i }),
          ),
        );
        const head = await harness.handle(store).head();
        const all = await store.all();
        expect(head.entries).toBe(all.length);
        expect(head.seq).toBe(all.length - 1);
        await dispose();
      });
    });
  });
}
