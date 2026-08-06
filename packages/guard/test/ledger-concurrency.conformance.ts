/**
 * Conformance suite: an audit ledger under CONCURRENT WRITERS.
 *
 * Run against TWO INDEPENDENT WRITER HANDLES ON ONE BACKING RESOURCE. That is
 * the entire point and it is not negotiable — every one of these assertions
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
 * WHY A RESOURCE, NOT A STORE OBJECT: the real collision is two writers on one
 * PATH (or table, or pool) — two processes never share a store object. A
 * harness that hands every handle the same store object is defeated by the
 * most dangerous naive fix: move the queue from AuditLedger into the store.
 * That serializes handles which share the object and leaves the cross-process
 * race untouched — and it passes every test here IF the harness shares the
 * object. So `handle()` mints its own store from the shared descriptor
 * wherever the backend has one (a file path, a table, a pool). Only a backend
 * whose store object IS the resource (memory) may share the object.
 *
 * A naive (check-then-act) implementation passes every SEQUENTIAL test here and
 * fails the concurrent ones. If a change ever makes these pass without touching
 * the append path, suspect the test before believing the fix.
 */
import { describe, expect, it } from "vitest";
import { AuditLedger } from "../src/ledger/ledger.js";
import type { LedgerStore } from "../src/ledger/ledger.js";

export interface ConcurrencyHarness<R> {
  /**
   * A fresh, empty backing RESOURCE — the thing two processes would actually
   * share: a file path, a table name, a pool. For a memory backend the store
   * object itself is the resource; nothing else qualifies.
   */
  freshResource(): Promise<R> | R;
  /**
   * A NEW writer over that resource, constructed exactly as a separate process
   * would construct it: a distinct AuditLedger AND, wherever the backend
   * permits, a distinct store object minted from the descriptor. Never return
   * a cached instance.
   */
  handle(resource: R): AuditLedger;
  /**
   * An independent read-only view of the resource for assertions — a fresh
   * store where the backend permits, so the suite reads what was durably
   * written rather than any one writer's in-memory idea of it.
   */
  reader(resource: R): LedgerStore;
  /** Cleanup, if the resource holds a file or connection. */
  dispose?(resource: R): Promise<void> | void;
}

export function runLedgerConcurrencyConformance<R>(
  name: string,
  harness: ConcurrencyHarness<R>,
): void {
  describe(`ledger concurrency conformance: ${name}`, () => {
    async function open(n = 2) {
      const resource = await harness.freshResource();
      return {
        resource,
        handles: Array.from({ length: n }, () => harness.handle(resource)),
        read: () => harness.reader(resource).all(),
        dispose: () => harness.dispose?.(resource),
      };
    }

    describe("sequence numbers are unique and gapless", () => {
      it("SEQUENTIAL appends alternating between two handles", async () => {
        // A naive implementation PASSES this. It is here to prove the suite is
        // testing concurrency and not merely multi-instance use.
        const { handles, read, dispose } = await open();
        for (let i = 0; i < 6; i += 1) {
          await handles[i % 2]!.append("policy_decision", { i });
        }
        expect((await read()).map((e) => e.seq)).toEqual([0, 1, 2, 3, 4, 5]);
        await dispose();
      });

      it("CONCURRENT appends from two handles produce no duplicate seq", async () => {
        const { handles, read, dispose } = await open();
        await Promise.all(
          Array.from({ length: 8 }, (_, i) =>
            handles[i % 2]!.append("policy_decision", { i }),
          ),
        );
        const seqs = (await read()).map((e) => e.seq);
        expect(new Set(seqs).size).toBe(seqs.length);
        await dispose();
      });

      it("CONCURRENT appends leave no gaps", async () => {
        const { handles, read, dispose } = await open();
        await Promise.all(
          Array.from({ length: 8 }, (_, i) =>
            handles[i % 2]!.append("policy_decision", { i }),
          ),
        );
        const seqs = (await read()).map((e) => e.seq).sort((a, b) => a - b);
        expect(seqs).toEqual(seqs.map((_, i) => i));
        await dispose();
      });

      it("HEAVY: 30 concurrent appends across three handles", async () => {
        // The exact shape that measured 10 distinct seqs before the fix.
        const { handles, read, dispose } = await open(3);
        await Promise.all(
          Array.from({ length: 30 }, (_, i) =>
            handles[i % 3]!.append("policy_decision", { i }),
          ),
        );
        const seqs = (await read()).map((e) => e.seq);
        expect(seqs).toHaveLength(30);
        expect(new Set(seqs).size).toBe(30);
        await dispose();
      });

      it("EVERY append is durably recorded — none silently dropped", async () => {
        // Distinct from uniqueness: a store with a PRIMARY KEY on seq rejects
        // the loser instead of duplicating it, so the chain looks pristine
        // while an entry is simply gone. That is the quiet failure, and the
        // one that matters most on the execution_result path.
        const { handles, read, dispose } = await open(3);
        const ids = Array.from({ length: 30 }, (_, i) => `entry-${i}`);
        await Promise.all(
          ids.map((id, i) => handles[i % 3]!.append("policy_decision", { id })),
        );
        const written = (await read()).map((e) => (e.data as { id: string }).id);
        expect(new Set(written)).toEqual(new Set(ids));
        await dispose();
      });
    });

    describe("the hash chain survives concurrency", () => {
      it("no prevHash value appears twice — the anti-fork invariant", async () => {
        // Two entries committing to the SAME parent is the definition of a
        // fork, whatever their seqs say. This is exactly the invariant a
        // `unique (prev_hash)` constraint enforces at the DB layer; without
        // this assertion "no duplicate seq" can be satisfied by renumbering
        // the loser while both children of one parent survive.
        //
        // THIS ASSERTION FAILED ONCE, in one full 1022-test workspace run, and
        // was then hunted rather than shrugged off. It did NOT reproduce in:
        // 5 isolated runs, 3 full guard suites, 2 full workspace suites, 25
        // runs of this file under three concurrent full-guard-suite loops, or
        // 1,110 in-process rounds of this exact shape (24 appends, 3 handles)
        // across all three stores — including a variant with FileMutex
        // staleMs forced to 1 ms. What the hunt DID establish:
        //  - MemoryLedgerStore cannot fork: its compare-and-append is one
        //    synchronous body, so once an entry is the tail, exactly one
        //    append can match its hash as `expected.prevHash`.
        //  - SupabaseLedgerStore cannot fork: `unique (prev_hash)` makes a
        //    second child of one parent unrepresentable AT THE DATABASE, and
        //    the schema-faithful fake enforces it in one synchronous body.
        //  - JsonlLedgerStore can fork by exactly ONE mechanism — two
        //    simultaneous FileMutex holders, which requires a stale reclaim of
        //    a LIVE holder. That mechanism was real, had no test, and is now
        //    fixed (heartbeat + monotonic confirmed reclaim; see
        //    src/enforce/file-mutex.ts and test/file-mutex.test.ts, where both
        //    of its triggers are reproduced against the pre-fix code).
        // The honest statement: the fork path that existed has been closed,
        // and this specific failure was never reproduced, so it is NOT claimed
        // to have been that path. If it recurs, the fixture below plus
        // verify() (which reports a fork distinctly from a gap) is where to
        // start.
        const { handles, read, dispose } = await open(3);
        await Promise.all(
          Array.from({ length: 24 }, (_, i) =>
            handles[i % 3]!.append("policy_decision", { i }),
          ),
        );
        const prevs = (await read()).map((e) => e.prevHash);
        expect(new Set(prevs).size).toBe(prevs.length);
        await dispose();
      });

      it("verify() passes after concurrent appends", async () => {
        // The sharpest assertion in this file. A chain broken by your OWN
        // writers is worse than merely untidy: an honest system now reports
        // itself as tampered, and you can no longer tell an attack from a
        // second worker. The tamper-evidence signal is destroyed by noise.
        const { resource, handles, dispose } = await open(3);
        await Promise.all(
          Array.from({ length: 24 }, (_, i) =>
            handles[i % 3]!.append("policy_decision", { i }),
          ),
        );
        const result = await harness.handle(resource).verify();
        expect(result.ok).toBe(true);
        await dispose();
      });

      it("verify() passes when concurrency is interleaved with sequential work", async () => {
        const { resource, handles, dispose } = await open();
        await handles[0]!.append("policy_decision", { phase: "before" });
        await Promise.all(
          Array.from({ length: 10 }, (_, i) =>
            handles[i % 2]!.append("policy_decision", { i }),
          ),
        );
        await handles[1]!.append("policy_decision", { phase: "after" });
        expect((await harness.handle(resource).verify()).ok).toBe(true);
        await dispose();
      });

      it("a handle that never wrote can still verify the whole chain", async () => {
        // The auditor's view: a third party reads the store and checks it.
        const { resource, handles, dispose } = await open();
        await Promise.all(
          Array.from({ length: 10 }, (_, i) =>
            handles[i % 2]!.append("policy_decision", { i }),
          ),
        );
        const auditor = harness.handle(resource);
        expect((await auditor.verify()).ok).toBe(true);
        await dispose();
      });
    });

    describe("head() agrees with the store after concurrent writes", () => {
      it("issues a head, and it is the true tip", async () => {
        // head() refuses a forked chain outright, so merely RETURNING here is
        // part of the contract under test: after concurrent appends the chain
        // must be linear enough to anchor.
        const { resource, handles, read, dispose } = await open();
        await Promise.all(
          Array.from({ length: 10 }, (_, i) =>
            handles[i % 2]!.append("policy_decision", { i }),
          ),
        );
        const head = await harness.handle(resource).head();
        const all = await read();
        expect(head.entries).toBe(all.length);
        expect(head.seq).toBe(all.length - 1);
        await dispose();
      });
    });
  });
}
