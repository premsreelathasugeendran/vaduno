/**
 * RevocationStore conformance suite.
 *
 * WHY: the index this store hands out is a bit position in a PUBLISHED W3C
 * Bitstring Status List. A duplicate allocation is not an internal
 * inconsistency — revoking one mandate flips a bit that third-party verifiers
 * read as revoking a different one. A revocation that revokes the wrong
 * credential is worse than one that fails, because it looks like it worked.
 *
 * `MemoryRevocationStore` is correct within one process (it never awaits
 * between checking and assigning) and completely wrong across two. That is
 * exactly the shape a sequential test cannot see, so this suite takes TWO
 * independent handles on one backing store and races them.
 *
 * This file is not published to npm. Copy it, or add your store to this repo.
 */
import { describe, expect, it } from "vitest";
import type { RevocationStore } from "../src/store.js";

export interface RevocationStoreHarness {
  name: string;
  /** Fresh, EMPTY store; one or more independent handles on the same state. */
  create(): Promise<{ stores: RevocationStore[]; cleanup?: () => Promise<void> }>;
}

const CAP = 1024;

export function runRevocationStoreConformance(harness: RevocationStoreHarness): void {
  describe(`RevocationStore conformance: ${harness.name}`, () => {
    async function withStore(fn: (s: RevocationStore[]) => Promise<void>): Promise<void> {
      const { stores, cleanup } = await harness.create();
      if (stores.length === 0) throw new Error("harness returned no stores");
      try {
        await fn(stores);
      } finally {
        await cleanup?.();
      }
    }

    // ---- allocation ---------------------------------------------------------

    it("allocates from zero and increments", async () => {
      await withStore(async ([s]) => {
        expect(await s.allocate("m-1", "a", CAP)).toBe(0);
        expect(await s.allocate("m-2", "a", CAP)).toBe(1);
      });
    });

    it("allocation is idempotent — a mandate keeps its index", async () => {
      await withStore(async ([s]) => {
        const first = await s.allocate("m-1", "a", CAP);
        expect(await s.allocate("m-1", "a", CAP)).toBe(first);
        // And it must not have consumed a second bit.
        expect(await s.allocate("m-2", "a", CAP)).toBe(1);
      });
    });

    it("returns null when the bit space is exhausted", async () => {
      await withStore(async ([s]) => {
        expect(await s.allocate("m-1", null, 1)).toBe(0);
        // A full list must never wrap or reuse — the caller revokes locally and
        // flags the record unpublishable.
        expect(await s.allocate("m-2", null, 1)).toBeNull();
      });
    });

    it("indexOf reports what allocate assigned", async () => {
      await withStore(async ([s]) => {
        expect(await s.indexOf("never")).toBeNull();
        const i = await s.allocate("m-1", null, CAP);
        expect(await s.indexOf("m-1")).toBe(i);
      });
    });

    // ---- THE bug this suite exists for --------------------------------------

    it("CONCURRENCY: parallel allocations never share a bit", async () => {
      await withStore(async (stores) => {
        const N = 24;
        const indices = await Promise.all(
          Array.from({ length: N }, (_, i) =>
            stores[i % stores.length].allocate(`m-${i}`, "agent-1", CAP),
          ),
        );
        const assigned = indices.filter((i): i is number => i !== null);
        expect(assigned).toHaveLength(N);
        // The whole point. A duplicate here is a mis-revocation in a published
        // credential, not a test failure.
        expect(new Set(assigned).size).toBe(N);
      });
    });

    it("CONCURRENCY: parallel allocations of the SAME mandate yield ONE bit", async () => {
      await withStore(async (stores) => {
        const results = await Promise.all(
          Array.from({ length: 8 }, (_, i) =>
            stores[i % stores.length].allocate("same-mandate", "agent-1", CAP),
          ),
        );
        expect(new Set(results).size).toBe(1);
        // And exactly one bit was consumed, so the next mandate gets 1.
        expect(await stores[0].allocate("other", null, CAP)).toBe(1);
      });
    });

    it("CROSS-PROCESS: an index allocated on one handle is visible on another", async () => {
      await withStore(async (stores) => {
        if (stores.length < 2) return;
        const [a, b] = stores;
        const i = await a.allocate("m-1", "agent-1", CAP);
        expect(await b.indexOf("m-1")).toBe(i);
        // And b must not hand the same bit to someone else.
        expect(await b.allocate("m-2", "agent-1", CAP)).not.toBe(i);
      });
    });

    // ---- records ------------------------------------------------------------

    it("revoke then get round-trips the record", async () => {
      await withStore(async ([s]) => {
        expect(await s.get("m-1")).toBeNull();
        await s.revoke({
          mandateId: "m-1",
          index: 0,
          purpose: "revocation",
          revokedAt: "2026-01-01T00:00:00.000Z",
          reason: "compromised",
          by: "ops",
          agentId: "agent-1",
        });
        const r = await s.get("m-1");
        expect(r?.purpose).toBe("revocation");
        expect(r?.reason).toBe("compromised");
        expect(r?.index).toBe(0);
      });
    });

    it("a record with a null index is preserved — a full list still revokes locally", async () => {
      await withStore(async ([s]) => {
        await s.revoke({
          mandateId: "m-x",
          index: null,
          purpose: "revocation",
          revokedAt: "2026-01-01T00:00:00.000Z",
          reason: null,
          by: null,
          agentId: null,
        });
        expect((await s.get("m-x"))?.index).toBeNull();
      });
    });

    it("clear lifts the revocation but NOT the index assignment", async () => {
      await withStore(async ([s]) => {
        const i = await s.allocate("m-1", null, CAP);
        await s.revoke({
          mandateId: "m-1",
          index: i,
          purpose: "suspension",
          revokedAt: "2026-01-01T00:00:00.000Z",
          reason: null,
          by: null,
          agentId: null,
        });
        await s.clear("m-1");
        expect(await s.get("m-1")).toBeNull();
        // The bit stays owned. Reissuing it would make a later revocation flip
        // a bit a verifier already associates with this mandate.
        expect(await s.indexOf("m-1")).toBe(i);
      });
    });

    it("CROSS-PROCESS: a revocation on one handle is seen by another", async () => {
      await withStore(async (stores) => {
        if (stores.length < 2) return;
        const [a, b] = stores;
        await a.revoke({
          mandateId: "m-1",
          index: 0,
          purpose: "revocation",
          revokedAt: "2026-01-01T00:00:00.000Z",
          reason: null,
          by: null,
          agentId: null,
        });
        expect(await b.get("m-1")).not.toBeNull();
      });
    });

    // ---- agent links and blocks --------------------------------------------

    it("links a mandate to an agent and lists it back", async () => {
      // The original version of this test called link("m-2", …) and then
      // asserted only on "m-1" — which allocate() had already linked — so it
      // passed against a link() that recorded nothing. A test that cannot
      // fail proves nothing; assert on the mandate link() was given.
      await withStore(async ([s]) => {
        await s.allocate("m-1", "agent-1", CAP);
        await s.link("m-2", "agent-1");
        expect(await s.agentOf("m-1")).toBe("agent-1");
        expect(await s.agentOf("m-2")).toBe("agent-1");
        const mandates = await s.mandatesFor("agent-1");
        expect(mandates).toContain("m-1");
        expect(mandates).toContain("m-2");
      });
    });

    it("link BEFORE allocate is RECORDED, never silently dropped", async () => {
      // The silent-drop shape this project keeps finding: a method that
      // reports success while writing nothing. A mandate is routinely linked
      // before it holds a status-list bit; if that link vanishes, agentOf()
      // answers null, mandatesFor() omits the mandate, revokeAgent's fan-out
      // misses it, and its bit is never set in the published list — a
      // third-party verifier reads a mandate of a REVOKED agent as ACTIVE.
      await withStore(async (stores) => {
        const a = stores[0];
        await a.link("m-linked-first", "agent-7");
        expect(await a.agentOf("m-linked-first")).toBe("agent-7");
        expect(await a.mandatesFor("agent-7")).toContain("m-linked-first");
        // No bit yet: linked is not allocated.
        expect(await a.indexOf("m-linked-first")).toBeNull();
        // And the link is durable in the SHARED state, not a handle-local
        // fiction: the other handle (another process) must see it too.
        const b = stores[stores.length - 1];
        expect(await b.agentOf("m-linked-first")).toBe("agent-7");
        expect(await b.mandatesFor("agent-7")).toContain("m-linked-first");
      });
    });

    it("allocate AFTER link assigns a fresh bit and keeps the association", async () => {
      await withStore(async ([s]) => {
        expect(await s.allocate("m-0", null, CAP)).toBe(0);
        await s.link("m-1", "agent-1");
        // The link-only mandate holds no bit, so it must get the NEXT free
        // one — never bit 0 (someone else's), never a phantom.
        expect(await s.allocate("m-1", null, CAP)).toBe(1);
        expect(await s.indexOf("m-1")).toBe(1);
        // Allocating with a null agentId must not erase the linked agent.
        expect(await s.agentOf("m-1")).toBe("agent-1");
        expect(await s.mandatesFor("agent-1")).toContain("m-1");
        // Idempotency still holds through the link-then-allocate path.
        expect(await s.allocate("m-1", null, CAP)).toBe(1);
        expect(await s.allocate("m-2", null, CAP)).toBe(2);
      });
    });

    it("blocks and unblocks an agent", async () => {
      await withStore(async ([s]) => {
        expect(await s.isAgentBlocked("agent-1")).toBe(false);
        await s.blockAgent("agent-1", {
          reason: "compromised",
          by: "ops",
          at: "2026-01-01T00:00:00.000Z",
          purpose: "suspension",
        });
        expect(await s.isAgentBlocked("agent-1")).toBe(true);
        await s.unblockAgent("agent-1");
        expect(await s.isAgentBlocked("agent-1")).toBe(false);
      });
    });

    it("a permanent revocation is NEVER downgraded to a liftable suspension", async () => {
      await withStore(async ([s]) => {
        await s.blockAgent("agent-1", {
          reason: "fraud",
          by: "ops",
          at: "2026-01-01T00:00:00.000Z",
          purpose: "revocation",
        });
        await s.blockAgent("agent-1", {
          reason: "oops",
          by: "someone",
          at: "2026-01-02T00:00:00.000Z",
          purpose: "suspension",
        });
        // Otherwise a later, weaker call could quietly make a permanent kill
        // liftable.
        expect((await s.getAgentBlock("agent-1"))?.purpose).toBe("revocation");
      });
    });

    it("CROSS-PROCESS: an agent block on one handle is seen by another", async () => {
      await withStore(async (stores) => {
        if (stores.length < 2) return;
        const [a, b] = stores;
        await a.blockAgent("agent-1", {
          reason: null,
          by: null,
          at: "2026-01-01T00:00:00.000Z",
          purpose: "revocation",
        });
        expect(await b.isAgentBlocked("agent-1")).toBe(true);
      });
    });

    it("snapshot reports records, blocks and the assigned count", async () => {
      await withStore(async ([s]) => {
        await s.allocate("m-1", null, CAP);
        await s.allocate("m-2", null, CAP);
        await s.revoke({
          mandateId: "m-1",
          index: 0,
          purpose: "revocation",
          revokedAt: "2026-01-01T00:00:00.000Z",
          reason: null,
          by: null,
          agentId: null,
        });
        await s.blockAgent("agent-9", {
          reason: null,
          by: null,
          at: "2026-01-01T00:00:00.000Z",
          purpose: "suspension",
        });
        const snap = await s.snapshot();
        expect(snap.records).toHaveLength(1);
        expect(snap.blockedAgents).toContain("agent-9");
        expect(snap.assigned).toBe(2);
      });
    });
  });
}
