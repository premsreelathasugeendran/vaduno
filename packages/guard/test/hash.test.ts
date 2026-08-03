import { describe, expect, it } from "vitest";
import { CanonicalizeError, canonicalJson, sha256Hex } from "../src/ledger/hash.js";
import { AuditLedger } from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";

describe("canonicalJson", () => {
  it("is stable under key order", () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe(canonicalJson({ a: 2, b: 1 }));
  });

  it("sorts nested objects and keeps array order", () => {
    expect(canonicalJson({ x: [{ b: 1, a: 2 }], a: 1 })).toBe(
      '{"a":1,"x":[{"a":2,"b":1}]}',
    );
  });

  it("drops undefined values", () => {
    expect(canonicalJson({ a: 1, b: undefined })).toBe('{"a":1}');
  });

  it("commits __proto__ as an ordinary key (no pollution, no omission)", () => {
    const poisoned = JSON.parse('{"__proto__": {"x": 1}, "a": 2}');
    const out = canonicalJson(poisoned);
    expect(out).toContain('"__proto__"');
    // Two objects differing only in a __proto__ key must hash differently.
    expect(canonicalJson(JSON.parse('{"__proto__":{"x":1}}'))).not.toBe(
      canonicalJson(JSON.parse('{"__proto__":{"x":2}}')),
    );
  });

  it("REFUSES a bigint rather than encoding it deterministically", () => {
    // Reversed in 0.3.0. This test previously asserted the opposite, and the
    // "deterministic" encoding it was protecting was `String(n) + "n"` — which
    // collided with the ordinary string "10n". Determinism is not the property
    // a signature needs; injectivity is. See canonical-injectivity.test.ts.
    expect(() => canonicalJson({ n: 10n })).toThrow(CanonicalizeError);
  });
});

describe("sha256Hex", () => {
  it("matches a known vector", () => {
    expect(sha256Hex("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});

describe("AuditLedger chain", () => {
  it("verifies an untouched chain", async () => {
    const ledger = new AuditLedger(new MemoryLedgerStore());
    await ledger.append("guard_frozen", { reason: "a" });
    await ledger.append("guard_unfrozen", { previousReason: "a" });
    await ledger.append("policy_updated", { n: 1 });
    const result = await ledger.verify();
    expect(result.ok).toBe(true);
    expect(result.entries).toBe(3);
  });

  it("detects data tampering", async () => {
    const store = new MemoryLedgerStore();
    const ledger = new AuditLedger(store);
    await ledger.append("guard_frozen", { reason: "a" });
    await ledger.append("guard_unfrozen", { previousReason: "a" });
    const entries = await store.all();
    // Mutate the stored copy directly (simulates DB-side tampering).
    (store as unknown as { entries: typeof entries }).entries[0]!.data = {
      reason: "b",
    };
    const result = await ledger.verify();
    expect(result.ok).toBe(false);
    expect(result.firstBadSeq).toBe(0);
  });

  it("detects deletion (sequence gap)", async () => {
    const store = new MemoryLedgerStore();
    const ledger = new AuditLedger(store);
    await ledger.append("guard_frozen", { reason: "a" });
    await ledger.append("guard_unfrozen", { previousReason: "a" });
    await ledger.append("policy_updated", { n: 1 });
    (store as unknown as { entries: unknown[] }).entries.splice(1, 1);
    const result = await ledger.verify();
    expect(result.ok).toBe(false);
    // Deletion must read as a GAP, never as a fork — the operator's next move
    // (hunt the attacker vs hunt the second writer) hinges on this word.
    expect(result.problem).toMatch(/sequence gap/);
    expect(result.problem).not.toMatch(/fork/);
  });

  it("reports a DUPLICATED seq as a fork, distinctly from a gap", async () => {
    // The concurrent-writer signature: two children of one parent. Before
    // 0.3.0 verify() called this a "sequence gap" — deletion-shaped — so an
    // honest ledger that hit its own race was forensically misdiagnosed as
    // tampered-by-deletion.
    const store = new MemoryLedgerStore();
    const ledger = new AuditLedger(store);
    await ledger.append("policy_updated", { i: 0 });
    const first = (await store.all())[0]!;
    // A second writer that read the same tip: same seq, same prevHash,
    // different payload, correctly self-hashed. The store's own
    // compare-and-append refuses this since 0.3.0, so the row is planted
    // store-side — the pre-fix racing writer, a hostile store, and a
    // pre-0.3.0 store that skipped the comparison all leave this exact shape.
    const { hash: _drop, ...partial } = first;
    const rival = { ...partial, data: { i: "rival" } };
    (store as unknown as { entries: unknown[] }).entries.push({
      ...rival,
      hash: sha256Hex(canonicalJson(rival)),
    });

    const result = await ledger.verify();
    expect(result.ok).toBe(false);
    expect(result.firstBadSeq).toBe(0);
    expect(result.problem).toMatch(/duplicate or regressed seq/);
    expect(result.problem).toMatch(/fork/);
    expect(result.problem).not.toMatch(/sequence gap/);
  });

  it("head() refuses to anchor a forked chain", async () => {
    // A retained head is the operator's trust anchor. Issuing one over a
    // chain with duplicated seqs would bless the fork: whichever branch
    // verify(head) later reads becomes "the" history.
    const store = new MemoryLedgerStore();
    const ledger = new AuditLedger(store);
    await ledger.append("policy_updated", { i: 0 });
    const first = (await store.all())[0]!;
    const { hash: _drop, ...partial } = first;
    const rival = { ...partial, data: { i: "rival" } };
    // Planted store-side: the compare-and-append API refuses a stale-tip
    // write, but the store itself (or a pre-0.3.0 writer) can still hold one.
    (store as unknown as { entries: unknown[] }).entries.push({
      ...rival,
      hash: sha256Hex(canonicalJson(rival)),
    });

    await expect(ledger.head()).rejects.toThrow(/forked or truncated/);
  });

  it("serializes concurrent appends into a valid chain", async () => {
    const ledger = new AuditLedger(new MemoryLedgerStore());
    await Promise.all(
      Array.from({ length: 25 }, (_, i) =>
        ledger.append("policy_updated", { i }),
      ),
    );
    const result = await ledger.verify();
    expect(result.ok).toBe(true);
    expect(result.entries).toBe(25);
  });

  it("retained head detects truncation an internally-consistent forgery would pass", async () => {
    const store = new MemoryLedgerStore();
    const ledger = new AuditLedger(store);
    await ledger.append("policy_updated", { i: 0 });
    await ledger.append("policy_updated", { i: 1 });
    await ledger.append("policy_updated", { i: 2 });
    const head = await ledger.head();

    // Attacker truncates the last entry; the remaining prefix self-verifies.
    (store as unknown as { entries: unknown[] }).entries.pop();
    expect((await ledger.verify()).ok).toBe(true); // prefix alone looks fine
    expect((await ledger.verify(head)).ok).toBe(false); // vs retained head: caught
  });

  it("trailFor returns only the given intent's entries", async () => {
    const ledger = new AuditLedger(new MemoryLedgerStore());
    await ledger.append("intent_received", { a: 1 }, { intentId: "i1", agentId: "g" });
    await ledger.append("intent_received", { a: 2 }, { intentId: "i2", agentId: "g" });
    await ledger.append("policy_decision", { a: 3 }, { intentId: "i1", agentId: "g" });
    const trail = await ledger.trailFor("i1");
    expect(trail.map((e) => e.type)).toEqual([
      "intent_received",
      "policy_decision",
    ]);
  });
});
