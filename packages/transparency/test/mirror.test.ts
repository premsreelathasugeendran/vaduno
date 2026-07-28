import { describe, expect, it } from "vitest";
import { AuditLedger, MemoryLedgerStore } from "@vaduno/guard";
import {
  LedgerMirror,
  MemoryTreeStore,
  TransparencyLog,
  generateLogKeyPair,
  leafHash,
  ledgerEntryLeaf,
  verifyInclusion,
  verifyTreeHead,
} from "../src/index.js";

function setup(withSigning = false) {
  const store = new MemoryLedgerStore();
  const ledger = new AuditLedger(store, () => new Date("2026-07-22T00:00:00Z"));
  const tree = new TransparencyLog(new MemoryTreeStore());
  const keys = generateLogKeyPair();
  const mirror = new LedgerMirror(
    ledger,
    tree,
    withSigning ? { signing: { logId: "audit-log", privateKeyPem: keys.privateKeyPem } } : {},
  );
  return { store, ledger, tree, mirror, keys };
}

describe("LedgerMirror", () => {
  it("mirrors ledger entries into the tree incrementally", async () => {
    const { ledger, mirror } = setup();
    await ledger.append("intent_received", { amount: 100 }, { intentId: "i-1" });
    await ledger.append("policy_decision", { decision: "allow" }, { intentId: "i-1" });

    const s1 = await mirror.sync();
    expect(s1.appended).toBe(2);
    expect(s1.head.treeSize).toBe(2);

    await ledger.append("execution_result", { ok: true }, { intentId: "i-1" });
    const s2 = await mirror.sync();
    expect(s2.appended).toBe(1);
    expect(s2.head.treeSize).toBe(3);

    // Idempotent when nothing is new.
    expect((await mirror.sync()).appended).toBe(0);
  });

  it("proves a specific ledger entry is committed under the signed head", async () => {
    const { ledger, mirror, keys } = setup(true);
    for (let i = 0; i < 7; i++) {
      await ledger.append("policy_decision", { n: i }, { intentId: `i-${i}` });
    }
    const { signedHead } = await mirror.sync();
    expect(signedHead).toBeDefined();
    expect(verifyTreeHead(signedHead!, keys.publicKeyPem)).toBe(true);

    // Third-party check: entry seq 4 is in the published history.
    const entry = (await ledger.all())[4]!;
    const proof = await mirror.proveEntry(4);
    expect(
      verifyInclusion(leafHash(ledgerEntryLeaf(entry)), proof, signedHead!.rootHash),
    ).toBe(true);
  });

  it("serializes overlapping sync() calls (no double-append, no false divergence)", async () => {
    const { ledger, tree, mirror } = setup();
    await ledger.append("intent_received", { amount: 100 }, { intentId: "i-1" });
    await ledger.append("policy_decision", { decision: "allow" }, { intentId: "i-1" });

    // Before the fix both syncs read before=0 and appended both entries twice,
    // permanently bricking the mirror with a false "diverged" alarm.
    const [a, b] = await Promise.all([mirror.sync(), mirror.sync()]);
    expect(a.appended + b.appended).toBe(2);
    expect(await tree.size()).toBe(2);
    expect(await mirror.audit()).toEqual({ ok: true, checked: 2 });
    await expect(mirror.sync()).resolves.toMatchObject({ appended: 0 });
  });

  it("audit() racing sync() never reports a false tamper alarm", async () => {
    const { ledger, mirror } = setup();
    for (let i = 0; i < 6; i++) {
      await ledger.append("policy_decision", { n: i }, { intentId: `i-${i}` });
    }
    const [, auditResult] = await Promise.all([mirror.sync(), mirror.audit()]);
    expect(auditResult.ok).toBe(true);
  });

  it("audit() passes on an honest pair and fails when the ledger is rewritten", async () => {
    const { store, ledger, mirror } = setup();
    for (let i = 0; i < 5; i++) {
      await ledger.append("policy_decision", { n: i }, { intentId: `i-${i}` });
    }
    await mirror.sync();
    expect(await mirror.audit()).toEqual({ ok: true, checked: 5 });

    // Tamper with an already-mirrored entry (MemoryLedgerStore returns the
    // same entry objects, so this simulates in-place mutation of history).
    const victim = (await store.all())[2]!;
    (victim.data as { n: number }).n = 999;
    const bad = await mirror.audit();
    expect(bad.ok).toBe(false);
    expect(bad.problem).toMatch(/leaf 2/);
  });

  it("fails sync when the tree is ahead of the ledger (divergence)", async () => {
    const { tree, mirror } = setup();
    await tree.appendLeaf("stray");
    await expect(mirror.sync()).rejects.toThrow(/diverged/);
  });
});
