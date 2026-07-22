import { describe, expect, it } from "vitest";
import {
  MemoryTreeStore,
  TransparencyLog,
  detectSplitView,
  generateLogKeyPair,
  signTreeHead,
  verifyTreeHead,
  witnessObserve,
  type WitnessState,
} from "../src/index.js";

const keys = generateLogKeyPair();
const signing = { logId: "log-1", privateKeyPem: keys.privateKeyPem };

describe("signed tree heads", () => {
  it("signs and verifies a head", async () => {
    const log = new TransparencyLog(new MemoryTreeStore());
    await log.appendLeaf("a");
    const sth = signTreeHead(await log.head(), signing);
    expect(sth.logId).toBe("log-1");
    expect(sth.treeSize).toBe(1);
    expect(verifyTreeHead(sth, keys.publicKeyPem)).toBe(true);
  });

  it("rejects a tampered or wrong-key head, failing closed", async () => {
    const log = new TransparencyLog(new MemoryTreeStore());
    await log.appendLeaf("a");
    const sth = signTreeHead(await log.head(), signing);
    expect(verifyTreeHead({ ...sth, treeSize: 2 }, keys.publicKeyPem)).toBe(false);
    expect(verifyTreeHead({ ...sth, rootHash: "00".repeat(32) }, keys.publicKeyPem)).toBe(false);
    expect(verifyTreeHead({ ...sth, signature: "garbage" }, keys.publicKeyPem)).toBe(false);
    expect(verifyTreeHead(sth, generateLogKeyPair().publicKeyPem)).toBe(false);
    expect(verifyTreeHead(sth, "not a pem")).toBe(false);
  });
});

describe("witness protocol", () => {
  async function grow(log: TransparencyLog, from: number, to: number) {
    for (let i = from; i < to; i++) await log.appendLeaf(`w-${i}`);
  }

  it("accepts an honest grow-only log", async () => {
    const log = new TransparencyLog(new MemoryTreeStore());
    let state: WitnessState = {
      logId: "log-1",
      publicKeyPem: keys.publicKeyPem,
      lastHead: null,
    };

    await grow(log, 0, 5);
    const sth1 = signTreeHead(await log.head(), signing);
    const r1 = witnessObserve(state, sth1);
    expect(r1.ok).toBe(true);
    if (r1.ok) state = r1.state;

    await grow(log, 5, 12);
    const sth2 = signTreeHead(await log.head(), signing);
    const proof = await log.proveConsistency(5, 12);
    const r2 = witnessObserve(state, sth2, proof);
    expect(r2.ok).toBe(true);
    if (r2.ok) state = r2.state;
    expect(state.lastHead?.treeSize).toBe(12);

    // Re-observing the same head needs no proof.
    expect(witnessObserve(state, sth2).ok).toBe(true);
  });

  it("refuses growth without a proof, and an invalid proof", async () => {
    const log = new TransparencyLog(new MemoryTreeStore());
    await grow(log, 0, 4);
    const sth1 = signTreeHead(await log.head(), signing);
    const first = witnessObserve(
      { logId: "log-1", publicKeyPem: keys.publicKeyPem, lastHead: null },
      sth1,
    );
    if (!first.ok) throw new Error("baseline observation failed");

    await grow(log, 4, 9);
    const sth2 = signTreeHead(await log.head(), signing);
    const noProof = witnessObserve(first.state, sth2);
    expect(noProof).toMatchObject({ ok: false, code: "CONSISTENCY_PROOF_MISSING" });

    const wrong = await log.proveConsistency(5, 9); // wrong first size
    expect(witnessObserve(first.state, sth2, wrong)).toMatchObject({
      ok: false,
      code: "CONSISTENCY_PROOF_INVALID",
    });
  });

  it("catches truncation, rewrite, wrong log, and bad signature", async () => {
    const honest = new TransparencyLog(new MemoryTreeStore());
    await grow(honest, 0, 6);
    const base = witnessObserve(
      { logId: "log-1", publicKeyPem: keys.publicKeyPem, lastHead: null },
      signTreeHead(await honest.head(), signing),
    );
    if (!base.ok) throw new Error("baseline observation failed");
    const state = base.state;

    // Truncated history.
    const shrunk = signTreeHead(await honest.headAt(3), signing);
    expect(witnessObserve(state, shrunk)).toMatchObject({ ok: false, code: "TREE_SHRANK" });

    // Rewritten history: same size, different leaves.
    const forged = new TransparencyLog(new MemoryTreeStore());
    for (let i = 0; i < 6; i++) await forged.appendLeaf(`forged-${i}`);
    const rewritten = signTreeHead(await forged.head(), signing);
    expect(witnessObserve(state, rewritten)).toMatchObject({
      ok: false,
      code: "ROOT_CHANGED_WITHOUT_GROWTH",
    });

    // Wrong log id.
    const otherLog = signTreeHead(await honest.head(), {
      logId: "log-2",
      privateKeyPem: keys.privateKeyPem,
    });
    expect(witnessObserve(state, otherLog)).toMatchObject({ ok: false, code: "WRONG_LOG" });

    // Signature from a different key.
    const impostor = signTreeHead(await honest.head(), {
      logId: "log-1",
      privateKeyPem: generateLogKeyPair().privateKeyPem,
    });
    expect(witnessObserve(state, impostor)).toMatchObject({ ok: false, code: "BAD_SIGNATURE" });
  });

  it("accepts growth from an EMPTY-tree baseline without a proof (no lockout)", async () => {
    const log = new TransparencyLog(new MemoryTreeStore());
    // Witness starts following the log before its first leaf exists.
    const sth0 = signTreeHead(await log.head(), signing);
    expect(sth0.treeSize).toBe(0);
    const r0 = witnessObserve(
      { logId: "log-1", publicKeyPem: keys.publicKeyPem, lastHead: null },
      sth0,
    );
    expect(r0.ok).toBe(true);
    if (!r0.ok) return;

    // The empty tree is a prefix of every tree; RFC 9162 has no proof for
    // first=0 — growth must be accepted directly, not bricked forever.
    await log.appendLeaf("first-entry");
    const sth1 = signTreeHead(await log.head(), signing);
    const r1 = witnessObserve(r0.state, sth1);
    expect(r1.ok).toBe(true);

    // And from there, normal proof-gated observation resumes.
    if (!r1.ok) return;
    await log.appendLeaf("second-entry");
    const sth2 = signTreeHead(await log.head(), signing);
    expect(witnessObserve(r1.state, sth2)).toMatchObject({
      ok: false,
      code: "CONSISTENCY_PROOF_MISSING",
    });
    const proof = await log.proveConsistency(1, 2);
    expect(witnessObserve(r1.state, sth2, proof).ok).toBe(true);
  });

  it("detectSplitView finds equivocation across witnesses", async () => {
    const a = new TransparencyLog(new MemoryTreeStore());
    const b = new TransparencyLog(new MemoryTreeStore());
    await a.appendLeaf("x");
    await b.appendLeaf("y");
    const ha = signTreeHead(await a.head(), signing);
    const hb = signTreeHead(await b.head(), signing);
    expect(detectSplitView([ha, ha], keys.publicKeyPem).consistent).toBe(true);
    const split = detectSplitView([ha, hb], keys.publicKeyPem);
    expect(split.consistent).toBe(false);
    expect(split.conflict).toHaveLength(2);
  });

  it("detectSplitView never treats an unverifiable head as evidence", async () => {
    const a = new TransparencyLog(new MemoryTreeStore());
    await a.appendLeaf("x");
    const genuine = signTreeHead(await a.head(), signing);
    // Forged head: same size, different root, garbage signature. Without
    // signature verification this would count as "proof" of equivocation.
    const forged = { ...genuine, rootHash: "11".repeat(32), signature: "AAAA" };
    const r = detectSplitView([genuine, forged], keys.publicKeyPem);
    expect(r.consistent).toBe(true);
    expect(r.unverified).toEqual([forged]);
    // A REAL equivocation (both properly signed) is still caught.
    const b = new TransparencyLog(new MemoryTreeStore());
    await b.appendLeaf("y");
    const rival = signTreeHead(await b.head(), signing);
    expect(detectSplitView([genuine, rival], keys.publicKeyPem).consistent).toBe(false);
  });
});
