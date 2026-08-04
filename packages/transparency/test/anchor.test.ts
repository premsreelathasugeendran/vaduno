/**
 * assessCheckpointAnchor: anchor strength labels and witnessedAt.
 *
 * The two attacks this suite pins:
 *  1. LABEL UPGRADE: unverifiable or garbage 0x06 lines must never produce
 *     "witnessed-pq" — the label counts only what VERIFIED.
 *  2. witnessedAt POISONING: witnessedAt for a witnessed-pq checkpoint is
 *     computed from 0x06 cosignatures ONLY. A post-CRQC attacker who can
 *     forge Ed25519 could otherwise append a validly-signed 0x04 line with a
 *     BACKDATED timestamp and move the claimed witness time arbitrarily
 *     early. (Simulated here by signing with a REAL Ed25519 witness key —
 *     which is exactly what a CRQC yields the attacker.)
 *
 * PQ NOTE: no native ML-DSA on this machine; the deterministic fake ops
 * carry the logic (see fake-mldsa.ts). Every test here can fail.
 */
import { describe, expect, it } from "vitest";
import {
  assessCheckpointAnchor,
  attachCosignatures,
  cosignCheckpoint,
  cosignCheckpointMlDsa44,
  generateLogKeyPair,
  signCheckpoint,
  type KnownWitness,
} from "../src/index.js";
import { fakeMlDsa44KeyPair, fakeMlDsa44Ops } from "./fake-mldsa.js";

const ORIGIN = "vaduno.example/ledger";
const log = generateLogKeyPair();
const NOW = 1_780_000_000;
const nowSeconds = () => NOW;
const fake = fakeMlDsa44Ops();
const BINDING = { origin: ORIGIN, logPublicKeyPem: log.publicKeyPem };

const edA = generateLogKeyPair();
const edB = generateLogKeyPair();
const pqA = fakeMlDsa44KeyPair("anchor-witness-a");
const pqB = fakeMlDsa44KeyPair("anchor-witness-b");

/** Two witnesses, each holding BOTH an Ed25519 and an ML-DSA-44 key. */
const witnesses: KnownWitness[] = [
  { name: "w/a", publicKeyPem: edA.publicKeyPem, mlDsa44PublicKeyPem: pqA.publicKeyPem },
  { name: "w/b", publicKeyPem: edB.publicKeyPem, mlDsa44PublicKeyPem: pqB.publicKeyPem },
];

function note(treeSize = 3, rootHash = "e".repeat(64)) {
  return signCheckpoint(
    { origin: ORIGIN, treeSize, rootHash },
    { name: ORIGIN, privateKeyPem: log.privateKeyPem, publicKeyPem: log.publicKeyPem },
  );
}

function edCosign(n: string, name: string, kp: typeof edA, timestamp: number) {
  return cosignCheckpoint(n, {
    name,
    privateKeyPem: kp.privateKeyPem,
    publicKeyPem: kp.publicKeyPem,
    timestamp,
  });
}

function pqCosign(n: string, name: string, kp: typeof pqA, timestamp: number) {
  return cosignCheckpointMlDsa44(n, {
    name,
    privateKeyPem: kp.privateKeyPem,
    publicKeyPem: kp.publicKeyPem,
    timestamp,
    pq: fake,
  });
}

describe("anchor strength", () => {
  it("witnessed-pq when a k-party 0x06 quorum verifies; witnessedAt is the earliest 0x06 time", () => {
    const n = note();
    const full = attachCosignatures(n, [
      pqCosign(n, "w/a", pqA, NOW - 500),
      pqCosign(n, "w/b", pqB, NOW - 100),
    ]);
    const a = assessCheckpointAnchor(full, witnesses, 2, BINDING, { nowSeconds, pq: fake });
    expect(a.strength).toBe("witnessed-pq");
    expect(a.pq.ok).toBe(true);
    expect(a.witnessedAt).toBe(NOW - 500);
  });

  it("witnessed (not -pq) when only Ed25519 cosignatures reach quorum", () => {
    const n = note();
    const full = attachCosignatures(n, [
      edCosign(n, "w/a", edA, NOW - 50),
      edCosign(n, "w/b", edB, NOW - 20),
    ]);
    const a = assessCheckpointAnchor(full, witnesses, 2, BINDING, { nowSeconds, pq: fake });
    expect(a.strength).toBe("witnessed");
    expect(a.pq.ok).toBe(false);
    expect(a.witnessedAt).toBe(NOW - 50);
  });

  it("unwitnessed when no quorum at all; witnessedAt is null", () => {
    const n = note();
    const full = attachCosignatures(n, [edCosign(n, "w/a", edA, NOW)]);
    const a = assessCheckpointAnchor(full, witnesses, 2, BINDING, { nowSeconds, pq: fake });
    expect(a.strength).toBe("unwitnessed");
    expect(a.witnessedAt).toBeNull();
  });

  it("ATTACK — label upgrade: garbage 0x06 lines with the right key ids and lengths do NOT reach witnessed-pq", () => {
    const n = note();
    // Ed25519 quorum is genuine; the 0x06 lines are forged garbage.
    const parsedFor = (name: string, kp: typeof pqA) => {
      // Right key id, right blob length, garbage signature bytes.
      const rec = pqCosign(n, name, kp, NOW);
      const b64 = rec.line.trim().split(" ").pop()!;
      const blob = Buffer.from(b64, "base64");
      blob.fill(0x77, 12); // clobber the signature, keep keyID+timestamp
      return `— ${name} ${blob.toString("base64")}\n`;
    };
    const full =
      attachCosignatures(n, [edCosign(n, "w/a", edA, NOW), edCosign(n, "w/b", edB, NOW)]) +
      parsedFor("w/a", pqA) +
      parsedFor("w/b", pqB);
    const a = assessCheckpointAnchor(full, witnesses, 2, BINDING, { nowSeconds, pq: fake });
    expect(a.strength).toBe("witnessed"); // NOT witnessed-pq
    expect(a.pq.ok).toBe(false);
  });

  it("ATTACK — witnessedAt poisoning: a backdated, validly-signed 0x04 line cannot move a witnessed-pq checkpoint's witnessedAt", () => {
    const n = note();
    const full = attachCosignatures(n, [
      pqCosign(n, "w/a", pqA, NOW - 1000),
      pqCosign(n, "w/b", pqB, NOW - 900),
      // The attacker (post-CRQC, holding w/a's RECOVERED Ed25519 key) appends
      // a 0x04 cosignature backdated ten years. It VERIFIES — that is the
      // attack. It must not count toward the PQ-grade witness time.
      edCosign(n, "w/a", edA, NOW - 10 * 365 * 24 * 60 * 60),
    ]);
    const a = assessCheckpointAnchor(full, witnesses, 2, BINDING, { nowSeconds, pq: fake });
    expect(a.strength).toBe("witnessed-pq");
    // Earliest 0x06 time — NOT the forged classical one.
    expect(a.witnessedAt).toBe(NOW - 1000);
    // The classical quorum still sees the backdated line (it is genuine as
    // far as Ed25519 can say); the STRENGTH SCOPING is the defense.
    expect(a.classical.verified.some((v) => v.alg === "Ed25519")).toBe(true);
  });

  it("DOWNGRADE HONESTY: a verifier that cannot verify ML-DSA reports witnessed, never witnessed-pq — and its witnessedAt is classical-grade", () => {
    const n = note();
    const full = attachCosignatures(n, [
      pqCosign(n, "w/a", pqA, NOW - 1000),
      pqCosign(n, "w/b", pqB, NOW - 900),
      edCosign(n, "w/a", edA, NOW - 10),
      edCosign(n, "w/b", edB, NOW - 10),
    ]);
    const a = assessCheckpointAnchor(full, witnesses, 2, BINDING, { nowSeconds, pq: null });
    // The 0x06 lines are unverifiable HERE, so the claim honestly degrades.
    expect(a.strength).toBe("witnessed");
    expect(a.witnessedAt).toBe(NOW - 10);
    expect(a.pq.ok).toBe(false);
  });

  it("a dual-key witness cosigning with both algorithms is still ONE party toward each quorum", () => {
    const n = note();
    const full = attachCosignatures(n, [
      pqCosign(n, "w/a", pqA, NOW),
      edCosign(n, "w/a", edA, NOW),
    ]);
    // k=2 must NOT be satisfiable by one witness wearing two key types.
    const a = assessCheckpointAnchor(full, witnesses, 2, BINDING, { nowSeconds, pq: fake });
    expect(a.classical.ok).toBe(false);
    expect(a.pq.ok).toBe(false);
    expect(a.strength).toBe("unwitnessed");
  });

  it("the log binding still gates everything (wrong origin never anchors)", () => {
    const other = signCheckpoint(
      { origin: "someone.else/log", treeSize: 3, rootHash: "e".repeat(64) },
      { name: "someone.else/log", privateKeyPem: log.privateKeyPem, publicKeyPem: log.publicKeyPem },
    );
    const full = attachCosignatures(other, [
      pqCosign(other, "w/a", pqA, NOW),
      pqCosign(other, "w/b", pqB, NOW),
    ]);
    const a = assessCheckpointAnchor(full, witnesses, 2, BINDING, { nowSeconds, pq: fake });
    expect(a.strength).toBe("unwitnessed");
  });
});
