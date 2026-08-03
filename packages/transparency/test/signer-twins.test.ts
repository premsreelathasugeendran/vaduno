/**
 * The async `*With` twins must be BYTE-EQUAL to their sync counterparts for
 * the same key and clock — the signer abstraction may not move the wire
 * format by a single bit. And a failing signer must deny NEW heads only:
 * the tree keeps its truthful leaves and the next healthy sync signs them.
 */
import { describe, expect, it } from "vitest";
import {
  AuditLedger,
  LocalKeySigner,
  MemoryLedgerStore,
  SignerError,
  type Ed25519Signer,
} from "@vaduno/guard";
import {
  generateLogKeyPair,
  signTreeHead,
  signTreeHeadWith,
  verifyTreeHead,
} from "../src/sth.js";
import {
  parseNote,
  signCheckpoint,
  signCheckpointWith,
  verifyNoteSignature,
  type Checkpoint,
} from "../src/checkpoint.js";
import { cosignCheckpoint, cosignCheckpointWith, verifyCosignatures } from "../src/cosign.js";
import { MemoryTreeStore, TransparencyLog } from "../src/tree.js";
import { LedgerMirror } from "../src/mirror.js";

const keys = generateLogKeyPair();
const signer = new LocalKeySigner(keys.privateKeyPem);
const fixedNow = () => new Date("2026-08-03T00:00:00.000Z");

async function makeHead() {
  const tree = new TransparencyLog(new MemoryTreeStore());
  await tree.appendLeaves(["leaf-a", "leaf-b", "leaf-c"]);
  return tree.head();
}

describe("byte-equality of the four twins", () => {
  it("signTreeHeadWith === signTreeHead", async () => {
    const head = await makeHead();
    const sync = signTreeHead(head, { logId: "log-1", privateKeyPem: keys.privateKeyPem, now: fixedNow });
    const viaSigner = await signTreeHeadWith(head, { logId: "log-1", signer, now: fixedNow });
    expect(viaSigner).toEqual(sync);
    expect(verifyTreeHead(viaSigner, keys.publicKeyPem)).toBe(true);
  });

  it("signCheckpointWith === signCheckpoint, and the note round-trips", async () => {
    const head = await makeHead();
    const cp: Checkpoint = {
      origin: "vaduno.example/ledger",
      treeSize: head.treeSize,
      rootHash: head.rootHash,
    };
    const sync = signCheckpoint(cp, {
      name: "vaduno.example/ledger",
      privateKeyPem: keys.privateKeyPem,
      publicKeyPem: keys.publicKeyPem,
    });
    const viaSigner = await signCheckpointWith(cp, { name: "vaduno.example/ledger", signer });
    expect(viaSigner).toBe(sync);

    // The produced note is a real C2SP note: log signature verifies and the
    // parse round-trips the checkpoint.
    expect(
      verifyNoteSignature(viaSigner, {
        name: "vaduno.example/ledger",
        publicKeyPem: keys.publicKeyPem,
      }),
    ).toBe(true);
    const parsed = parseNote(viaSigner);
    expect(parsed.checkpoint).toEqual(cp);
    expect(parsed.malformedSignatures).toBe(0);
  });

  it("cosignCheckpointWith === cosignCheckpoint for a fixed timestamp", async () => {
    const head = await makeHead();
    const note = signCheckpoint(
      { origin: "vaduno.example/ledger", treeSize: head.treeSize, rootHash: head.rootHash },
      { name: "vaduno.example/ledger", privateKeyPem: keys.privateKeyPem, publicKeyPem: keys.publicKeyPem },
    );
    const witnessKeys = generateLogKeyPair();
    const witnessSigner = new LocalKeySigner(witnessKeys.privateKeyPem);
    const ts = 1_754_179_200;

    const sync = cosignCheckpoint(note, {
      name: "witness-1",
      privateKeyPem: witnessKeys.privateKeyPem,
      publicKeyPem: witnessKeys.publicKeyPem,
      timestamp: ts,
    });
    const viaSigner = await cosignCheckpointWith(note, {
      name: "witness-1",
      signer: witnessSigner,
      timestamp: ts,
    });
    expect(viaSigner).toEqual(sync);

    const verified = verifyCosignatures(
      note + viaSigner.line,
      [{ name: "witness-1", publicKeyPem: witnessKeys.publicKeyPem }],
      { nowSeconds: () => ts + 60 },
    );
    expect(verified).toEqual([{ name: "witness-1", timestamp: ts }]);
  });
});

describe("mirror behind a signer", () => {
  function mirrorRig(signingSigner: Ed25519Signer) {
    const ledger = new AuditLedger(new MemoryLedgerStore());
    const tree = new TransparencyLog(new MemoryTreeStore());
    const mirror = new LedgerMirror(ledger, tree, {
      signing: { logId: "log-1", signer: signingSigner },
    });
    return { ledger, tree, mirror };
  }

  it("mirror signing config refuses both privateKeyPem and signer, and neither", () => {
    const ledger = new AuditLedger(new MemoryLedgerStore());
    const tree = new TransparencyLog(new MemoryTreeStore());
    expect(
      () =>
        new LedgerMirror(ledger, tree, {
          signing: { logId: "log-1", privateKeyPem: keys.privateKeyPem, signer },
        }),
    ).toThrow(SignerError);
    expect(() => new LedgerMirror(ledger, tree, { signing: { logId: "log-1" } })).toThrow(
      SignerError,
    );
  });

  it("mirror signing config refuses an unparseable DECLARED public key at construction, not first sync", () => {
    // "Throws at construction, before any authority exists" — the mirror
    // must not accept a signer it could never verify and only find out when
    // the first signed head is due.
    const ledger = new AuditLedger(new MemoryLedgerStore());
    const tree = new TransparencyLog(new MemoryTreeStore());
    const bad = {
      algorithm: "Ed25519",
      publicKeyPem: "not a pem",
      sign: async () => new Uint8Array(64),
    } as Ed25519Signer;
    expect(
      () => new LedgerMirror(ledger, tree, { signing: { logId: "log-1", signer: bad } }),
    ).toThrow(SignerError);
  });

  it("a signer that ROTATES its declared key after construction fails sync — the frozen key wins", async () => {
    // The mirror snapshots the declared key at construction; a backend that
    // rotates mid-life must produce a deny, not signed heads the deployment
    // can no longer verify.
    const rotatedKeys = generateLogKeyPair();
    const rotatedSigner = new LocalKeySigner(rotatedKeys.privateKeyPem);
    let pem = keys.publicKeyPem;
    let backend: Ed25519Signer = signer;
    const rotating: Ed25519Signer = {
      algorithm: "Ed25519",
      get publicKeyPem() {
        return pem;
      },
      sign: (m) => backend.sign(m),
    };
    const { ledger, tree, mirror } = mirrorRig(rotating);
    await ledger.append("policy_updated", { note: "a" });
    const first = await mirror.sync();
    expect(verifyTreeHead(first.signedHead!, keys.publicKeyPem)).toBe(true);

    pem = rotatedKeys.publicKeyPem;
    backend = rotatedSigner;
    await ledger.append("policy_updated", { note: "b" });
    await expect(mirror.sync()).rejects.toThrow(/declared public key/);
    // The leaves stayed (they mirror real entries); restoring the constructed
    // key signs the same root on the next sync.
    expect(await tree.size()).toBe(2);
    pem = keys.publicKeyPem;
    backend = signer;
    const healed = await mirror.sync();
    expect(healed.head.treeSize).toBe(2);
    expect(verifyTreeHead(healed.signedHead!, keys.publicKeyPem)).toBe(true);
  });

  it("signer-backed sync equals pem-backed sync on the wire", async () => {
    const ledger = new AuditLedger(new MemoryLedgerStore());
    await ledger.append("policy_updated", { note: "x" });
    const treeA = new TransparencyLog(new MemoryTreeStore());
    const treeB = new TransparencyLog(new MemoryTreeStore());
    const viaPem = new LedgerMirror(ledger, treeA, {
      signing: { logId: "log-1", privateKeyPem: keys.privateKeyPem, now: fixedNow },
    });
    const viaSigner = new LedgerMirror(ledger, treeB, {
      signing: { logId: "log-1", signer, now: fixedNow },
    });
    const [a, b] = await Promise.all([viaPem.sync(), viaSigner.sync()]);
    expect(b.signedHead).toEqual(a.signedHead);
  });

  it("a failing signer rejects sync, leaves REMAIN, and the next healthy sync signs the same root", async () => {
    let healthy = false;
    const flaky: Ed25519Signer = {
      algorithm: "Ed25519",
      publicKeyPem: signer.publicKeyPem,
      sign: (m) => {
        if (!healthy) return Promise.reject(new Error("kms unavailable"));
        return signer.sign(m);
      },
    };
    const { ledger, tree, mirror } = mirrorRig(flaky);
    await ledger.append("policy_updated", { note: "a" });
    await ledger.append("policy_updated", { note: "b" });

    await expect(mirror.sync()).rejects.toBeInstanceOf(SignerError);
    // The leaves mirror REAL ledger entries — the tree stays truthful, so a
    // signing outage must not unwind them.
    expect(await tree.size()).toBe(2);

    healthy = true;
    const result = await mirror.sync();
    expect(result.appended).toBe(0);
    expect(result.head.treeSize).toBe(2);
    expect(result.signedHead).toBeDefined();
    expect(result.signedHead!.rootHash).toBe(result.head.rootHash);
    expect(verifyTreeHead(result.signedHead!, keys.publicKeyPem)).toBe(true);
  });
});
