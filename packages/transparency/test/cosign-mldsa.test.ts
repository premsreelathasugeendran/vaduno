/**
 * C2SP tlog-cosignature ML-DSA-44 (key-id algorithm byte 0x06).
 *
 * THE POINT MOST WORTH PINNING: the 0x06 payload is a DIFFERENT BINARY
 * STRUCTURE, not an algorithm swap of the 0x04 text payload. Getting that
 * wrong would break interop with every real witness while all local tests
 * still passed — so the struct is asserted byte-by-byte, independently
 * reassembled here rather than read back from the builder.
 *
 * PQ NOTE: this machine has no native ML-DSA (Node 20 / OpenSSL 3.0). The
 * logic runs through the deterministic fake ops (fake-mldsa.ts); the
 * NATIVE-tagged suite at the bottom is skipIf-gated and runs only where
 * node:crypto has ML-DSA (CI Node >= 24.7 on OpenSSL >= 3.5).
 */
import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  PqUnavailableError,
  mlDsa44Available,
  generateMlDsa44KeyPair,
  nativeMlDsa44Ops,
  rawMlDsa44PublicKey,
} from "@vaduno/guard";
import {
  attachCosignatures,
  cosignCheckpoint,
  cosignCheckpointMlDsa44,
  generateLogKeyPair,
  keyId,
  mlDsa44CosignaturePayload,
  parseNote,
  rawEd25519PublicKey,
  signCheckpoint,
  verifyCosignatures,
  SIG_TYPE_COSIGNATURE_MLDSA44,
  SIG_TYPE_COSIGNATURE_V1,
  type KnownWitness,
} from "../src/index.js";
import { fakeMlDsa44KeyPair, fakeMlDsa44Ops } from "./fake-mldsa.js";

const ORIGIN = "vaduno.example/ledger";
const log = generateLogKeyPair();
const NOW = 1_780_000_000;
const nowSeconds = () => NOW;
const fake = fakeMlDsa44Ops();

const pqWitnessA = fakeMlDsa44KeyPair("witness-a");

function freshNote(treeSize = 3, rootHash = "e".repeat(64)) {
  return signCheckpoint(
    { origin: ORIGIN, treeSize, rootHash },
    { name: ORIGIN, privateKeyPem: log.privateKeyPem, publicKeyPem: log.publicKeyPem },
  );
}

describe("the 0x06 binary payload structure", () => {
  it("assembles label || name<1..255> || u64 ts || origin<1..255> || u64 start=0 || u64 end || raw root — byte for byte", () => {
    const rootHash = "ab".repeat(32);
    const payload = mlDsa44CosignaturePayload({
      cosignerName: "witness.example/a",
      timestamp: NOW,
      origin: ORIGIN,
      treeSize: 42,
      rootHash,
    });
    // Independent reassembly — NOT via the builder under test.
    const name = Buffer.from("witness.example/a", "utf8");
    const origin = Buffer.from(ORIGIN, "utf8");
    const u64 = (v: bigint) => {
      const b = Buffer.alloc(8);
      b.writeBigUInt64BE(v);
      return b;
    };
    const expected = Buffer.concat([
      Buffer.from([0x73, 0x75, 0x62, 0x74, 0x72, 0x65, 0x65, 0x2f, 0x76, 0x31, 0x0a, 0x00]), // "subtree/v1\n\0"
      Buffer.from([name.length]),
      name,
      u64(BigInt(NOW)),
      Buffer.from([origin.length]),
      origin,
      u64(0n), // start MUST be 0 for checkpoints
      u64(42n), // end = tree size
      Buffer.from(rootHash, "hex"), // RAW 32 bytes, not base64
    ]);
    expect(payload.equals(expected)).toBe(true);
  });

  it("is NOT the 0x04 text payload with a different algorithm — no 'cosignature/v1' framing, raw root, no body", () => {
    const payload = mlDsa44CosignaturePayload({
      cosignerName: "w",
      timestamp: NOW,
      origin: ORIGIN,
      treeSize: 3,
      rootHash: "e".repeat(64),
    });
    const text = payload.toString("latin1");
    expect(text).not.toContain("cosignature/v1");
    expect(text).not.toContain("time ");
    // The 0x04 payload embeds the base64 root (via the body); 0x06 must not.
    expect(text).not.toContain(Buffer.from("e".repeat(64), "hex").toString("base64"));
  });

  it("bounds the length-prefixed fields to 1..255 bytes and validates the rest", () => {
    const ok = { cosignerName: "w", timestamp: NOW, origin: ORIGIN, treeSize: 1, rootHash: "e".repeat(64) };
    expect(() => mlDsa44CosignaturePayload({ ...ok, cosignerName: "" })).toThrow(/1\.\.255/);
    expect(() => mlDsa44CosignaturePayload({ ...ok, cosignerName: "x".repeat(256) })).toThrow(/1\.\.255/);
    expect(() => mlDsa44CosignaturePayload({ ...ok, origin: "" })).toThrow(/1\.\.255/);
    expect(() => mlDsa44CosignaturePayload({ ...ok, origin: "x".repeat(256) })).toThrow(/1\.\.255/);
    expect(() => mlDsa44CosignaturePayload({ ...ok, treeSize: -1 })).toThrow(/tree size/);
    expect(() => mlDsa44CosignaturePayload({ ...ok, timestamp: -1 })).toThrow(/timestamp/);
    expect(() => mlDsa44CosignaturePayload({ ...ok, rootHash: "zz" })).toThrow(/64 lowercase hex/);
  });
});

describe("the committed 0x06 payload vector reproduces", () => {
  it("spec/vectors/cosign-mldsa44-payload.json is what the builder emits", () => {
    // The committed JSON is the frozen contract; regenerating it to make
    // this pass would be the bug. See docs/WIRE-FORMAT.md.
    const vectorsDir = join(
      dirname(fileURLToPath(import.meta.url)),
      "..", "..", "..",
      "spec", "vectors",
    );
    const v = JSON.parse(
      readFileSync(join(vectorsDir, "cosign-mldsa44-payload.json"), "utf8"),
    ) as {
      input: { cosignerName: string; timestamp: number; origin: string; treeSize: number; rootHashHex: string };
      payloadHex: string;
      payloadSha256: string;
    };
    const payload = mlDsa44CosignaturePayload({
      cosignerName: v.input.cosignerName,
      timestamp: v.input.timestamp,
      origin: v.input.origin,
      treeSize: v.input.treeSize,
      rootHash: v.input.rootHashHex,
    });
    expect(payload.toString("hex")).toBe(v.payloadHex);
    expect(createHash("sha256").update(payload).digest("hex")).toBe(v.payloadSha256);
  });
});

describe("0x06 key ids use the REAL raw key, never the last-32-bytes shortcut", () => {
  it("derives the key id from the parsed 1312-byte raw key", () => {
    const raw = rawMlDsa44PublicKey(pqWitnessA.publicKeyPem);
    expect(raw.length).toBe(1312);
    const expected = createHash("sha256")
      .update(Buffer.from("witness.example/a", "utf8"))
      .update(Buffer.from([0x0a]))
      .update(Buffer.from([SIG_TYPE_COSIGNATURE_MLDSA44]))
      .update(raw)
      .digest()
      .subarray(0, 4)
      .toString("hex");
    expect(keyId("witness.example/a", SIG_TYPE_COSIGNATURE_MLDSA44, raw)).toBe(expected);
    // The last-32-bytes shortcut would produce a DIFFERENT (garbage) id.
    const garbage = keyId(
      "witness.example/a",
      SIG_TYPE_COSIGNATURE_MLDSA44,
      raw.subarray(raw.length - 32),
    );
    expect(garbage).not.toBe(expected);
  });

  it("rawEd25519PublicKey REFUSES an ML-DSA SPKI instead of returning its last 32 bytes", () => {
    expect(() => rawEd25519PublicKey(pqWitnessA.publicKeyPem)).toThrow(/Ed25519|rawMlDsa44PublicKey/);
  });

  it("the same conceptual key under 0x04 vs 0x06 yields different ids (role separation)", () => {
    const raw32 = Buffer.alloc(32, 7);
    expect(keyId("w", SIG_TYPE_COSIGNATURE_V1, raw32)).not.toBe(
      keyId("w", SIG_TYPE_COSIGNATURE_MLDSA44, raw32),
    );
  });
});

describe("cosign and verify with 0x06 (fake ops)", () => {
  const witnessed = () => {
    const note = freshNote();
    const record = cosignCheckpointMlDsa44(note, {
      name: "witness.example/a",
      privateKeyPem: pqWitnessA.privateKeyPem,
      publicKeyPem: pqWitnessA.publicKeyPem,
      timestamp: NOW,
      pq: fake,
    });
    return { note, record, full: attachCosignatures(note, [record]) };
  };
  const knownPq: KnownWitness = {
    name: "witness.example/a",
    mlDsa44PublicKeyPem: pqWitnessA.publicKeyPem,
  };

  it("round-trips attach -> verify with alg ML-DSA-44, and the blob is keyID||u64 ts||2420-byte sig", () => {
    const { record, full } = witnessed();
    const parsed = parseNote(full);
    const line = parsed.signatures.find((s) => s.name === "witness.example/a")!;
    expect(line.signature).toHaveLength(8 + 2420);
    expect(Number(line.signature.readBigUInt64BE(0))).toBe(NOW);
    expect(record.timestamp).toBe(NOW);
    expect(
      verifyCosignatures(full, [knownPq], { nowSeconds, pq: fake }),
    ).toEqual([{ name: "witness.example/a", timestamp: NOW, alg: "ML-DSA-44" }]);
  });

  it("does NOT verify against a different checkpoint (root/size are inside the struct)", () => {
    const { record } = witnessed();
    const other = freshNote(4, "f".repeat(64));
    const moved = attachCosignatures(other, [record]);
    expect(verifyCosignatures(moved, [knownPq], { nowSeconds, pq: fake })).toEqual([]);
  });

  it("a garbage 0x06 line is IGNORED (per signed-note), never fatal to the rest of the note", () => {
    const { note } = witnessed();
    const ed = cosignCheckpoint(note, {
      name: "witness.example/b",
      privateKeyPem: log.privateKeyPem, // reuse a real ed key for a second witness
      publicKeyPem: log.publicKeyPem,
      timestamp: NOW,
    });
    const raw = rawMlDsa44PublicKey(pqWitnessA.publicKeyPem);
    const id = keyId("witness.example/a", SIG_TYPE_COSIGNATURE_MLDSA44, raw);
    const garbageBlob = Buffer.concat([
      Buffer.from(id, "hex"),
      Buffer.alloc(8 + 2420, 0x5a), // right length, wrong everything
    ]);
    const garbageLine = `— witness.example/a ${garbageBlob.toString("base64")}\n`;
    const full = attachCosignatures(note, [ed]) + garbageLine;
    const verified = verifyCosignatures(
      full,
      [knownPq, { name: "witness.example/b", publicKeyPem: log.publicKeyPem }],
      { nowSeconds, pq: fake },
    );
    // The Ed25519 cosignature survives; the garbage 0x06 simply is not there.
    expect(verified).toEqual([{ name: "witness.example/b", timestamp: NOW, alg: "Ed25519" }]);
  });

  it("ARCHIVAL semantics apply to 0x06 too: years-old verifies by default, future-dated never", () => {
    const note = freshNote();
    const old = cosignCheckpointMlDsa44(note, {
      name: "witness.example/a",
      privateKeyPem: pqWitnessA.privateKeyPem,
      publicKeyPem: pqWitnessA.publicKeyPem,
      timestamp: NOW - 5 * 365 * 24 * 60 * 60,
      pq: fake,
    });
    const future = cosignCheckpointMlDsa44(note, {
      name: "witness.example/a",
      privateKeyPem: pqWitnessA.privateKeyPem,
      publicKeyPem: pqWitnessA.publicKeyPem,
      timestamp: NOW + 10_000,
      pq: fake,
    });
    expect(
      verifyCosignatures(attachCosignatures(note, [old]), [knownPq], { nowSeconds, pq: fake })
        .map((v) => v.timestamp),
    ).toEqual([old.timestamp]);
    expect(
      verifyCosignatures(attachCosignatures(note, [future]), [knownPq], { nowSeconds, pq: fake }),
    ).toEqual([]);
  });

  it("SIGNING without the capability throws the typed PqUnavailableError — no silent classical fallback", () => {
    const note = freshNote();
    expect(() =>
      cosignCheckpointMlDsa44(note, {
        name: "witness.example/a",
        privateKeyPem: pqWitnessA.privateKeyPem,
        publicKeyPem: pqWitnessA.publicKeyPem,
        timestamp: NOW,
        pq: null,
      }),
    ).toThrow(PqUnavailableError);
  });

  it("VERIFYING without the capability IGNORES 0x06 lines — the note rests on its classical cosignatures", () => {
    const { note, record } = witnessed();
    const ed = cosignCheckpoint(note, {
      name: "witness.example/b",
      privateKeyPem: log.privateKeyPem,
      publicKeyPem: log.publicKeyPem,
      timestamp: NOW,
    });
    const full = attachCosignatures(note, [record, ed]);
    const verified = verifyCosignatures(
      full,
      [knownPq, { name: "witness.example/b", publicKeyPem: log.publicKeyPem }],
      { nowSeconds, pq: null },
    );
    expect(verified).toEqual([{ name: "witness.example/b", timestamp: NOW, alg: "Ed25519" }]);
  });

  it("a witness holding BOTH keys contributes one entry per algorithm", () => {
    const note = freshNote();
    const kp = generateLogKeyPair();
    const both: KnownWitness = {
      name: "witness.example/dual",
      publicKeyPem: kp.publicKeyPem,
      mlDsa44PublicKeyPem: pqWitnessA.publicKeyPem,
    };
    const ed = cosignCheckpoint(note, {
      name: "witness.example/dual",
      privateKeyPem: kp.privateKeyPem,
      publicKeyPem: kp.publicKeyPem,
      timestamp: NOW,
    });
    const ml = cosignCheckpointMlDsa44(note, {
      name: "witness.example/dual",
      privateKeyPem: pqWitnessA.privateKeyPem,
      publicKeyPem: pqWitnessA.publicKeyPem,
      timestamp: NOW + 1,
      pq: fake,
    });
    const verified = verifyCosignatures(
      attachCosignatures(note, [ed, ml]),
      [both],
      { nowSeconds: () => NOW + 10, pq: fake },
    );
    expect(verified.map((v) => v.alg).sort()).toEqual(["Ed25519", "ML-DSA-44"]);
  });
});

describe("NATIVE ML-DSA-44 (runs only where node:crypto has it — otherwise SKIPPED, and that skip is stated)", () => {
  it.skipIf(!mlDsa44Available())("cosigns and verifies a checkpoint with REAL ML-DSA-44 keys", () => {
    const keys = generateMlDsa44KeyPair();
    const ops = nativeMlDsa44Ops()!;
    const note = freshNote();
    const record = cosignCheckpointMlDsa44(note, {
      name: "witness.example/native",
      privateKeyPem: keys.privateKeyPem,
      publicKeyPem: keys.publicKeyPem,
      timestamp: NOW,
      pq: ops,
    });
    const verified = verifyCosignatures(
      attachCosignatures(note, [record]),
      [{ name: "witness.example/native", mlDsa44PublicKeyPem: keys.publicKeyPem }],
      { nowSeconds, pq: ops },
    );
    expect(verified).toEqual([
      { name: "witness.example/native", timestamp: NOW, alg: "ML-DSA-44" },
    ]);
  });
});
