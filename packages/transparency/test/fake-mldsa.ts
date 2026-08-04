import { createHash } from "node:crypto";
import {
  MLDSA44_PUBLIC_KEY_BYTES,
  MLDSA44_SIGNATURE_BYTES,
  mlDsa44SpkiFromRawPublicKey,
  rawMlDsa44PublicKey,
  type MlDsa44Ops,
} from "@vaduno/guard";

/**
 * Deterministic FAKE MlDsa44Ops with ML-DSA-44's exact sizes — same double
 * as packages/guard/test/fake-mldsa.ts, duplicated here so transparency's
 * tests stay decoupled from guard's test tree (they may only import guard's
 * BUILT dist).
 *
 * This machine's node:crypto has no native ML-DSA (Node 20 / OpenSSL 3.0):
 * the fake lets the 0x06 cosignature LOGIC — payload structure, key-id
 * derivation, quorum counting, anchor labels, downgrade behavior — run and
 * FAIL honestly everywhere, while the native algorithm is exercised by the
 * skipIf-gated suite on runtimes that have it. It is a MAC, not a signature
 * scheme; never anything but a test double.
 */

function expand(tag: string, parts: Buffer[], length: number): Buffer {
  const out: Buffer[] = [];
  let produced = 0;
  for (let i = 0; produced < length; i++) {
    const h = createHash("sha256").update(tag, "utf8").update(Buffer.from([i]));
    for (const p of parts) h.update(p);
    const block = h.digest();
    out.push(block);
    produced += block.length;
  }
  return Buffer.concat(out).subarray(0, length);
}

const PRIV = /-----BEGIN FAKE ML-DSA-44 PRIVATE KEY-----\n(.+)\n-----END FAKE ML-DSA-44 PRIVATE KEY-----/;

function rawPublicFromSeed(seed: string): Buffer {
  return expand("fake-mldsa-pub", [Buffer.from(seed, "utf8")], MLDSA44_PUBLIC_KEY_BYTES);
}

export function fakeMlDsa44KeyPair(seed: string): {
  privateKeyPem: string;
  publicKeyPem: string;
} {
  return {
    privateKeyPem: `-----BEGIN FAKE ML-DSA-44 PRIVATE KEY-----\n${seed}\n-----END FAKE ML-DSA-44 PRIVATE KEY-----\n`,
    publicKeyPem: mlDsa44SpkiFromRawPublicKey(rawPublicFromSeed(seed)),
  };
}

export function fakeMlDsa44Ops(): MlDsa44Ops {
  return {
    sign(message, privateKeyPem) {
      const m = PRIV.exec(privateKeyPem);
      if (!m || m[1] === undefined) throw new Error("not a fake ML-DSA-44 private key");
      const raw = rawPublicFromSeed(m[1]);
      return expand("fake-mldsa-sig", [raw, Buffer.from(message)], MLDSA44_SIGNATURE_BYTES);
    },
    verify(message, publicKeyPem, signature) {
      let raw: Buffer;
      try {
        raw = rawMlDsa44PublicKey(publicKeyPem);
      } catch {
        return false;
      }
      const expected = expand(
        "fake-mldsa-sig",
        [raw, Buffer.from(message)],
        MLDSA44_SIGNATURE_BYTES,
      );
      return expected.equals(Buffer.from(signature));
    },
  };
}
