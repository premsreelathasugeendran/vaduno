import { createHash } from "node:crypto";
import {
  MLDSA44_PUBLIC_KEY_BYTES,
  MLDSA44_SIGNATURE_BYTES,
  mlDsa44SpkiFromRawPublicKey,
  rawMlDsa44PublicKey,
  type MlDsa44Ops,
} from "../src/mandate/pq.js";

/**
 * A deterministic FAKE MlDsa44Ops: a keyed hash wearing ML-DSA-44's exact
 * sizes (1312-byte keys in real id-ml-dsa-44 SPKI PEMs, 2420-byte
 * signatures).
 *
 * WHY IT EXISTS: this machine's node:crypto has no native ML-DSA (the runtime
 * probe is negative on Node 20 / OpenSSL 3.0), yet the LOGIC around ML-DSA —
 * structural gates, (algorithm, kid) lookup, requireAlgs enforcement, hybrid
 * both-must-verify, downgrade behavior — must be exercised by tests that can
 * FAIL. The fake provides working sign/verify with public/private
 * correspondence; the real algorithm is exercised by the skipIf-gated native
 * suites on runtimes that have it (CI Node >= 24.7 on OpenSSL >= 3.5).
 *
 * It is a MAC, not a signature scheme — anyone holding a public key can forge
 * under it. Never anything but a test double.
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

const PRIV_HEADER = "-----BEGIN FAKE ML-DSA-44 PRIVATE KEY-----";

function seedFromPrivatePem(privateKeyPem: string): string {
  const m = /-----BEGIN FAKE ML-DSA-44 PRIVATE KEY-----\n(.+)\n-----END FAKE ML-DSA-44 PRIVATE KEY-----/.exec(
    privateKeyPem,
  );
  if (!m || m[1] === undefined) throw new Error("not a fake ML-DSA-44 private key");
  return m[1];
}

function rawPublicFromSeed(seed: string): Buffer {
  return expand("fake-mldsa-pub", [Buffer.from(seed, "utf8")], MLDSA44_PUBLIC_KEY_BYTES);
}

/** Deterministic key pair from a seed. The public half is a REAL-shaped SPKI
 * PEM, so key ids and raw-key extraction go through the production parsers. */
export function fakeMlDsa44KeyPair(seed: string): {
  privateKeyPem: string;
  publicKeyPem: string;
} {
  return {
    privateKeyPem: `${PRIV_HEADER}\n${seed}\n-----END FAKE ML-DSA-44 PRIVATE KEY-----\n`,
    publicKeyPem: mlDsa44SpkiFromRawPublicKey(rawPublicFromSeed(seed)),
  };
}

export function fakeMlDsa44Ops(): MlDsa44Ops {
  return {
    sign(message, privateKeyPem) {
      const raw = rawPublicFromSeed(seedFromPrivatePem(privateKeyPem));
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
