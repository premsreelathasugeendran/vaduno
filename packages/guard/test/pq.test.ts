/**
 * The ML-DSA-44 runtime capability probe and the pure-parsing key utilities.
 *
 * MEASURED GROUND TRUTH this suite is written against: the dev machine runs
 * Node 20 on OpenSSL 3.0, where node:crypto REJECTS ml-dsa-44 — so the
 * native-path tests SKIP there (and say so), while the unavailable-path tests
 * skip on runtimes that DO have ML-DSA. Exactly one of the two conditional
 * groups runs everywhere; the pure-parsing tests run everywhere.
 */
import { describe, expect, it } from "vitest";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
  MLDSA44_PUBLIC_KEY_BYTES,
  MLDSA44_SIGNATURE_BYTES,
  PqUnavailableError,
  generateMlDsa44KeyPair,
  mlDsa44Available,
  mlDsa44KeyId,
  mlDsa44SpkiFromRawPublicKey,
  nativeMlDsa44Ops,
  rawMlDsa44PublicKey,
} from "../src/mandate/pq.js";
import { fakeMlDsa44KeyPair } from "./fake-mldsa.js";

const available = mlDsa44Available();

describe("runtime capability probe", () => {
  it("is a stable, cached answer", () => {
    expect(mlDsa44Available()).toBe(available);
    expect(mlDsa44Available()).toBe(available);
  });

  it("nativeMlDsa44Ops() agrees with the probe", () => {
    expect(nativeMlDsa44Ops() === null).toBe(!available);
  });

  it.skipIf(available)(
    "SKIPPED-ON-PQ-RUNTIMES: without native ML-DSA, key generation throws a typed PqUnavailableError naming the REAL requirement",
    () => {
      const err = (() => {
        try {
          generateMlDsa44KeyPair();
          return null;
        } catch (e) {
          return e;
        }
      })();
      expect(err).toBeInstanceOf(PqUnavailableError);
      const message = (err as Error).message;
      // Revision: "Node >= 24.7" alone is MISLEADING — ML-DSA needs the Node
      // binary built against OpenSSL >= 3.5; an older OpenSSL lacks it at any
      // Node version. The error must say so and point at the probe.
      expect(message).toMatch(/Node >= 24\.7/);
      expect(message).toMatch(/OpenSSL >= 3\.5/);
      expect(message).toMatch(/any Node version/i);
      expect(message).toMatch(/mlDsa44Available/);
    },
  );

  it.skipIf(!available)(
    "NATIVE: generates a key pair and signs/verifies round-trip (runs only where node:crypto has ML-DSA)",
    () => {
      const keys = generateMlDsa44KeyPair();
      const ops = nativeMlDsa44Ops();
      expect(ops).not.toBeNull();
      const msg = Buffer.from("archival evidence payload");
      const sig = ops!.sign(msg, keys.privateKeyPem);
      expect(sig.length).toBe(MLDSA44_SIGNATURE_BYTES);
      expect(ops!.verify(msg, keys.publicKeyPem, sig)).toBe(true);
      expect(ops!.verify(Buffer.from("tampered"), keys.publicKeyPem, sig)).toBe(false);
      // The raw extractor must agree with the native SPKI encoding.
      expect(rawMlDsa44PublicKey(keys.publicKeyPem).length).toBe(MLDSA44_PUBLIC_KEY_BYTES);
    },
  );
});

describe("rawMlDsa44PublicKey (pure DER parsing — runs everywhere)", () => {
  it("round-trips through mlDsa44SpkiFromRawPublicKey", () => {
    const raw = Buffer.alloc(MLDSA44_PUBLIC_KEY_BYTES, 0xa7);
    const pem = mlDsa44SpkiFromRawPublicKey(raw);
    expect(rawMlDsa44PublicKey(pem).equals(raw)).toBe(true);
  });

  it("REJECTS an Ed25519 SPKI instead of returning garbage bytes", () => {
    // rawEd25519PublicKey takes the last 32 bytes of any DER; the ML-DSA
    // extractor must never mirror that shortcut — a wrong-family key must be
    // refused, not silently turned into a wrong-but-plausible key id.
    const { publicKey } = generateKeyPairSync("ed25519");
    const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(() => rawMlDsa44PublicKey(pem)).toThrow(/OID|SEQUENCE|BIT STRING/);
  });

  it("rejects a truncated key, a non-PEM string, and a wrong-length raw input", () => {
    const raw = Buffer.alloc(MLDSA44_PUBLIC_KEY_BYTES, 1);
    const pem = mlDsa44SpkiFromRawPublicKey(raw);
    const body = pem.split("\n").slice(1, -2).join("");
    const truncated =
      "-----BEGIN PUBLIC KEY-----\n" + body.slice(0, 200) + "\n-----END PUBLIC KEY-----\n";
    expect(() => rawMlDsa44PublicKey(truncated)).toThrow();
    expect(() => rawMlDsa44PublicKey("not a pem")).toThrow(/PEM/);
    expect(() => mlDsa44SpkiFromRawPublicKey(Buffer.alloc(32))).toThrow(/1312/);
  });
});

describe("mlDsa44KeyId", () => {
  it("derives the documented truncated hash over the SPKI DER", () => {
    const raw = Buffer.alloc(MLDSA44_PUBLIC_KEY_BYTES, 0x42);
    const pem = mlDsa44SpkiFromRawPublicKey(raw);
    const der = Buffer.from(
      pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "").replace(/\s+/g, ""),
      "base64",
    );
    const expected = createHash("sha256")
      .update("vaduno-mandate-key/v1\n", "utf8")
      .update(der)
      .digest("hex")
      .slice(0, 16);
    expect(mlDsa44KeyId(pem)).toBe(expected);
    expect(mlDsa44KeyId(pem)).toMatch(/^[0-9a-f]{16}$/);
  });

  it("refuses to mint an id for bytes that are not an ML-DSA-44 SPKI", () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(() => mlDsa44KeyId(pem)).toThrow();
  });

  it("gives the fake test keys real-shaped, distinct ids", () => {
    const a = fakeMlDsa44KeyPair("seed-a");
    const b = fakeMlDsa44KeyPair("seed-b");
    expect(mlDsa44KeyId(a.publicKeyPem)).toMatch(/^[0-9a-f]{16}$/);
    expect(mlDsa44KeyId(a.publicKeyPem)).not.toBe(mlDsa44KeyId(b.publicKeyPem));
  });
});
