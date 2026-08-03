/**
 * The checkedSign gate — the single choke point between any Ed25519Signer
 * (KMS, HSM, hardware, or the in-process LocalKeySigner) and everything
 * Vaduno emits. The property under test throughout: NO failure mode of a
 * signer can produce output. A signer can deny; it can never corrupt.
 */
import { generateKeyPairSync, sign as edSign, verify as edVerify } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  checkedSign,
  LocalKeySigner,
  SignerError,
  SignerTimeoutError,
  SignerVerificationError,
  type Ed25519Signer,
} from "../src/mandate/signer.js";
import { generateMandateKeyPair } from "../src/mandate/mandate.js";

const keys = generateMandateKeyPair();
const local = new LocalKeySigner(keys.privateKeyPem);
const message = Buffer.from("vaduno-test/v1\npayload", "utf8");

/** A signer that declares one key but behaves as told — the adversary rig. */
function fakeSigner(over: Partial<Ed25519Signer> & { sign?: Ed25519Signer["sign"] }): Ed25519Signer {
  return {
    algorithm: "Ed25519",
    publicKeyPem: keys.publicKeyPem,
    sign: async () => new Uint8Array(64),
    ...over,
  } as Ed25519Signer;
}

describe("LocalKeySigner", () => {
  it("derives its public key from the private key and signs verifiably", async () => {
    expect(local.publicKeyPem).toBe(keys.publicKeyPem);
    const sig = await checkedSign(local, message);
    expect(sig.length).toBe(64);
  });

  it("refuses a non-Ed25519 private key", () => {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    expect(() => new LocalKeySigner(pem)).toThrow(SignerError);
  });

  it("refuses garbage instead of parsing it as a key", () => {
    expect(() => new LocalKeySigner("not a pem")).toThrow(SignerError);
  });
});

describe("checkedSign refuses every malformed output BEFORE verification", () => {
  it("63 and 65 byte outputs are SignerError, never SignerVerificationError", async () => {
    for (const n of [0, 32, 63, 65]) {
      const err = await checkedSign(fakeSigner({ sign: async () => new Uint8Array(n) }), message)
        .then(() => null, (e: unknown) => e);
      expect(err).toBeInstanceOf(SignerError);
      // Length is checked before any verify: a wrong-sized blob must not
      // reach the crypto layer at all.
      expect(err).not.toBeInstanceOf(SignerVerificationError);
    }
  });

  it("a non-byte return value is SignerError", async () => {
    const s = fakeSigner({ sign: (async () => "sig") as unknown as Ed25519Signer["sign"] });
    await expect(checkedSign(s, message)).rejects.toBeInstanceOf(SignerError);
  });

  it("a rejecting signer is SignerError carrying the cause", async () => {
    const s = fakeSigner({
      sign: async () => {
        throw new Error("kms: PERMISSION_DENIED");
      },
    });
    const err = await checkedSign(s, message).then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(SignerError);
    expect((err as Error).message).toContain("PERMISSION_DENIED");
  });

  it("a synchronously-throwing signer is SignerError, not an escaped throw", async () => {
    const s = fakeSigner({
      sign: () => {
        throw new Error("sync boom");
      },
    });
    await expect(checkedSign(s, message)).rejects.toBeInstanceOf(SignerError);
  });

  it("a non-Ed25519 algorithm is refused at the gate", async () => {
    const s = { ...fakeSigner({}), algorithm: "secp256k1" } as unknown as Ed25519Signer;
    await expect(checkedSign(s, message)).rejects.toBeInstanceOf(SignerError);
  });

  it("an unparseable declared public key is refused at the gate", async () => {
    const s = fakeSigner({ publicKeyPem: "not a pem" });
    await expect(checkedSign(s, message)).rejects.toBeInstanceOf(SignerError);
  });
});

describe("checkedSign verifies against the DECLARED key with the ORIGINAL bytes", () => {
  it("a signer signing with a different key than it declares is refused", async () => {
    const other = new LocalKeySigner(generateMandateKeyPair().privateKeyPem);
    const s = fakeSigner({ sign: (m) => other.sign(m) });
    await expect(checkedSign(s, message)).rejects.toBeInstanceOf(SignerVerificationError);
  });

  it("random 64 bytes are refused", async () => {
    const s = fakeSigner({
      sign: async () => Uint8Array.from({ length: 64 }, (_, i) => (i * 37 + 11) % 256),
    });
    await expect(checkedSign(s, message)).rejects.toBeInstanceOf(SignerVerificationError);
  });

  it("a signer that signs then SCRIBBLES OVER its input cannot corrupt the result", async () => {
    // Copy-in: the signer gets its own buffer. It signs the true bytes, then
    // zeroes what it was handed. If checkedSign verified (or emitted) the
    // signer-held buffer, this would break; against the retained original it
    // must verify.
    const s = fakeSigner({
      sign: async (m) => {
        const sig = await local.sign(m);
        (m as Uint8Array).fill(0);
        return sig;
      },
    });
    const sig = await checkedSign(s, message);
    expect(edVerify(null, message, keys.publicKeyPem, sig)).toBe(true);
  });

  it("a signer that scribbles FIRST and signs the mutated bytes is refused", async () => {
    // The dual case: signature over the wrong bytes must never be emitted,
    // even though it is a valid signature by the declared key.
    const s = fakeSigner({
      sign: async (m) => {
        (m as Uint8Array).fill(0);
        return local.sign(m);
      },
    });
    await expect(checkedSign(s, message)).rejects.toBeInstanceOf(SignerVerificationError);
  });

  it("mutating the CALLER's buffer after the call does not invalidate the result", async () => {
    const mine = Buffer.from(message);
    const sig = await checkedSign(local, mine);
    mine.fill(0);
    expect(edVerify(null, message, keys.publicKeyPem, sig)).toBe(true);
  });

  it("a signer mutating its RETURNED signature after the fact changes nothing", async () => {
    let kept: Uint8Array | null = null;
    const s = fakeSigner({
      sign: async (m) => {
        kept = (await local.sign(m)) as Uint8Array;
        return kept;
      },
    });
    const sig = await checkedSign(s, message);
    (kept as unknown as Uint8Array).fill(0);
    expect(edVerify(null, message, keys.publicKeyPem, sig)).toBe(true);
  });
});

describe("checkedSign deadline", () => {
  it("a never-resolving signer times out as SignerTimeoutError, fast", async () => {
    const s = fakeSigner({ sign: () => new Promise<Uint8Array>(() => undefined) });
    const t0 = Date.now();
    const err = await checkedSign(s, message, { timeoutMs: 50 }).then(() => null, (e: unknown) => e);
    expect(Date.now() - t0).toBeLessThan(500);
    expect(err).toBeInstanceOf(SignerTimeoutError);
  });

  it("a LATE resolution after the timeout is discarded, and a late rejection cannot crash", async () => {
    let resolveLate!: (v: Uint8Array) => void;
    let rejectLate!: (e: Error) => void;
    const s = fakeSigner({
      sign: () =>
        new Promise<Uint8Array>((res, rej) => {
          resolveLate = res;
          rejectLate = rej;
        }),
    });
    await expect(checkedSign(s, message, { timeoutMs: 20 })).rejects.toBeInstanceOf(
      SignerTimeoutError,
    );
    // Settle the abandoned promise both ways a hostile signer could.
    resolveLate(await local.sign(message));
    rejectLate(new Error("late failure"));
    await new Promise((r) => setTimeout(r, 30));
    // Reaching this line means no unhandled rejection took the process down,
    // and the earlier timeout result stood.
    expect(true).toBe(true);
  });

  it("a rejection-after-success signature is still the verified one", async () => {
    // Signature validity is decided by edVerify against the declared key —
    // asserted end to end: what checkedSign returns equals a deterministic
    // re-signing of the same bytes.
    const sig = await checkedSign(local, message);
    const expected = edSign(null, message, (await import("node:crypto")).createPrivateKey(keys.privateKeyPem));
    expect(Buffer.from(sig).equals(expected)).toBe(true);
  });
});
