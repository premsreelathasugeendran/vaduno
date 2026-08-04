import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";

/**
 * ML-DSA-44 (FIPS 204) support, behind a RUNTIME capability probe.
 *
 * WHY THIS EXISTS: audit evidence is long-lived. A dispute bundle or
 * transparency proof verified years from now must resist a THEN-current
 * adversary forging "2026" signatures — the archival variant of
 * harvest-now-decrypt-later. NIST IR 8547 deprecates ECC/RSA signatures for
 * new use in 2030 and disallows them in 2035; any Ed25519 signature emitted
 * today is inside that window if it is verified after 2030. The hash chain
 * and the RFC 9162 Merkle tree are SHA-256 and already adequate against a
 * quantum adversary (Grover halves the bits; 128-bit preimage resistance
 * remains) — the SIGNATURES are the exposed surface, and this module is the
 * second algorithm slot for them.
 *
 * WHY A RUNTIME PROBE AND NOT A VERSION CHECK: ML-DSA in node:crypto requires
 * Node >= 24.7 **built against OpenSSL >= 3.5**. A Node binary linked to an
 * older system OpenSSL lacks ML-DSA at ANY Node version, so a version-string
 * check is wrong in both directions. `mlDsa44Available()` asks the crypto
 * layer directly, once, and caches the answer; it is the only authority.
 *
 * HONEST CLAIM DISCIPLINE: nothing here makes anything "quantum-safe".
 * A hybrid artifact adds an ML-DSA-44 signature ALONGSIDE Ed25519 where the
 * runtime supports it; the classical signatures remain exposed post-CRQC
 * unless the verifier's policy requires the PQ algorithm (`requireAlgs`).
 */

/** Algorithm label used in hybrid (v2) mandates and policy requirements. */
export const MLDSA44_ALG = "ML-DSA-44";
/** FIPS 204 ML-DSA-44 signature size. Anything else is not a signature. */
export const MLDSA44_SIGNATURE_BYTES = 2420;
/** FIPS 204 ML-DSA-44 public key size. */
export const MLDSA44_PUBLIC_KEY_BYTES = 1312;

/**
 * Thrown on a SIGNING path that needs ML-DSA when the runtime has none.
 * Signing fails loudly and typed — it never silently emits classical-only
 * output where hybrid output was requested. (Verification paths do not throw
 * this; each verifier documents how it treats an unverifiable-here PQ
 * signature, and none of those treatments may loosen a decision.)
 */
export class PqUnavailableError extends Error {
  constructor(message?: string) {
    super(
      message ??
        "ML-DSA-44 is not available in this runtime's node:crypto. Native " +
          "ML-DSA requires Node >= 24.7 built against OpenSSL >= 3.5 — a Node " +
          "binary linked to an older OpenSSL lacks it at ANY Node version. " +
          "The runtime probe (mlDsa44Available()) is the only authority; do " +
          "not infer support from version strings.",
    );
    this.name = "PqUnavailableError";
  }
}

/** Cached probe result; null until first asked. */
let probeResult: boolean | null = null;

/**
 * RUNTIME capability probe for native ML-DSA-44. Asks node:crypto to actually
 * generate a key pair once and caches the verdict. This — not
 * `process.version`, not an OpenSSL version string — is the authority for
 * whether PQ paths exist here (see module docs for why).
 */
export function mlDsa44Available(): boolean {
  if (probeResult === null) {
    try {
      // The narrow typings of older @types/node do not know this key type;
      // the runtime either does (returns keys) or does not (throws).
      generateKeyPairSync("ml-dsa-44" as never);
      probeResult = true;
    } catch {
      probeResult = false;
    }
  }
  return probeResult;
}

/**
 * The two operations everything ML-DSA consumes, as a capability object.
 * `nativeMlDsa44Ops()` returns the node:crypto-backed implementation when the
 * probe passes and null otherwise — callers treat null as "this runtime
 * cannot do ML-DSA" and follow their documented degraded behavior. Tests may
 * substitute a deterministic fake to exercise the surrounding LOGIC on
 * runtimes without native support; nothing in production constructs its own.
 */
export interface MlDsa44Ops {
  /** Sign `message`; resolves to the raw 2420-byte signature. Throws on failure. */
  sign(message: Uint8Array, privateKeyPem: string): Buffer;
  /** Verify; returns false on ANY failure (fail closed), never throws. */
  verify(message: Uint8Array, publicKeyPem: string, signature: Uint8Array): boolean;
}

/** node:crypto-backed ops, or null when the runtime probe fails. */
export function nativeMlDsa44Ops(): MlDsa44Ops | null {
  if (!mlDsa44Available()) return null;
  return {
    sign(message, privateKeyPem) {
      const sig = cryptoSign(null, Buffer.from(message), createPrivateKey(privateKeyPem));
      if (sig.length !== MLDSA44_SIGNATURE_BYTES) {
        throw new Error(
          `ML-DSA-44 signer returned ${sig.length} bytes; expected ${MLDSA44_SIGNATURE_BYTES}`,
        );
      }
      return sig;
    },
    verify(message, publicKeyPem, signature) {
      try {
        return cryptoVerify(
          null,
          Buffer.from(message),
          createPublicKey(publicKeyPem),
          Buffer.from(signature),
        );
      } catch {
        return false; // an unverifiable signature is an invalid signature
      }
    },
  };
}

export interface MlDsa44KeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
}

/** Generate an ML-DSA-44 key pair, or throw `PqUnavailableError`. */
export function generateMlDsa44KeyPair(): MlDsa44KeyPair {
  if (!mlDsa44Available()) throw new PqUnavailableError();
  const { privateKey, publicKey } = generateKeyPairSync("ml-dsa-44" as never) as unknown as {
    privateKey: import("node:crypto").KeyObject;
    publicKey: import("node:crypto").KeyObject;
  };
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

/** id-ml-dsa-44 OID 2.16.840.1.101.3.4.3.17, DER-encoded (9 content bytes). */
const MLDSA44_OID_DER = Buffer.from("0609608648016503040311", "hex");

/** Strict PEM -> DER for a single PUBLIC KEY block. Pure parsing, no crypto. */
function spkiDerFromPem(publicKeyPem: string): Buffer {
  const m = /-----BEGIN PUBLIC KEY-----([A-Za-z0-9+/=\s]+)-----END PUBLIC KEY-----/.exec(
    publicKeyPem,
  );
  if (!m || m[1] === undefined) {
    throw new Error("not a PEM PUBLIC KEY block");
  }
  const b64 = m[1].replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) {
    throw new Error("PEM body is not base64");
  }
  return Buffer.from(b64, "base64");
}

/** Minimal DER TLV reader used only for the fixed SPKI shapes below. */
function readTlv(buf: Buffer, offset: number): { tag: number; start: number; length: number } {
  if (offset + 2 > buf.length) throw new Error("DER truncated");
  const tag = buf[offset]!;
  let len = buf[offset + 1]!;
  let start = offset + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || start + n > buf.length) throw new Error("DER length malformed");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[start + i]!;
    start += n;
  }
  if (start + len > buf.length) throw new Error("DER value truncated");
  return { tag, start, length: len };
}

/**
 * Extract the RAW 1312-byte ML-DSA-44 public key from an SPKI PEM.
 *
 * This function must exist because `rawEd25519PublicKey` (transparency
 * checkpoint module) takes the LAST 32 BYTES of whatever DER it is handed —
 * correct for Ed25519's fixed 44-byte SPKI, silently garbage for an ML-DSA
 * key, and a garbage key id would then be minted for it. Here the SPKI is
 * actually parsed: the AlgorithmIdentifier OID must be id-ml-dsa-44 and the
 * BIT STRING must hold exactly 1312 bytes with zero unused bits.
 *
 * Pure DER parsing — works on runtimes with NO native ML-DSA, so key ids and
 * wire payloads can be computed anywhere even when verification cannot.
 */
export function rawMlDsa44PublicKey(publicKeyPem: string): Buffer {
  const der = spkiDerFromPem(publicKeyPem);
  const outer = readTlv(der, 0);
  if (outer.tag !== 0x30) throw new Error("SPKI: expected outer SEQUENCE");
  const algId = readTlv(der, outer.start);
  if (algId.tag !== 0x30) throw new Error("SPKI: expected AlgorithmIdentifier SEQUENCE");
  const oid = readTlv(der, algId.start);
  if (oid.tag !== 0x06) throw new Error("SPKI: expected algorithm OID");
  const oidTlv = der.subarray(algId.start, algId.start + 2 + oid.length);
  if (!oidTlv.equals(MLDSA44_OID_DER)) {
    throw new Error("SPKI algorithm OID is not id-ml-dsa-44 (2.16.840.1.101.3.4.3.17)");
  }
  // FIPS 204 SPKI carries the AlgorithmIdentifier with ABSENT parameters.
  if (algId.length !== 2 + oid.length) {
    throw new Error("SPKI: id-ml-dsa-44 AlgorithmIdentifier must have absent parameters");
  }
  const bitString = readTlv(der, algId.start + algId.length);
  if (bitString.tag !== 0x03) throw new Error("SPKI: expected subjectPublicKey BIT STRING");
  if (bitString.length !== MLDSA44_PUBLIC_KEY_BYTES + 1 || der[bitString.start] !== 0x00) {
    throw new Error(
      `SPKI: ML-DSA-44 subjectPublicKey must be ${MLDSA44_PUBLIC_KEY_BYTES} bytes with zero unused bits`,
    );
  }
  return Buffer.from(der.subarray(bitString.start + 1, bitString.start + 1 + MLDSA44_PUBLIC_KEY_BYTES));
}

/**
 * Inverse of `rawMlDsa44PublicKey`: wrap 1312 raw public-key bytes in the
 * fixed id-ml-dsa-44 SPKI header and PEM-encode. Pure encoding, no crypto —
 * usable for interop tooling and for deterministic fixtures on runtimes
 * without native ML-DSA.
 */
export function mlDsa44SpkiFromRawPublicKey(raw: Buffer): string {
  if (raw.length !== MLDSA44_PUBLIC_KEY_BYTES) {
    throw new Error(`raw ML-DSA-44 public key must be ${MLDSA44_PUBLIC_KEY_BYTES} bytes`);
  }
  const algId = Buffer.concat([Buffer.from([0x30, MLDSA44_OID_DER.length]), MLDSA44_OID_DER]);
  const bitStringContent = Buffer.concat([Buffer.from([0x00]), raw]);
  const lenBytes = (n: number): Buffer =>
    n < 0x80
      ? Buffer.from([n])
      : Buffer.from([0x82, (n >> 8) & 0xff, n & 0xff]); // lengths here always fit 2 bytes
  const bitString = Buffer.concat([
    Buffer.from([0x03]),
    lenBytes(bitStringContent.length),
    bitStringContent,
  ]);
  const content = Buffer.concat([algId, bitString]);
  const der = Buffer.concat([Buffer.from([0x30]), lenBytes(content.length), content]);
  const b64 = der.toString("base64");
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
}

/** Same domain as `mandateKeyId` — the id commits to the SPKI DER either way. */
const KEY_ID_DOMAIN = "vaduno-mandate-key/v1\n";

/**
 * Mandate key id for an ML-DSA-44 verify key: first 8 bytes of
 * SHA-256("vaduno-mandate-key/v1\n" || SPKI DER), hex — the same derivation
 * as `mandateKeyId`, computed from the PEM body directly so it works on
 * runtimes whose node:crypto cannot parse an ML-DSA SPKI at all. The DER is
 * validated as a real id-ml-dsa-44 SPKI first, so an id is never minted for
 * bytes that are not an ML-DSA-44 key.
 *
 * HONEST LIMIT (do not restate this as "collision-free by construction"):
 * the id is a 64-bit TRUNCATED hash. Distinct keys can share an id —
 * birthday-colliding two attacker-chosen keys costs ~2^32 work, grinding a
 * second preimage for a targeted id ~2^64. What keeps a collision from
 * crossing algorithm families is that verifiers look keys up by
 * (algorithm, kid) — the algorithm is bound AT LOOKUP, not assumed from the
 * id. Within one family the truncation residual remains and is stated in
 * docs/SECURITY-MODEL.md rather than papered over.
 */
export function mlDsa44KeyId(publicKeyPem: string): string {
  rawMlDsa44PublicKey(publicKeyPem); // validate the shape before minting an id
  const der = spkiDerFromPem(publicKeyPem);
  return createHash("sha256")
    .update(KEY_ID_DOMAIN, "utf8")
    .update(der)
    .digest("hex")
    .slice(0, 16);
}
