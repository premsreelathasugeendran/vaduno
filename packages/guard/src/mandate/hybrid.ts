import { canonicalJson } from "../ledger/hash.js";
import type { MandateConstraints } from "./mandate.js";
import { MLDSA44_SIGNATURE_BYTES } from "./pq.js";

/**
 * Hybrid (v2) mandates: the SECOND ALGORITHM SLOT.
 *
 * A v2 mandate carries BOTH an Ed25519 and an ML-DSA-44 signature over the
 * SAME domain-tagged payload, under a NEW version and a NEW domain tag. The
 * frozen v1 format is untouched: v1 vectors still pass byte-for-byte and v1
 * mandates remain verifiable forever. Hybrid follows the composite pattern
 * the IETF is standardizing for signatures: where a signature can be
 * verified, it MUST verify — a present-but-invalid half is tamper evidence,
 * never ignorable.
 *
 * Whether hybrid or PQ-only is the right end state is a genuine, UNSETTLED
 * policy split (NSA CNSA 2.0 says hybrid is not required; BSI and ANSSI
 * mandate hybrid). This module implements hybrid and takes no side beyond
 * that — see docs/SECURITY-MODEL.md.
 *
 * WHAT HYBRID DOES NOT DO (the downgrade truth, stated here because it is
 * easy to overclaim): as long as a verifier still accepts v1 and still
 * registers Ed25519-only trust, a post-CRQC attacker does not need to strip
 * a v2 mandate — they MINT A FRESH v1 mandate under any registered Ed25519
 * kid. Setting `requireAlgs: ["ML-DSA-44"]` (or de-registering
 * classical-only keys) is the ONLY defense; issuing v2 alongside merely
 * makes that future enforcement possible. The attack and the remedy are both
 * pinned by tests in test/mandate-v2.test.ts.
 */

/** Domain separator for the v2 (hybrid) mandate signing payload. */
export const MANDATE_V2_DOMAIN = "vaduno-mandate/v2\n";

/** Value of `MandateV2.v`. */
export const MANDATE_V2_FORMAT_VERSION = 2;

/**
 * The exact algorithm suite v2 defines, in the exact order it must appear.
 * v2 IS the hybrid version — a v2 carrying any other set (including Ed25519
 * alone, which is v1's job) is malformed and refused before any crypto runs.
 */
export const MANDATE_V2_ALGS: readonly ["Ed25519", "ML-DSA-44"] = ["Ed25519", "ML-DSA-44"];

/** Exact DECODED signature length per algorithm (see structural gate below). */
const SIGNATURE_BYTES: Record<string, number> = {
  Ed25519: 64,
  "ML-DSA-44": MLDSA44_SIGNATURE_BYTES,
};

/** Key ids are 8 bytes of truncated SHA-256, lowercase hex — exactly 16 chars. */
const KID_SHAPE = /^[0-9a-f]{16}$/;

/** Base64 shape gate. Node's decoder skips invalid characters silently, so a
 * shape check on the STRING is not a length check on the SIGNATURE — the
 * decoded length is asserted separately, and that one is authoritative. */
const BASE64_SHAPE = /^[A-Za-z0-9+/]+={0,2}$/;

export interface MandateV2 {
  /** Always 2. A verifier that does not recognise the value MUST refuse. */
  v: number;
  /**
   * The algorithm suite, exactly `["Ed25519", "ML-DSA-44"]`. Signed, so a
   * verifier refuses a suite it does not implement instead of guessing.
   */
  algs: string[];
  /** Signing key id PER ALGORITHM. Keys of this object MUST equal `algs`. */
  kids: Record<string, string>;
  id: string;
  issuer: string;
  agentId: string;
  constraints: MandateConstraints;
  createdAt: string;
  /**
   * Signature PER ALGORITHM (base64), each over the SAME
   * `MANDATE_V2_DOMAIN`-tagged payload. Keys MUST equal `algs`.
   */
  signatures: Record<string, string>;
}

/**
 * The exact bytes both v2 signatures cover: the v2 domain tag, then the
 * canonical JSON of every field except `signatures`.
 */
export function mandateV2Payload(m: Omit<MandateV2, "signatures">): Buffer {
  return Buffer.from(MANDATE_V2_DOMAIN + canonicalJson(m), "utf8");
}

export type StructureCheck = { ok: true } | { ok: false; message: string };

/**
 * Pre-crypto structural gate for a v2 mandate — every bound here runs BEFORE
 * any signature verification, so a malformed artifact cannot buy CPU time or
 * reach a lenient code path:
 *
 *  - `algs` must equal the v2 suite exactly (content AND order — order is
 *    part of the signed canonical form).
 *  - `kids` keys must equal `algs` EXACTLY, and every kid must match
 *    ^[0-9a-f]{16}$. Both bounds exist because kids is signed but
 *    issuer-side bugs are real: without them an issuer could bloat kids
 *    unbounded or ship a kid no verifier can ever hold.
 *  - `signatures` keys must equal `algs` exactly; each value must be base64
 *    AND must DECODE to the exact per-algorithm length (64 / 2420). The
 *    decoded check is the real one — Node's base64 decoder silently skips
 *    invalid characters, so an encoded-length check alone can be satisfied
 *    by a string that decodes to something shorter.
 */
export function checkMandateV2Structure(m: MandateV2): StructureCheck {
  const fail = (message: string): StructureCheck => ({ ok: false, message });
  if (m.v !== MANDATE_V2_FORMAT_VERSION) return fail(`v must be ${MANDATE_V2_FORMAT_VERSION}`);
  if (
    !Array.isArray(m.algs) ||
    m.algs.length !== MANDATE_V2_ALGS.length ||
    !MANDATE_V2_ALGS.every((a, i) => m.algs[i] === a)
  ) {
    return fail(
      `algs must be exactly ${JSON.stringify(MANDATE_V2_ALGS)} in that order (v2 is the hybrid format)`,
    );
  }
  for (const [field, record] of [
    ["kids", m.kids],
    ["signatures", m.signatures],
  ] as const) {
    if (record === null || typeof record !== "object" || Array.isArray(record)) {
      return fail(`${field} must be a plain object`);
    }
    const keys = Object.keys(record).sort();
    const expected = [...MANDATE_V2_ALGS].sort();
    if (keys.length !== expected.length || !expected.every((k, i) => keys[i] === k)) {
      return fail(`${field} keys must equal algs exactly (got ${JSON.stringify(keys)})`);
    }
  }
  for (const alg of MANDATE_V2_ALGS) {
    const kid = m.kids[alg];
    if (typeof kid !== "string" || !KID_SHAPE.test(kid)) {
      return fail(`kids["${alg}"] must be 16 lowercase hex chars`);
    }
    const sig = m.signatures[alg];
    const want = SIGNATURE_BYTES[alg]!;
    if (typeof sig !== "string" || !BASE64_SHAPE.test(sig)) {
      return fail(`signatures["${alg}"] must be base64`);
    }
    // ceil(want/3)*4 is the exact encoded length for `want` bytes; anything
    // longer cannot decode to `want` bytes and is refused before decoding.
    if (sig.length > Math.ceil(want / 3) * 4) {
      return fail(`signatures["${alg}"] is longer than a ${want}-byte signature can encode`);
    }
    if (Buffer.from(sig, "base64").length !== want) {
      return fail(`signatures["${alg}"] must decode to exactly ${want} bytes`);
    }
  }
  for (const [name, value] of [
    ["id", m.id],
    ["issuer", m.issuer],
    ["agentId", m.agentId],
    ["createdAt", m.createdAt],
  ] as const) {
    if (typeof value !== "string" || value.length === 0) {
      return fail(`${name} must be a non-empty string`);
    }
  }
  if (m.constraints === null || typeof m.constraints !== "object") {
    return fail("constraints must be an object");
  }
  return { ok: true };
}
