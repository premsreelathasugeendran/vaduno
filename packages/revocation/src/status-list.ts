import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";
import { canonicalJson } from "@swale/guard";
import { Bitstring, BitstringError, MINIMUM_ENTRIES } from "./bitstring.js";

/**
 * A signed Bitstring Status List credential — the publishable artifact a
 * verifier fetches to learn which mandates are revoked or suspended.
 *
 * Shaped after the W3C Bitstring Status List credentialSubject (statusPurpose
 * + encodedList) but signed with the same Ed25519 construction Swale uses
 * elsewhere, domain-separated so a status-list signature can never be
 * confused with a mandate or a transparency-log tree head.
 */

/**
 * §2.1 purposes. `revocation` is PERMANENT ("not reversible"); `suspension`
 * is reversible. Swale enforces that distinction — un-revoking is refused.
 */
export type StatusPurpose = "revocation" | "suspension";

export interface StatusListCredential {
  /** Identifier of this list (the URL a verifier fetches, or any stable id). */
  id: string;
  /** Who publishes it — the mandate issuer. */
  issuer: string;
  statusPurpose: StatusPurpose;
  /** Multibase base64url of the GZIP'd bitstring (§3.3). */
  encodedList: string;
  /** Total 1-bit entries in the uncompressed list. */
  entries: number;
  /** Monotonic version; a verifier must never accept a lower one (rollback). */
  version: number;
  /** ISO timestamp this snapshot was published. */
  validFrom: string;
  /**
   * ISO timestamp after which this snapshot is STALE. A verifier that only
   * holds an expired list must fail closed (treat as unavailable), never
   * assume "not revoked".
   */
  validUntil: string;
  /** Ed25519 signature (base64) over the canonical unsigned credential. */
  signature: string;
}

/** Domain separation: status-list signatures are their own namespace. */
const STATUS_LIST_DOMAIN = "swale-status-list/v1\n";

function payload(unsigned: Omit<StatusListCredential, "signature">): Buffer {
  return Buffer.from(STATUS_LIST_DOMAIN + canonicalJson(unsigned), "utf8");
}

export interface PublishOptions {
  id: string;
  issuer: string;
  statusPurpose: StatusPurpose;
  privateKeyPem: string;
  version: number;
  /** How long this snapshot stays fresh. Default 1 hour. */
  ttlMs?: number;
  now?: () => Date;
}

/** Sign a bitstring into a publishable status list credential. */
export function publishStatusList(
  bitstring: Bitstring,
  opts: PublishOptions,
): StatusListCredential {
  const now = opts.now ?? (() => new Date());
  const at = now();
  const ttl = opts.ttlMs ?? 3_600_000;
  if (!Number.isSafeInteger(opts.version) || opts.version < 0) {
    throw new BitstringError(`invalid status list version: ${opts.version}`);
  }
  const unsigned: Omit<StatusListCredential, "signature"> = {
    id: opts.id,
    issuer: opts.issuer,
    statusPurpose: opts.statusPurpose,
    encodedList: bitstring.encode(),
    entries: bitstring.length,
    version: opts.version,
    validFrom: at.toISOString(),
    validUntil: new Date(at.getTime() + ttl).toISOString(),
  };
  const signature = edSign(
    null,
    payload(unsigned),
    createPrivateKey(opts.privateKeyPem),
  ).toString("base64");
  return { ...unsigned, signature };
}

export type StatusCheckCode =
  | "OK"
  | "SIGNATURE_INVALID"
  | "STATUS_LIST_EXPIRED"
  | "STATUS_LIST_NOT_YET_VALID"
  | "STATUS_LIST_LENGTH_ERROR"
  | "RANGE_ERROR"
  | "PURPOSE_MISMATCH"
  | "LIST_MISMATCH"
  | "ISSUER_MISMATCH"
  | "MALFORMED";

export interface StatusCheck {
  /** True ONLY when the entry is verifiably NOT set. Anything else = false. */
  valid: boolean;
  /** True when the bit is set (revoked/suspended). */
  revoked: boolean;
  code: StatusCheckCode;
  message: string;
}

/**
 * Verify a status list credential and read one entry. FAIL CLOSED: any
 * problem — bad signature, stale list, malformed body, out-of-range index —
 * returns `valid: false`. A verifier must treat `valid:false` as "do not
 * authorize", never as "probably fine".
 *
 * Note `revoked` and `valid` are NOT complements: an expired list yields
 * valid:false with revoked:false, because its contents are unknown-not-clean.
 */
export function checkStatus(
  credential: StatusListCredential,
  index: number,
  opts: {
    publicKeyPem: string;
    /**
     * The purpose this check is FOR. Pass the value the caller expects — never
     * `credential.statusPurpose`, which would make the gate a tautology and
     * let a sibling suspension list (same key, same id, bits clear) stand in
     * for the revocation list and un-revoke everything.
     */
    expectedPurpose?: StatusPurpose;
    /** Pin the list id — one key may sign several lists. */
    expectedListId?: string;
    /** Pin the issuer. */
    expectedIssuer?: string;
    /** Reject a list whose entry count is under the W3C 16KB minimum. */
    requireMinimumEntries?: boolean;
    now?: () => Date;
  },
): StatusCheck {
  const now = opts.now ?? (() => new Date());
  if (!credential || typeof credential !== "object") {
    return fail("MALFORMED", "status list credential is missing");
  }
  // 1. Signature over the exact canonical unsigned credential.
  let signatureOk: boolean;
  try {
    const { signature, ...unsigned } = credential;
    signatureOk = edVerify(
      null,
      payload(unsigned),
      createPublicKey(opts.publicKeyPem),
      Buffer.from(signature, "base64"),
    );
  } catch {
    signatureOk = false;
  }
  if (!signatureOk) {
    return fail("SIGNATURE_INVALID", "status list signature does not verify");
  }
  // 2. Identity: a signature only proves WHO signed, not WHICH list. Without
  // pinning, any list the issuer key ever signed — including a sibling
  // suspension list whose revocation bits are clear — substitutes for this one.
  if (opts.expectedPurpose && credential.statusPurpose !== opts.expectedPurpose) {
    return fail(
      "PURPOSE_MISMATCH",
      `status list purpose is "${credential.statusPurpose}", expected "${opts.expectedPurpose}"`,
    );
  }
  if (opts.expectedListId !== undefined && credential.id !== opts.expectedListId) {
    return fail(
      "LIST_MISMATCH",
      `status list id is "${credential.id}", expected "${opts.expectedListId}"`,
    );
  }
  if (opts.expectedIssuer !== undefined && credential.issuer !== opts.expectedIssuer) {
    return fail(
      "ISSUER_MISMATCH",
      `status list issuer is "${credential.issuer}", expected "${opts.expectedIssuer}"`,
    );
  }
  // 3. Freshness — a stale list is UNAVAILABLE, not "clean".
  const until = Date.parse(credential.validUntil);
  const from = Date.parse(credential.validFrom);
  if (Number.isNaN(until) || Number.isNaN(from)) {
    return fail("MALFORMED", "validFrom/validUntil is not a parseable timestamp");
  }
  if (from >= until) {
    return fail("MALFORMED", "validFrom is not before validUntil");
  }
  const nowMs = now().getTime();
  if (nowMs < from) {
    // A future-dated snapshot must not verify: accepting one would also let a
    // huge version number poison a verifier's rollback floor forever.
    return fail(
      "STATUS_LIST_NOT_YET_VALID",
      `status list is not valid until ${credential.validFrom}`,
    );
  }
  if (nowMs >= until) {
    return fail(
      "STATUS_LIST_EXPIRED",
      `status list expired at ${credential.validUntil} — treat as unavailable, not as "not revoked"`,
    );
  }
  // 4. Decode and length-check (§3.2 step 4).
  let bits: Bitstring;
  try {
    bits = Bitstring.decode(credential.encodedList);
  } catch (err) {
    return fail("MALFORMED", err instanceof Error ? err.message : String(err));
  }
  if (bits.length !== credential.entries) {
    return fail(
      "MALFORMED",
      `declared entries (${credential.entries}) != decoded bitstring length (${bits.length})`,
    );
  }
  if ((opts.requireMinimumEntries ?? true) && bits.length < MINIMUM_ENTRIES) {
    return fail(
      "STATUS_LIST_LENGTH_ERROR",
      `status list has ${bits.length} entries, below the ${MINIMUM_ENTRIES} minimum`,
    );
  }
  // 5. Read the entry.
  let revoked: boolean;
  try {
    revoked = bits.get(index);
  } catch (err) {
    return {
      valid: false,
      revoked: false,
      code: "RANGE_ERROR",
      message: err instanceof Error ? err.message : String(err),
    };
  }
  return revoked
    ? {
        valid: false,
        revoked: true,
        code: "OK",
        message: `entry ${index} is ${credential.statusPurpose === "suspension" ? "suspended" : "revoked"}`,
      }
    : { valid: true, revoked: false, code: "OK", message: `entry ${index} is active` };
}

function fail(code: StatusCheckCode, message: string): StatusCheck {
  return { valid: false, revoked: false, code, message };
}
