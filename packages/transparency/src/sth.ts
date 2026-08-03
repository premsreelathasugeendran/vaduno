import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
} from "node:crypto";
import { canonicalJson, checkedSign, type Ed25519Signer } from "@vaduno/guard";
import type { TreeHead } from "./tree.js";

/**
 * Signed Tree Heads (STH) — the log operator's commitment to a tree state.
 * Publishing STHs is what turns the Merkle tree into a TRANSPARENCY log:
 * once a head is public (or retained by any client), the operator cannot
 * rewrite or truncate history without failing a consistency proof against it.
 *
 * Honest limit, stated plainly: a single operator can still EQUIVOCATE —
 * show different signed heads to different parties. Detection of that needs
 * heads to be shared/witnessed (see witness.ts). We provide the mechanism and
 * document the boundary rather than claiming distributed trust we don't have.
 */
export interface SignedTreeHead {
  /** Operator-chosen stable identifier for this log. */
  logId: string;
  treeSize: number;
  rootHash: string;
  /** ISO timestamp at signing. Informational; not a freshness proof. */
  timestamp: string;
  /** Ed25519 signature (base64) over the canonical JSON of the fields above. */
  signature: string;
}

export interface LogKeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
}

export function generateLogKeyPair(): LogKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

/**
 * Domain-separation tag: STH signatures can never be replayed as (or forged
 * from) any other Vaduno Ed25519 payload. The Vaduno-owned formats each carry
 * their own versioned tag (mandates: `vaduno-mandate/v1`, status lists:
 * `vaduno-status-list/v1`, tree heads this one); the C2SP interop formats are
 * framed by their own structure instead — cosignatures by the fixed
 * `cosignature/v1` header, checkpoint bodies by nothing but the
 * operator-chosen origin line (see checkpoint.ts, and docs/signers.md for
 * why that limit matters). The \n makes the tag unambiguous (canonical JSON
 * never starts mid-line).
 */
const STH_DOMAIN = "vaduno-tlog-sth/v1\n";

function sthPayload(sth: Omit<SignedTreeHead, "signature">): Buffer {
  return Buffer.from(STH_DOMAIN + canonicalJson(sth), "utf8");
}

/** One builder for both signing paths, so their unsigned bytes cannot drift. */
function unsignedTreeHead(
  head: TreeHead,
  opts: { logId: string; now?: () => Date },
): Omit<SignedTreeHead, "signature"> {
  return {
    logId: opts.logId,
    treeSize: head.treeSize,
    rootHash: head.rootHash,
    timestamp: (opts.now ? opts.now() : new Date()).toISOString(),
  };
}

export function signTreeHead(
  head: TreeHead,
  opts: { logId: string; privateKeyPem: string; now?: () => Date },
): SignedTreeHead {
  const unsigned = unsignedTreeHead(head, opts);
  const signature = edSign(
    null,
    sthPayload(unsigned),
    createPrivateKey(opts.privateKeyPem),
  ).toString("base64");
  return { ...unsigned, signature };
}

/**
 * `signTreeHead` through a non-exportable Ed25519Signer (KMS/HSM). Same
 * unsigned structure, same payload bytes, byte-identical signature for the
 * same key (Ed25519 is deterministic). Every signer failure rejects via
 * `checkedSign`; nothing unverifiable is ever returned.
 */
export async function signTreeHeadWith(
  head: TreeHead,
  opts: { logId: string; signer: Ed25519Signer; now?: () => Date; timeoutMs?: number },
): Promise<SignedTreeHead> {
  const unsigned = unsignedTreeHead(head, opts);
  const signature = (
    await checkedSign(
      opts.signer,
      sthPayload(unsigned),
      opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {},
    )
  ).toString("base64");
  return { ...unsigned, signature };
}

/** Fails closed: any malformed input verifies as false, never throws. */
export function verifyTreeHead(sth: SignedTreeHead, publicKeyPem: string): boolean {
  try {
    const { signature, ...unsigned } = sth;
    return edVerify(
      null,
      sthPayload(unsigned),
      createPublicKey(publicKeyPem),
      Buffer.from(signature, "base64"),
    );
  } catch {
    return false;
  }
}
