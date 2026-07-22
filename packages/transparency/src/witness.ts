import { verifyConsistency, type ConsistencyProof } from "./merkle.js";
import { verifyTreeHead, type SignedTreeHead } from "./sth.js";

/**
 * A witness is any party (a client, a second machine, a friend's server) that
 * retains the last signed tree head it accepted and refuses to advance to a
 * new one unless the log PROVES append-only consistency from the old head.
 *
 * With one external witness, a log operator that rewrites history gets caught
 * the next time that witness asks for a consistency proof. With k independent
 * witnesses comparing heads, showing different histories to different parties
 * (split-view/equivocation) requires all k to collude. This module is the
 * client half; publishing heads somewhere public is the operator half.
 */
export interface WitnessState {
  logId: string;
  /** The log operator's Ed25519 public key (PEM). */
  publicKeyPem: string;
  /** Last head this witness accepted; null before the first observation. */
  lastHead: SignedTreeHead | null;
}

export type WitnessResult =
  | { ok: true; state: WitnessState }
  | {
      ok: false;
      code:
        | "BAD_SIGNATURE"
        | "WRONG_LOG"
        | "TREE_SHRANK"
        | "ROOT_CHANGED_WITHOUT_GROWTH"
        | "CONSISTENCY_PROOF_MISSING"
        | "CONSISTENCY_PROOF_INVALID";
      message: string;
    };

/**
 * Observe a new signed head. Fails closed: on any failure the witness state
 * is NOT advanced and the reason names what the operator could not prove.
 *
 * `proof` must cover lastHead.treeSize -> sth.treeSize when the tree grew;
 * it is not needed for the first observation or an identical re-observation.
 */
export function witnessObserve(
  state: WitnessState,
  sth: SignedTreeHead,
  proof?: ConsistencyProof,
): WitnessResult {
  if (sth.logId !== state.logId) {
    return {
      ok: false,
      code: "WRONG_LOG",
      message: `head is for log "${sth.logId}", witness follows "${state.logId}"`,
    };
  }
  if (!verifyTreeHead(sth, state.publicKeyPem)) {
    return {
      ok: false,
      code: "BAD_SIGNATURE",
      message: "signed tree head signature does not verify",
    };
  }
  const prev = state.lastHead;
  if (prev === null) {
    // Trust-on-first-use: the first head is the baseline everything after
    // must stay consistent with.
    return { ok: true, state: { ...state, lastHead: sth } };
  }
  if (sth.treeSize < prev.treeSize) {
    return {
      ok: false,
      code: "TREE_SHRANK",
      message: `tree shrank from ${prev.treeSize} to ${sth.treeSize} (history truncated)`,
    };
  }
  if (sth.treeSize === prev.treeSize) {
    if (sth.rootHash !== prev.rootHash) {
      return {
        ok: false,
        code: "ROOT_CHANGED_WITHOUT_GROWTH",
        message: "same tree size but a different root (history rewritten)",
      };
    }
    return { ok: true, state: { ...state, lastHead: sth } };
  }
  if (prev.treeSize === 0) {
    // The empty tree is a prefix of EVERY tree — growth from it is trivially
    // append-only and no consistency proof exists for first=0 (RFC 9162
    // defines proofs for 0 < first). Without this case a witness whose
    // baseline predates the first leaf could never advance.
    return { ok: true, state: { ...state, lastHead: sth } };
  }
  if (!proof) {
    return {
      ok: false,
      code: "CONSISTENCY_PROOF_MISSING",
      message: `no consistency proof for ${prev.treeSize} -> ${sth.treeSize}`,
    };
  }
  if (
    proof.first !== prev.treeSize ||
    proof.second !== sth.treeSize ||
    !verifyConsistency(prev.rootHash, sth.rootHash, proof)
  ) {
    return {
      ok: false,
      code: "CONSISTENCY_PROOF_INVALID",
      message: `consistency proof does not prove ${prev.treeSize} -> ${sth.treeSize} append-only`,
    };
  }
  return { ok: true, state: { ...state, lastHead: sth } };
}

export interface SplitViewResult {
  consistent: boolean;
  /** Two VERIFIED heads, same size, different roots — signed equivocation. */
  conflict?: [SignedTreeHead, SignedTreeHead];
  /** Heads whose signature did not verify; excluded from comparison. */
  unverified: SignedTreeHead[];
}

/**
 * Compare heads gathered from independent witnesses of the same log. Each
 * head's signature is verified first — an unverifiable head is set aside,
 * never treated as evidence. Two VERIFIED heads of the SAME size with
 * DIFFERENT roots are cryptographic proof of operator equivocation (both
 * carry the operator's signature).
 *
 * Honest scope: this offline check only catches same-size forks. Different-
 * size forks are caught by `witnessObserve`, which demands a consistency
 * proof from each witness's retained head — run both.
 */
export function detectSplitView(
  heads: readonly SignedTreeHead[],
  publicKeyPem: string,
): SplitViewResult {
  const unverified: SignedTreeHead[] = [];
  const bySize = new Map<number, SignedTreeHead>();
  for (const h of heads) {
    if (!verifyTreeHead(h, publicKeyPem)) {
      unverified.push(h);
      continue;
    }
    const seen = bySize.get(h.treeSize);
    if (seen && seen.rootHash !== h.rootHash) {
      return { consistent: false, conflict: [seen, h], unverified };
    }
    bySize.set(h.treeSize, h);
  }
  return { consistent: true, unverified };
}
