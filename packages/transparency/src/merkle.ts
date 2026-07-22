import { createHash } from "node:crypto";

/**
 * RFC 9162 (Certificate Transparency v2) Merkle tree math over SHA-256.
 *
 * Domain separation per §2.1.1:
 *   leaf hash:          MTH({d0})  = HASH(0x00 || d0)
 *   interior node hash: MTH(D[n])  = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
 * with k the largest power of two strictly less than n. The 0x00/0x01
 * prefixes prevent a leaf from being reinterpreted as an interior node
 * (the second-preimage attack on unprefixed Merkle trees).
 *
 * The proof VERIFIERS below transcribe the RFC's numbered algorithms
 * (§2.1.3.2 inclusion, §2.1.4.2 consistency) step for step; the provers
 * follow the recursive PATH/SUBPROOF definitions (§2.1.3.1, §2.1.4.1).
 * All hashes are lowercase hex at this module's boundary.
 */

const LEAF_PREFIX = 0x00;
const NODE_PREFIX = 0x01;

/**
 * Proof-size bounds. An inclusion path is at most ceil(log2(treeSize)) nodes
 * and a consistency path at most ~2*log2(second)+1; JS integers cap tree
 * sizes below 2^53, so 64 / 130 accommodate every representable tree while
 * stopping an attacker-supplied multi-megabyte path from being hex-validated
 * and hashed at full length before rejection.
 */
const MAX_INCLUSION_PATH = 64;
const MAX_CONSISTENCY_PATH = 130;

/** Integer in [1, Number.MAX_SAFE_INTEGER] — sizes/indexes proofs may carry. */
function safeSize(n: number): boolean {
  return Number.isSafeInteger(n) && n >= 1;
}

/** MTH({}) — the hash of the empty input; root of the empty tree. */
export const EMPTY_TREE_ROOT = createHash("sha256").digest("hex");

export class ProofError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProofError";
  }
}

function sha256(...parts: Uint8Array[]): Buffer {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
}

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

function unhex(s: string, what: string): Buffer {
  if (!/^[0-9a-f]{64}$/.test(s)) {
    throw new ProofError(`${what} is not a 64-char lowercase hex sha256`);
  }
  return Buffer.from(s, "hex");
}

/** HASH(0x00 || data) — hex leaf hash for raw leaf bytes. */
export function leafHash(data: Uint8Array | string): string {
  const bytes = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  return hex(sha256(Buffer.from([LEAF_PREFIX]), bytes));
}

/** HASH(0x01 || left || right) — hex interior-node hash. */
export function nodeHash(leftHex: string, rightHex: string): string {
  return hex(
    sha256(
      Buffer.from([NODE_PREFIX]),
      unhex(leftHex, "left node"),
      unhex(rightHex, "right node"),
    ),
  );
}

/** Largest power of two STRICTLY less than n (n >= 2). */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/**
 * MTH(D[start:end]) over pre-hashed leaves. Iterative post-order fold to
 * keep large trees off the call stack.
 */
function subtreeRoot(leaves: readonly string[], start: number, end: number): string {
  const n = end - start;
  if (n === 0) return EMPTY_TREE_ROOT;
  if (n === 1) return leaves[start]!;
  const k = splitPoint(n);
  return nodeHash(
    subtreeRoot(leaves, start, start + k),
    subtreeRoot(leaves, start + k, end),
  );
}

/** Merkle Tree Hash (root) of the first `size` leaf hashes. */
export function rootFromLeafHashes(leafHashes: readonly string[], size?: number): string {
  const n = size ?? leafHashes.length;
  if (n < 0 || n > leafHashes.length) {
    throw new ProofError(`tree size ${n} out of range (have ${leafHashes.length} leaves)`);
  }
  return subtreeRoot(leafHashes, 0, n);
}

export interface InclusionProof {
  /** 0-based index of the leaf the proof is for. */
  leafIndex: number;
  /** Size of the tree the proof commits into. */
  treeSize: number;
  /** Audit path, leaf-to-root, hex node hashes. */
  path: string[];
}

export interface ConsistencyProof {
  /** Size of the earlier (contained) tree. Must be >= 1. */
  first: number;
  /** Size of the later tree. */
  second: number;
  /** Consistency path, hex node hashes. */
  path: string[];
}

/** PATH(m, D[n]) — RFC 9162 §2.1.3.1, over pre-hashed leaves. */
export function proveInclusion(
  leafHashes: readonly string[],
  leafIndex: number,
  treeSize?: number,
): InclusionProof {
  const n = treeSize ?? leafHashes.length;
  if (n < 1 || n > leafHashes.length) {
    throw new ProofError(`tree size ${n} out of range (have ${leafHashes.length} leaves)`);
  }
  if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= n) {
    throw new ProofError(`leaf index ${leafIndex} out of range for tree size ${n}`);
  }
  const path: string[] = [];
  let start = 0;
  let end = n;
  let m = leafIndex;
  while (end - start > 1) {
    const k = splitPoint(end - start);
    if (m < k) {
      // Sibling is the right subtree; recurse left. Collect on the way DOWN,
      // reverse at the end so the path reads leaf-to-root.
      path.push(subtreeRoot(leafHashes, start + k, end));
      end = start + k;
    } else {
      path.push(subtreeRoot(leafHashes, start, start + k));
      start += k;
      m -= k;
    }
  }
  return { leafIndex, treeSize: n, path: path.reverse() };
}

/** PROOF(m, D[n]) = SUBPROOF(m, D[n], true) — RFC 9162 §2.1.4.1. */
export function proveConsistency(
  leafHashes: readonly string[],
  first: number,
  second: number,
): ConsistencyProof {
  if (!Number.isInteger(first) || !Number.isInteger(second) || first < 1 || first > second) {
    throw new ProofError(`invalid consistency range ${first} -> ${second}`);
  }
  if (second > leafHashes.length) {
    throw new ProofError(`tree size ${second} out of range (have ${leafHashes.length} leaves)`);
  }
  const path: string[] = [];
  subproof(leafHashes, first, 0, second, true, path);
  return { first, second, path };
}

function subproof(
  leaves: readonly string[],
  m: number,
  start: number,
  end: number,
  complete: boolean,
  out: string[],
): void {
  const n = end - start;
  if (m === n) {
    // SUBPROOF(m, D[m], true) = {}; SUBPROOF(m, D[m], false) = {MTH(D[m])}.
    if (!complete) out.push(subtreeRoot(leaves, start, end));
    return;
  }
  const k = splitPoint(n);
  if (m <= k) {
    subproof(leaves, m, start, start + k, complete, out);
    out.push(subtreeRoot(leaves, start + k, end));
  } else {
    subproof(leaves, m - k, start + k, end, false, out);
    out.push(subtreeRoot(leaves, start, start + k));
  }
}

/**
 * RFC 9162 §2.1.3.2 — verify that `leafHashHex` is the leaf at
 * `proof.leafIndex` of the tree of size `proof.treeSize` whose root is
 * `rootHashHex`. Returns false (never throws) on any failure: proof
 * verification is a boundary that handles untrusted input.
 */
export function verifyInclusion(
  leafHashHex: string,
  proof: InclusionProof,
  rootHashHex: string,
): boolean {
  try {
    const { leafIndex, treeSize, path } = proof;
    if (!safeSize(treeSize) || !Number.isSafeInteger(leafIndex) || leafIndex < 0) {
      return false;
    }
    // Bound attacker-supplied work before touching the path contents.
    if (!Array.isArray(path) || path.length > MAX_INCLUSION_PATH) return false;
    // 1. If leaf_index >= tree_size, fail.
    if (leafIndex >= treeSize) return false;
    // 2. Set fn to leaf_index and sn to tree_size - 1.
    let fn = leafIndex;
    let sn = treeSize - 1;
    // 3. Set r to hash.
    let r = unhex(leafHashHex, "leaf hash");
    // 4. For each value p in the inclusion_path array:
    for (const pHex of path) {
      const p = unhex(pHex, "inclusion path node");
      // 4a. If sn is 0, stop and fail.
      if (sn === 0) return false;
      // 4b.
      if (fn % 2 === 1 || fn === sn) {
        r = sha256(Buffer.from([NODE_PREFIX]), p, r);
        if (fn % 2 === 0) {
          // Right-shift fn and sn equally until LSB(fn) is set or fn is 0.
          while (fn % 2 === 0 && fn !== 0) {
            fn = Math.floor(fn / 2);
            sn = Math.floor(sn / 2);
          }
        }
      } else {
        r = sha256(Buffer.from([NODE_PREFIX]), r, p);
      }
      // 4c. Right-shift both fn and sn one time.
      fn = Math.floor(fn / 2);
      sn = Math.floor(sn / 2);
    }
    // 5. sn must be 0 and r must equal the root.
    return sn === 0 && hex(r) === rootHashHex;
  } catch {
    return false;
  }
}

/**
 * RFC 9162 §2.1.4.2 — verify that the tree of size `proof.second` with root
 * `secondHashHex` is an append-only extension of the tree of size
 * `proof.first` with root `firstHashHex`. Returns false, never throws.
 */
export function verifyConsistency(
  firstHashHex: string,
  secondHashHex: string,
  proof: ConsistencyProof,
): boolean {
  try {
    const { first, second } = proof;
    if (!safeSize(first) || !safeSize(second) || first > second) return false;
    // Bound attacker-supplied work before touching the path contents.
    if (!Array.isArray(proof.path) || proof.path.length > MAX_CONSISTENCY_PATH) {
      return false;
    }
    const firstHash = unhex(firstHashHex, "first root");
    const secondHash = unhex(secondHashHex, "second root");
    // Identical trees: the proof must be empty and the roots equal.
    if (first === second) {
      return proof.path.length === 0 && firstHash.equals(secondHash);
    }
    // 1. If consistency_path is an empty array, fail.
    if (proof.path.length === 0) return false;
    let path = proof.path.map((p) => unhex(p, "consistency path node"));
    // 2. If first is an exact power of 2, prepend first_hash. (BigInt: the
    // bitwise test is 32-bit-truncated on Numbers and lies for first >= 2^32.)
    if ((BigInt(first) & (BigInt(first) - 1n)) === 0n) {
      path = [firstHash, ...path];
    }
    // 3. Set fn to first - 1 and sn to second - 1.
    let fn = first - 1;
    let sn = second - 1;
    // 4. If LSB(fn) is set, right-shift fn and sn equally until it is not.
    while (fn % 2 === 1) {
      fn = Math.floor(fn / 2);
      sn = Math.floor(sn / 2);
    }
    // 5. Set both fr and sr to the first value in the path.
    let fr = path[0]!;
    let sr = path[0]!;
    // 6. For each subsequent value c:
    for (let i = 1; i < path.length; i++) {
      const c = path[i]!;
      // 6a. If sn is 0, stop and fail.
      if (sn === 0) return false;
      // 6b.
      if (fn % 2 === 1 || fn === sn) {
        fr = sha256(Buffer.from([NODE_PREFIX]), c, fr);
        sr = sha256(Buffer.from([NODE_PREFIX]), c, sr);
        if (fn % 2 === 0) {
          while (fn % 2 === 0 && fn !== 0) {
            fn = Math.floor(fn / 2);
            sn = Math.floor(sn / 2);
          }
        }
      } else {
        sr = sha256(Buffer.from([NODE_PREFIX]), sr, c);
      }
      // 6c. Right-shift both fn and sn one time.
      fn = Math.floor(fn / 2);
      sn = Math.floor(sn / 2);
    }
    // 7. fr == first_hash, sr == second_hash, sn == 0.
    return fr.equals(firstHash) && sr.equals(secondHash) && sn === 0;
  } catch {
    return false;
  }
}
