import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import {
  EMPTY_TREE_ROOT,
  leafHash,
  proveConsistency,
  proveInclusion,
  rootFromLeafHashes,
  verifyConsistency,
  verifyInclusion,
} from "../src/merkle.js";

/**
 * Independent NAIVE implementation of RFC 9162 MTH, written recursively and
 * separately from the library's, so a shared bug would have to be made twice.
 */
function naiveRoot(leaves: Buffer[]): string {
  const h = (...parts: Buffer[]) =>
    createHash("sha256").update(Buffer.concat(parts)).digest();
  const mth = (a: Buffer[]): Buffer => {
    if (a.length === 0) return createHash("sha256").digest();
    if (a.length === 1) return h(Buffer.from([0x00]), a[0]!);
    let k = 1;
    while (k * 2 < a.length) k *= 2;
    return h(Buffer.from([0x01]), mth(a.slice(0, k)), mth(a.slice(k)));
  };
  return mth(leaves).toString("hex");
}

/** The 8 leaves used by the published Certificate Transparency test vectors. */
const CT_LEAVES = [
  "",
  "00",
  "10",
  "2021",
  "3031",
  "40414243",
  "5051525354555657",
  "606162636465666768696a6b6c6d6e6f",
].map((x) => Buffer.from(x, "hex"));

const CT_HASHES = CT_LEAVES.map((l) => leafHash(l));

/** Deterministic test leaves: leaf i = utf8("leaf-i"). */
function hashes(n: number): string[] {
  return Array.from({ length: n }, (_, i) => leafHash(`leaf-${i}`));
}

describe("Merkle tree hash (RFC 9162 / RFC 6962)", () => {
  it("matches the published Certificate Transparency test vectors", () => {
    expect(EMPTY_TREE_ROOT).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    expect(rootFromLeafHashes(CT_HASHES, 1)).toBe(
      "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    );
    expect(rootFromLeafHashes(CT_HASHES, 2)).toBe(
      "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    );
    expect(rootFromLeafHashes(CT_HASHES, 3)).toBe(
      "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    );
    expect(rootFromLeafHashes(CT_HASHES, 8)).toBe(
      "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    );
  });

  it("agrees with an independent naive implementation for sizes 0..65", () => {
    for (let n = 0; n <= 65; n++) {
      const raw = Array.from({ length: n }, (_, i) => Buffer.from(`leaf-${i}`, "utf8"));
      expect(rootFromLeafHashes(hashes(n))).toBe(naiveRoot(raw));
    }
  });

  it("domain-separates leaves from interior nodes (0x00 vs 0x01 prefix)", () => {
    // A leaf whose BYTES equal (left||right) of an interior node must not
    // collide with that node.
    const l0 = leafHash("a");
    const l1 = leafHash("b");
    const root2 = rootFromLeafHashes([l0, l1]);
    const forged = leafHash(Buffer.from(l0 + l1, "hex"));
    expect(forged).not.toBe(root2);
  });
});

describe("inclusion proofs", () => {
  it("proves and verifies every leaf for every tree size 1..64", () => {
    for (let n = 1; n <= 64; n++) {
      const hs = hashes(n);
      const root = rootFromLeafHashes(hs);
      for (let i = 0; i < n; i++) {
        const proof = proveInclusion(hs, i);
        expect(verifyInclusion(hs[i]!, proof, root)).toBe(true);
      }
    }
  });

  it("supports proofs against a historical (smaller) tree size", () => {
    const hs = hashes(40);
    const oldRoot = rootFromLeafHashes(hs, 25);
    const proof = proveInclusion(hs, 7, 25);
    expect(verifyInclusion(hs[7]!, proof, oldRoot)).toBe(true);
    // Same proof must NOT verify against the current root.
    expect(verifyInclusion(hs[7]!, proof, rootFromLeafHashes(hs))).toBe(false);
  });

  it("rejects a proof for the wrong leaf, wrong index, or wrong root", () => {
    const hs = hashes(13);
    const root = rootFromLeafHashes(hs);
    const proof = proveInclusion(hs, 5);
    expect(verifyInclusion(hs[6]!, proof, root)).toBe(false);
    expect(verifyInclusion(hs[5]!, { ...proof, leafIndex: 6 }, root)).toBe(false);
    expect(verifyInclusion(hs[5]!, proof, rootFromLeafHashes(hashes(14)))).toBe(false);
  });

  it("rejects truncated, extended, and reordered paths", () => {
    const hs = hashes(21);
    const root = rootFromLeafHashes(hs);
    const proof = proveInclusion(hs, 9);
    expect(proof.path.length).toBeGreaterThan(2);
    expect(
      verifyInclusion(hs[9]!, { ...proof, path: proof.path.slice(1) }, root),
    ).toBe(false);
    expect(
      verifyInclusion(hs[9]!, { ...proof, path: [...proof.path, proof.path[0]!] }, root),
    ).toBe(false);
    const swapped = [...proof.path];
    [swapped[0], swapped[1]] = [swapped[1]!, swapped[0]!];
    expect(verifyInclusion(hs[9]!, { ...proof, path: swapped }, root)).toBe(false);
  });

  it("fails closed on malformed input instead of throwing", () => {
    const hs = hashes(4);
    const root = rootFromLeafHashes(hs);
    const proof = proveInclusion(hs, 2);
    expect(verifyInclusion("zz-not-hex", proof, root)).toBe(false);
    expect(verifyInclusion(hs[2]!, { ...proof, leafIndex: -1 }, root)).toBe(false);
    expect(verifyInclusion(hs[2]!, { ...proof, leafIndex: 99 }, root)).toBe(false);
    expect(verifyInclusion(hs[2]!, { ...proof, treeSize: 2.5 }, root)).toBe(false);
    expect(
      verifyInclusion(hs[2]!, { ...proof, path: ["nothex"] }, root),
    ).toBe(false);
  });

  it("bounds attacker-supplied path length before doing any hashing work", () => {
    const hs = hashes(4);
    const root = rootFromLeafHashes(hs);
    const proof = proveInclusion(hs, 2);
    const hugePath = Array.from({ length: 100_000 }, () => hs[0]!);
    expect(verifyInclusion(hs[2]!, { ...proof, path: hugePath }, root)).toBe(false);
    // Unsafe-integer sizes fail closed too.
    expect(
      verifyInclusion(hs[2]!, { ...proof, treeSize: 2 ** 60 }, root),
    ).toBe(false);
  });

  it("refuses to prove an out-of-range leaf", () => {
    const hs = hashes(5);
    expect(() => proveInclusion(hs, 5)).toThrow(/out of range/);
    expect(() => proveInclusion(hs, -1)).toThrow(/out of range/);
    expect(() => proveInclusion(hs, 0, 9)).toThrow(/out of range/);
  });
});

describe("consistency proofs", () => {
  it("proves and verifies every pair 1 <= m <= n <= 33", () => {
    const hs = hashes(33);
    for (let n = 1; n <= 33; n++) {
      const newRoot = rootFromLeafHashes(hs, n);
      for (let m = 1; m <= n; m++) {
        const oldRoot = rootFromLeafHashes(hs, m);
        const proof = proveConsistency(hs, m, n);
        expect(verifyConsistency(oldRoot, newRoot, proof)).toBe(true);
      }
    }
  });

  it("rejects a rewritten history (same size, different content)", () => {
    const honest = hashes(20);
    const forged = [...honest];
    forged[3] = leafHash("evil-replacement");
    const oldRoot = rootFromLeafHashes(honest, 10);
    const forgedRoot = rootFromLeafHashes(forged, 20);
    // The forger cannot produce a valid proof from the honest old root; a
    // proof generated from the FORGED history must fail against it.
    const proof = proveConsistency(forged, 10, 20);
    expect(verifyConsistency(oldRoot, forgedRoot, proof)).toBe(false);
  });

  it("rejects proofs for mismatched sizes or tampered paths", () => {
    const hs = hashes(24);
    const oldRoot = rootFromLeafHashes(hs, 9);
    const newRoot = rootFromLeafHashes(hs, 24);
    const proof = proveConsistency(hs, 9, 24);
    expect(verifyConsistency(newRoot, oldRoot, proof)).toBe(false);
    expect(
      verifyConsistency(oldRoot, newRoot, { ...proof, path: proof.path.slice(1) }),
    ).toBe(false);
    expect(
      verifyConsistency(oldRoot, newRoot, {
        ...proof,
        path: [leafHash("junk"), ...proof.path.slice(1)],
      }),
    ).toBe(false);
    expect(verifyConsistency(oldRoot, newRoot, { ...proof, first: 8 })).toBe(false);
  });

  it("identical trees: empty path verifies, non-empty fails", () => {
    const hs = hashes(11);
    const root = rootFromLeafHashes(hs);
    expect(verifyConsistency(root, root, { first: 11, second: 11, path: [] })).toBe(
      true,
    );
    expect(
      verifyConsistency(root, root, { first: 11, second: 11, path: [hs[0]!] }),
    ).toBe(false);
    // Same size, different roots.
    const other = rootFromLeafHashes(
      Array.from({ length: 11 }, (_, i) => leafHash(`other-${i}`)),
    );
    expect(verifyConsistency(root, other, { first: 11, second: 11, path: [] })).toBe(
      false,
    );
  });

  it("fails closed on malformed input instead of throwing", () => {
    const hs = hashes(6);
    const proof = proveConsistency(hs, 3, 6);
    const a = rootFromLeafHashes(hs, 3);
    const b = rootFromLeafHashes(hs, 6);
    expect(verifyConsistency("nothex", b, proof)).toBe(false);
    expect(verifyConsistency(a, b, { ...proof, first: 0 })).toBe(false);
    expect(verifyConsistency(a, b, { ...proof, first: 1.5 })).toBe(false);
    expect(verifyConsistency(a, b, { ...proof, path: ["zz"] })).toBe(false);
  });

  it("refuses to prove an invalid range", () => {
    const hs = hashes(8);
    expect(() => proveConsistency(hs, 0, 8)).toThrow(/invalid/);
    expect(() => proveConsistency(hs, 5, 4)).toThrow(/invalid/);
    expect(() => proveConsistency(hs, 2, 9)).toThrow(/out of range/);
  });

  it("bounds attacker-supplied consistency paths and unsafe sizes", () => {
    const hs = hashes(6);
    const proof = proveConsistency(hs, 3, 6);
    const a = rootFromLeafHashes(hs, 3);
    const b = rootFromLeafHashes(hs);
    const hugePath = Array.from({ length: 100_000 }, () => hs[0]!);
    expect(verifyConsistency(a, b, { ...proof, path: hugePath })).toBe(false);
    expect(verifyConsistency(a, b, { ...proof, second: 2 ** 60 })).toBe(false);
  });
});
