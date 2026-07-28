import { describe, expect, it } from "vitest";
import { appendFile, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  EMPTY_TREE_ROOT,
  MemoryTreeStore,
  TransparencyLog,
  JsonlTreeStore,
  leafHash,
  verifyConsistency,
  verifyInclusion,
} from "../src/index.js";

describe("TransparencyLog", () => {
  it("starts at the empty-tree root and grows append-only", async () => {
    const log = new TransparencyLog(new MemoryTreeStore());
    expect(await log.head()).toEqual({ treeSize: 0, rootHash: EMPTY_TREE_ROOT });

    const r0 = await log.appendLeaf("alpha");
    expect(r0.leafIndex).toBe(0);
    expect(r0.leafHash).toBe(leafHash("alpha"));
    expect(r0.head.treeSize).toBe(1);

    const r1 = await log.appendLeaf("beta");
    expect(r1.leafIndex).toBe(1);
    expect(r1.head.treeSize).toBe(2);
    expect(r1.head.rootHash).not.toBe(r0.head.rootHash);
  });

  it("serializes concurrent appends (no lost or duplicated indexes)", async () => {
    const log = new TransparencyLog(new MemoryTreeStore());
    const results = await Promise.all(
      Array.from({ length: 25 }, (_, i) => log.appendLeaf(`leaf-${i}`)),
    );
    const indexes = results.map((r) => r.leafIndex).sort((a, b) => a - b);
    expect(indexes).toEqual(Array.from({ length: 25 }, (_, i) => i));
    expect(await log.size()).toBe(25);
  });

  it("issues verifiable inclusion and consistency proofs end to end", async () => {
    const log = new TransparencyLog(new MemoryTreeStore());
    for (let i = 0; i < 10; i++) await log.appendLeaf(`entry-${i}`);
    const headA = await log.head();

    for (let i = 10; i < 17; i++) await log.appendLeaf(`entry-${i}`);
    const headB = await log.head();

    // Non-omission: entry-4 is committed under BOTH heads.
    const pA = await log.proveInclusion(4, headA.treeSize);
    const pB = await log.proveInclusion(4);
    expect(verifyInclusion(leafHash("entry-4"), pA, headA.rootHash)).toBe(true);
    expect(verifyInclusion(leafHash("entry-4"), pB, headB.rootHash)).toBe(true);

    // Append-only: headB extends headA.
    const cons = await log.proveConsistency(headA.treeSize, headB.treeSize);
    expect(verifyConsistency(headA.rootHash, headB.rootHash, cons)).toBe(true);

    // headAt reproduces the historical root.
    expect((await log.headAt(headA.treeSize)).rootHash).toBe(headA.rootHash);
  });

  it("appendLeaves builds the identical tree to one-by-one appends", async () => {
    const batch = new TransparencyLog(new MemoryTreeStore());
    const single = new TransparencyLog(new MemoryTreeStore());
    const leaves = Array.from({ length: 13 }, (_, i) => `bulk-${i}`);

    const r = await batch.appendLeaves(leaves);
    for (const l of leaves) await single.appendLeaf(l);

    expect(r.firstIndex).toBe(0);
    expect(r.appended).toBe(13);
    expect(r.head).toEqual(await single.head());

    // Batches compose with prior content.
    const r2 = await batch.appendLeaves(["tail-a", "tail-b"]);
    expect(r2.firstIndex).toBe(13);
    expect(r2.head.treeSize).toBe(15);
  });

  it("rejects out-of-range headAt / leafHashAt", async () => {
    const log = new TransparencyLog(new MemoryTreeStore());
    await log.appendLeaf("only");
    await expect(log.headAt(2)).rejects.toThrow(/out of range/);
    await expect(log.leafHashAt(1)).rejects.toThrow(/out of range/);
    await expect(log.leafHashAt(-1)).rejects.toThrow(/out of range/);
  });
});

describe("JsonlTreeStore", () => {
  it("persists leaves across instances and keeps proofs identical", async () => {
    const dir = await mkdtemp(join(tmpdir(), "swale-tree-"));
    const file = join(dir, "tree.leaves");
    try {
      const log1 = new TransparencyLog(new JsonlTreeStore(file));
      for (let i = 0; i < 9; i++) await log1.appendLeaf(`persist-${i}`);
      const head1 = await log1.head();

      // Fresh instance over the same file: identical tree.
      const log2 = new TransparencyLog(new JsonlTreeStore(file));
      expect(await log2.head()).toEqual(head1);
      const proof = await log2.proveInclusion(3);
      expect(verifyInclusion(leafHash("persist-3"), proof, head1.rootHash)).toBe(true);

      // Appends from the second instance continue the same tree.
      await log2.appendLeaf("persist-9");
      const cons = await log2.proveConsistency(head1.treeSize);
      expect(
        verifyConsistency(head1.rootHash, (await log2.head()).rootHash, cons),
      ).toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("repairs a torn tail: completes an unterminated hash, truncates garbage", async () => {
    const dir = await mkdtemp(join(tmpdir(), "swale-torn-"));
    try {
      // Case 1: the hash reached disk, the newline didn't.
      const f1 = join(dir, "complete.leaves");
      const log1 = new TransparencyLog(new JsonlTreeStore(f1));
      await log1.appendLeaf("a");
      await log1.appendLeaf("b");
      const head1 = await log1.head();
      const raw = await readFile(f1, "utf8");
      await writeFile(f1, raw.slice(0, -1), "utf8"); // strip final \n

      const re1 = new TransparencyLog(new JsonlTreeStore(f1));
      expect(await re1.head()).toEqual(head1); // repaired, nothing lost
      await re1.appendLeaf("c"); // and appends stay well-formed
      expect((await readFile(f1, "utf8")).endsWith("\n")).toBe(true);
      expect(await re1.size()).toBe(3);

      // Case 2: partial garbage after the last complete line is truncated.
      const f2 = join(dir, "garbage.leaves");
      const log2 = new TransparencyLog(new JsonlTreeStore(f2));
      await log2.appendLeaf("a");
      const head2 = await log2.head();
      await appendFile(f2, "deadbeef", "utf8"); // torn partial hash

      const re2 = new TransparencyLog(new JsonlTreeStore(f2));
      expect(await re2.head()).toEqual(head2); // garbage gone, prefix intact
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("fails closed on a malformed line in the MIDDLE of the file", async () => {
    const dir = await mkdtemp(join(tmpdir(), "swale-corrupt-"));
    try {
      const f = join(dir, "corrupt.leaves");
      const log = new TransparencyLog(new JsonlTreeStore(f));
      await log.appendLeaf("a");
      await log.appendLeaf("b");
      const lines = (await readFile(f, "utf8")).split("\n");
      lines[0] = "not-a-hash";
      await writeFile(f, lines.join("\n"), "utf8");

      const re = new TransparencyLog(new JsonlTreeStore(f));
      await expect(re.head()).rejects.toThrow(/corrupted/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("refuses to append a non-hash leaf line", async () => {
    const dir = await mkdtemp(join(tmpdir(), "swale-badleaf-"));
    try {
      const store = new JsonlTreeStore(join(dir, "t.leaves"));
      await expect(store.append("not-hex")).rejects.toThrow(/refusing/);
      await expect(store.append("AB".repeat(32))).rejects.toThrow(/refusing/); // uppercase
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
