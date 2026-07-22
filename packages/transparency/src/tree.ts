import {
  EMPTY_TREE_ROOT,
  ProofError,
  leafHash,
  proveConsistency,
  proveInclusion,
  rootFromLeafHashes,
  type ConsistencyProof,
  type InclusionProof,
} from "./merkle.js";

/**
 * Storage for the log's leaf hashes, in append order. Like LedgerStore this
 * is intentionally minimal: the tree math re-derives everything from the
 * ordered leaf-hash list, so a store cannot corrupt structure — only content,
 * which proofs then expose.
 */
export interface TreeStore {
  append(leafHashHex: string): Promise<void>;
  all(): Promise<string[]>;
}

/** In-memory store — tests, demos, ephemeral agents. */
export class MemoryTreeStore implements TreeStore {
  private hashes: string[] = [];

  async append(leafHashHex: string): Promise<void> {
    this.hashes.push(leafHashHex);
  }

  async all(): Promise<string[]> {
    return [...this.hashes];
  }
}

export interface TreeHead {
  treeSize: number;
  rootHash: string;
}

export interface AppendResult {
  leafIndex: number;
  leafHash: string;
  head: TreeHead;
}

export interface BatchAppendResult {
  /** Index of the first appended leaf (== tree size before the batch). */
  firstIndex: number;
  appended: number;
  head: TreeHead;
}

/**
 * An RFC 9162 append-only Merkle transparency log over arbitrary leaf bytes.
 *
 * What it adds over a bare hash chain: an INCLUSION proof shows a specific
 * record is committed under a published root (proof of non-omission), and a
 * CONSISTENCY proof shows a later root extends an earlier one append-only
 * (nothing was rewritten or dropped in between). Both are verifiable by a
 * third party from the roots alone.
 *
 * Appends are serialized through an internal queue, mirroring AuditLedger.
 */
export class TransparencyLog {
  private queue: Promise<unknown> = Promise.resolve();

  constructor(private readonly store: TreeStore) {}

  /** Hash `data` as a leaf and append it. Returns its index and the new head. */
  async appendLeaf(data: Uint8Array | string): Promise<AppendResult> {
    const hash = leafHash(data);
    const batch = await this.appendLeaves([data]);
    return { leafIndex: batch.firstIndex, leafHash: hash, head: batch.head };
  }

  /**
   * Append many leaves as one serialized operation, recomputing the root ONCE
   * at the end — O(k + n) instead of k root computations. Use this to mirror
   * a backlog (a first sync over an existing ledger).
   */
  appendLeaves(datas: ReadonlyArray<Uint8Array | string>): Promise<BatchAppendResult> {
    // Hash before entering the queue so a bad leaf cannot leave a partial batch.
    const hashes = datas.map((d) => leafHash(d));
    const task = this.queue.then(async () => {
      const before = (await this.store.all()).length;
      for (const h of hashes) {
        await this.store.append(h);
      }
      const all = await this.store.all();
      return {
        firstIndex: before,
        appended: hashes.length,
        head: { treeSize: all.length, rootHash: rootFromLeafHashes(all) },
      };
    });
    this.queue = task.catch(() => undefined);
    return task;
  }

  async size(): Promise<number> {
    return (await this.store.all()).length;
  }

  /** Current tree head; root of the empty tree when no leaves exist. */
  async head(): Promise<TreeHead> {
    const hashes = await this.store.all();
    return { treeSize: hashes.length, rootHash: rootFromLeafHashes(hashes) };
  }

  /** Head as of an earlier size (for historical consistency checks). */
  async headAt(treeSize: number): Promise<TreeHead> {
    const hashes = await this.store.all();
    if (treeSize < 0 || treeSize > hashes.length) {
      throw new ProofError(`tree size ${treeSize} out of range (have ${hashes.length})`);
    }
    return { treeSize, rootHash: rootFromLeafHashes(hashes, treeSize) };
  }

  /** Leaf hash at an index (to hand to a verifier alongside a proof). */
  async leafHashAt(leafIndex: number): Promise<string> {
    const hashes = await this.store.all();
    const h = hashes[leafIndex];
    if (!Number.isInteger(leafIndex) || leafIndex < 0 || h === undefined) {
      throw new ProofError(`leaf index ${leafIndex} out of range (have ${hashes.length})`);
    }
    return h;
  }

  /** Inclusion proof for a leaf, against the current or a historical size. */
  async proveInclusion(leafIndex: number, treeSize?: number): Promise<InclusionProof> {
    const hashes = await this.store.all();
    return proveInclusion(hashes, leafIndex, treeSize);
  }

  /** Consistency proof between two sizes of this log. */
  async proveConsistency(first: number, second?: number): Promise<ConsistencyProof> {
    const hashes = await this.store.all();
    return proveConsistency(hashes, first, second ?? hashes.length);
  }
}

export { EMPTY_TREE_ROOT };
