import { createPublicKey } from "node:crypto";
import {
  canonicalJson,
  LocalKeySigner,
  SignerError,
  type AuditLedger,
  type Ed25519Signer,
  type LedgerEntry,
} from "@vaduno/guard";
import { leafHash } from "./merkle.js";
import type { TransparencyLog, TreeHead } from "./tree.js";
import { signTreeHeadWith, type SignedTreeHead } from "./sth.js";

/**
 * Binds the guard's hash-chained AuditLedger to a Merkle transparency log.
 *
 * Each ledger entry becomes one leaf: leafHash(ledgerEntryLeaf(entry)). The
 * chain gives ordering + tamper-evidence; the tree adds what the chain
 * cannot: an inclusion proof that a given decision IS in the published
 * history (non-omission), and consistency proofs that published history only
 * ever grows. Sync after appends (e.g. once per executed intent, or on a
 * timer) and publish the returned signed head.
 *
 * sync() and audit() are serialized through an internal queue: overlapping
 * calls (a timer sync racing a per-intent sync) cannot double-append leaves
 * or observe a half-synced tree.
 */
export interface MirrorSyncResult {
  /** Entries newly added to the tree by this sync. */
  appended: number;
  head: TreeHead;
  /** Present when the mirror was constructed with signing config. */
  signedHead?: SignedTreeHead;
}

export interface MirrorAuditResult {
  ok: boolean;
  /** Number of leaves cross-checked against ledger entries. */
  checked: number;
  problem?: string;
}

export interface LedgerMirrorOptions {
  /**
   * When set, every sync() also signs and returns the new head. Pass EITHER a
   * `privateKeyPem` (in-process key) OR a `signer` (non-exportable KMS/HSM
   * capability) — never both. A legacy `privateKeyPem` is wrapped into a
   * `LocalKeySigner` at construction, so both configs share one signing path
   * with byte-identical output.
   */
  signing?: {
    logId: string;
    privateKeyPem?: string;
    signer?: Ed25519Signer;
    now?: () => Date;
    timeoutMs?: number;
  };
}

/**
 * The versioned leaf encoding for ledger entries. The tag pins the format:
 * if the entry schema or serialization ever changes, a new version tag keeps
 * old proofs verifiable against old leaves instead of breaking silently.
 * Note the leaf commits to the entry's canonical JSON VALUE (as the ledger
 * hash itself does), not to the JS object graph that produced it.
 */
const LEAF_VERSION = "vaduno-ledger-entry/v1\n";

export function ledgerEntryLeaf(entry: LedgerEntry): string {
  return LEAF_VERSION + canonicalJson(entry);
}

export class LedgerMirror {
  private queue: Promise<unknown> = Promise.resolve();
  /** Normalized signing config; null when the mirror does not sign heads. */
  private readonly signing: {
    logId: string;
    signer: Ed25519Signer;
    now?: () => Date;
    timeoutMs?: number;
  } | null;

  constructor(
    private readonly ledger: AuditLedger,
    private readonly tree: TransparencyLog,
    opts: LedgerMirrorOptions = {},
  ) {
    // Signing misconfiguration fails at CONSTRUCTION, not at first sync.
    if (opts.signing) {
      const { logId, privateKeyPem, signer, now, timeoutMs } = opts.signing;
      if (privateKeyPem && signer) {
        throw new SignerError("mirror signing config: pass privateKeyPem OR signer, not both");
      }
      if (!privateKeyPem && !signer) {
        throw new SignerError("mirror signing config: pass privateKeyPem or signer");
      }
      if (signer && signer.algorithm !== "Ed25519") {
        throw new SignerError(
          `mirror signing config: signer declares algorithm "${String(signer.algorithm)}"; only Ed25519 is supported`,
        );
      }
      let normalized: Ed25519Signer;
      if (signer) {
        // Read the declared key ONCE, refuse it here if it does not parse,
        // and FREEZE it: every signed head is verified against this snapshot,
        // so a backend that later rotates its declared key fails verification
        // (deny) instead of signing heads this deployment cannot verify.
        const declaredPem = signer.publicKeyPem;
        try {
          createPublicKey(declaredPem);
        } catch (err) {
          throw new SignerError(
            "mirror signing config: signer's declared publicKeyPem does not parse",
            { cause: err },
          );
        }
        normalized = { algorithm: "Ed25519", publicKeyPem: declaredPem, sign: (m) => signer.sign(m) };
      } else {
        normalized = new LocalKeySigner(privateKeyPem as string);
      }
      this.signing = {
        logId,
        signer: normalized,
        ...(now ? { now } : {}),
        ...(timeoutMs !== undefined ? { timeoutMs } : {}),
      };
    } else {
      this.signing = null;
    }
  }

  /** Serialize an operation behind every previously queued one. */
  private run<T>(op: () => Promise<T>): Promise<T> {
    const task = this.queue.then(op);
    this.queue = task.catch(() => undefined);
    return task;
  }

  /** Append any ledger entries not yet in the tree; returns the new head. */
  sync(): Promise<MirrorSyncResult> {
    return this.run(async () => {
      const entries = await this.ledger.all();
      const before = await this.tree.size();
      if (before > entries.length) {
        throw new Error(
          `transparency tree has ${before} leaves but ledger has ${entries.length} entries — tree and ledger have diverged`,
        );
      }
      const fresh = entries.slice(before).map((e) => ledgerEntryLeaf(e));
      let head: TreeHead;
      if (fresh.length > 0) {
        const batch = await this.tree.appendLeaves(fresh);
        // The tree is only written by this mirror; a shifted batch means
        // something else appended concurrently. Surface it — the tree can no
        // longer be trusted to mirror the ledger 1:1.
        if (batch.firstIndex !== before) {
          throw new Error(
            `batch landed at leaf ${batch.firstIndex}, expected ${before} — another writer appended to this tree`,
          );
        }
        head = batch.head;
      } else {
        head = await this.tree.head();
      }
      const result: MirrorSyncResult = { appended: fresh.length, head };
      if (this.signing) {
        // A signer failure REJECTS this sync — but the leaves are already
        // appended, and truthfully so (they mirror real ledger entries). The
        // next healthy sync signs the same root; a wedged signer delays
        // publication of NEW heads, it never forks or unwinds the tree.
        result.signedHead = await signTreeHeadWith(head, this.signing);
      }
      return result;
    });
  }

  /**
   * Cross-check EVERY tree leaf against the ledger entry at the same index.
   * O(n) — run on demand (verify endpoint, startup), not per request. Catches
   * a ledger rewritten after mirroring, or a tree that drifted from its
   * ledger. Serialized behind sync(), so it never observes a half-applied
   * batch.
   */
  audit(): Promise<MirrorAuditResult> {
    return this.run(async () => {
      const [entries, size] = await Promise.all([this.ledger.all(), this.tree.size()]);
      if (size > entries.length) {
        return {
          ok: false,
          checked: 0,
          problem: `tree has ${size} leaves but ledger has ${entries.length} entries`,
        };
      }
      for (let i = 0; i < size; i++) {
        let expected: string;
        try {
          expected = leafHash(ledgerEntryLeaf(entries[i]!));
        } catch {
          return {
            ok: false,
            checked: i,
            problem: `ledger entry seq ${entries[i]!.seq} is not canonicalizable`,
          };
        }
        if ((await this.tree.leafHashAt(i)) !== expected) {
          return {
            ok: false,
            checked: i,
            problem: `leaf ${i} does not match ledger entry seq ${entries[i]!.seq} (ledger or tree modified after mirroring)`,
          };
        }
      }
      return { ok: true, checked: size };
    });
  }

  /**
   * Inclusion proof that a specific ledger entry is committed under the
   * current (or a historical) published root. Verify with
   * `verifyInclusion(leafHash(ledgerEntryLeaf(entry)), proof, head.rootHash)`.
   */
  async proveEntry(seq: number, treeSize?: number) {
    return this.tree.proveInclusion(seq, treeSize);
  }
}
