import { canonicalJson, sha256Hex } from "./hash.js";

export type LedgerEntryType =
  | "intent_received"
  | "policy_decision"
  | "approval_requested"
  | "approval_resolved"
  | "mandate_issued"
  | "mandate_consumed"
  | "mandate_revoked"
  | "execution_started"
  | "execution_result"
  | "policy_updated"
  | "guard_frozen"
  | "guard_unfrozen";

export interface LedgerEntry {
  seq: number;
  timestamp: string;
  type: LedgerEntryType;
  intentId?: string;
  agentId?: string;
  data: unknown;
  prevHash: string;
  hash: string;
}

export interface LedgerStore {
  append(entry: LedgerEntry): Promise<void>;
  last(): Promise<LedgerEntry | null>;
  all(): Promise<LedgerEntry[]>;
}

export const GENESIS_HASH = "0".repeat(64);

export interface VerifyResult {
  ok: boolean;
  entries: number;
  /** Sequence number of the first bad entry, if any. */
  firstBadSeq?: number;
  problem?: string;
}

/** Independent commitment to the chain's current tip. */
export interface LedgerHead {
  seq: number;
  hash: string;
  entries: number;
}

/**
 * Evidence bundle for a single intent: its ordered trail plus a local
 * verification of the whole chain it lives in.
 */
export interface EvidenceBundle {
  intentId: string;
  entries: LedgerEntry[];
  chain: VerifyResult;
}

function entryHash(entry: Omit<LedgerEntry, "hash">): string {
  return sha256Hex(canonicalJson(entry));
}

/**
 * Append-only, hash-chained audit ledger ("flight recorder").
 * Each entry commits to the previous entry's hash, so any mutation,
 * deletion, or reordering of history is detectable by verify().
 *
 * Appends are serialized through an internal queue: callers may append
 * concurrently, the chain stays linear.
 */
export class AuditLedger {
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly store: LedgerStore,
    private readonly now: () => Date = () => new Date(),
  ) {}

  append(
    type: LedgerEntryType,
    data: unknown,
    refs: { intentId?: string; agentId?: string } = {},
  ): Promise<LedgerEntry> {
    const task = this.queue.then(async () => {
      const last = await this.store.last();
      const seq = last ? last.seq + 1 : 0;
      const prevHash = last ? last.hash : GENESIS_HASH;
      const partial: Omit<LedgerEntry, "hash"> = {
        seq,
        timestamp: this.now().toISOString(),
        type,
        ...(refs.intentId !== undefined ? { intentId: refs.intentId } : {}),
        ...(refs.agentId !== undefined ? { agentId: refs.agentId } : {}),
        data,
        prevHash,
      };
      const entry: LedgerEntry = { ...partial, hash: entryHash(partial) };
      await this.store.append(entry);
      return entry;
    });
    // Keep the queue alive even if a caller's append fails.
    this.queue = task.catch(() => undefined);
    return task;
  }

  all(): Promise<LedgerEntry[]> {
    return this.store.all();
  }

  /** Every entry tagged with the given intentId, in sequence order. */
  async trailFor(intentId: string): Promise<LedgerEntry[]> {
    const entries = await this.store.all();
    return entries.filter((e) => e.intentId === intentId);
  }

  /**
   * Evidence bundle for one intent: its trail plus a full-chain verification,
   * suitable for export to a dispute/representment packet.
   */
  async exportEvidence(intentId: string): Promise<EvidenceBundle> {
    const [entries, chain] = await Promise.all([
      this.trailFor(intentId),
      this.verify(),
    ]);
    return { intentId, entries, chain };
  }

  /**
   * Current chain tip. Retain this out-of-band (e.g. print it, store it
   * elsewhere) and pass it to `verify(expected)` later: a store that rewrites
   * or truncates its own history cannot reproduce a head it never saw, so
   * external retention closes the "store controls all rows" gap.
   */
  async head(): Promise<LedgerHead> {
    const entries = await this.store.all();
    const last = entries.length > 0 ? entries[entries.length - 1]! : null;
    return {
      seq: last ? last.seq : -1,
      hash: last ? last.hash : GENESIS_HASH,
      entries: entries.length,
    };
  }

  /**
   * Re-derive every hash and link; O(n). If `expected` is provided, also
   * assert the chain still ends at that retained head (detects truncation or
   * wholesale rewrite that an internally-consistent forged chain would pass).
   */
  async verify(expected?: LedgerHead): Promise<VerifyResult> {
    const entries = await this.store.all();
    let prevHash = GENESIS_HASH;
    let prevSeq = -1;
    for (const entry of entries) {
      if (entry.seq !== prevSeq + 1) {
        return {
          ok: false,
          entries: entries.length,
          firstBadSeq: entry.seq,
          problem: `sequence gap: expected ${prevSeq + 1}, got ${entry.seq}`,
        };
      }
      if (entry.prevHash !== prevHash) {
        return {
          ok: false,
          entries: entries.length,
          firstBadSeq: entry.seq,
          problem: "prevHash does not match previous entry's hash (chain broken)",
        };
      }
      const { hash, ...rest } = entry;
      // A non-canonicalizable entry (e.g. planted with pathological nesting)
      // is treated as tampered, not allowed to throw out of the verifier.
      let recomputed: string;
      try {
        recomputed = entryHash(rest);
      } catch {
        return {
          ok: false,
          entries: entries.length,
          firstBadSeq: entry.seq,
          problem: "entry is not canonicalizable (rejected)",
        };
      }
      if (recomputed !== hash) {
        return {
          ok: false,
          entries: entries.length,
          firstBadSeq: entry.seq,
          problem: "entry hash does not match entry contents (tampered)",
        };
      }
      prevHash = hash;
      prevSeq = entry.seq;
    }
    if (expected) {
      if (entries.length !== expected.entries || prevHash !== expected.hash) {
        return {
          ok: false,
          entries: entries.length,
          problem: `chain tip (seq ${prevSeq}, ${entries.length} entries) does not match retained head (seq ${expected.seq}, ${expected.entries} entries) — truncated or rewritten`,
        };
      }
    }
    return { ok: true, entries: entries.length };
  }
}
