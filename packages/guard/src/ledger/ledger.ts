import { canonicalJson, sha256Hex } from "./hash.js";

export type LedgerEntryType =
  | "intent_received"
  | "policy_decision"
  | "approval_requested"
  | "approval_resolved"
  | "mandate_issued"
  | "mandate_consumed"
  | "mandate_replayed"
  | "mandate_revoked"
  | "mandate_unsuspended"
  | "mandate_index_assigned"
  | "agent_revoked"
  | "agent_revoke_partial"
  | "agent_unblocked"
  | "revocation_fanout"
  | "status_list_published"
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

/** The chain tip a store reports back to a losing writer. */
export interface LedgerTip {
  seq: number;
  hash: string;
}

/**
 * The tip a writer believes it is extending. `prevSeq: -1` with the genesis
 * hash means "I believe the ledger is empty".
 */
export interface ExpectedTip {
  prevSeq: number;
  prevHash: string;
}

export type LedgerAppendResult =
  | { ok: true }
  | { ok: false; tip: LedgerTip | null };

/**
 * Storage contract: COMPARE-AND-APPEND (breaking change in 0.3.0).
 *
 * `append` must atomically compare the store's current tip against `expected`
 * and persist the entry ONLY on a match; on a mismatch it reports the real tip
 * so the caller can re-chain and retry. "Atomically" is the load-bearing word:
 * a store that checks the tip, suspends, then writes has reimplemented the
 * check-then-act race this contract exists to kill — two writers both extend
 * seq N and the chain forks. How atomicity is achieved is per-backend (a
 * synchronous body, a file lock, a UNIQUE constraint); that it is achieved is
 * the contract.
 *
 * Hashing stays CLIENT-SIDE — the entry arrives fully hashed. A store that
 * assigned seq/prevHash would also have to compute the hash, and server-side
 * hashing is exactly what makes server-side tampering undetectable.
 *
 * A pre-0.3.0 store (`append(entry): Promise<void>`) no longer satisfies this
 * interface. AuditLedger REFUSES such a store at runtime rather than letting
 * it run unsafely: an unchecked bare append is indistinguishable from the
 * fork-on-concurrency bug this contract replaced.
 */
export interface LedgerStore {
  append(entry: LedgerEntry, expected: ExpectedTip): Promise<LedgerAppendResult>;
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
 * Every failed compare-and-append means another writer committed since our
 * last look at the tip, so the bound is really "how many rival commits we
 * absorb before declaring the peer too hot and failing closed". 32 clears the
 * heaviest conformance burst (30 rival commits) with margin; a writer that
 * loses more than that in one append is contending with something better
 * served by fewer writers, and the failure surfaces as AUDIT_WRITE_FAILED.
 */
const MAX_APPEND_ATTEMPTS = 32;

/**
 * Append-only, hash-chained audit ledger ("flight recorder").
 * Each entry commits to the previous entry's hash, so any mutation,
 * deletion, or reordering of history is detectable by verify().
 *
 * Concurrent writers — several callers of one instance, several instances
 * over one store, or several processes — keep the chain linear (since 0.3.0):
 * the store's compare-and-append admits an entry only if the tip it chains
 * onto is still the tip, and a losing writer re-reads and retries a bounded
 * number of times before failing CLOSED. Residual limits live with each
 * store, not here: JsonlLedgerStore inherits FileMutex's stale-lock window,
 * and pre-0.3.0 third-party stores are refused outright (see LedgerStore).
 *
 * The per-instance queue below is a fairness measure, not the safety
 * mechanism: it stops one instance's own callers from burning the retry
 * budget against each other.
 *
 * A retried append recomputes its timestamp, so an entry's timestamp is taken
 * after its parent was durably committed — monotonic along the chain on one
 * clock. Across machines, clock skew can still produce out-of-order
 * timestamps; seq is the order of record, timestamps are informational
 * (SECURITY-MODEL item 10).
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
      const first = await this.store.last();
      let tip: LedgerTip | null = first
        ? { seq: first.seq, hash: first.hash }
        : null;
      for (let attempt = 0; attempt < MAX_APPEND_ATTEMPTS; attempt += 1) {
        const seq = tip ? tip.seq + 1 : 0;
        const prevHash = tip ? tip.hash : GENESIS_HASH;
        const partial: Omit<LedgerEntry, "hash"> = {
          seq,
          // Inside the loop on purpose: the hash commits to the timestamp, so
          // a retry must restamp — reusing the first attempt's clock reading
          // would backdate the entry relative to the parent it now chains to.
          timestamp: this.now().toISOString(),
          type,
          ...(refs.intentId !== undefined ? { intentId: refs.intentId } : {}),
          ...(refs.agentId !== undefined ? { agentId: refs.agentId } : {}),
          data,
          prevHash,
        };
        const entry: LedgerEntry = { ...partial, hash: entryHash(partial) };
        const result = (await this.store.append(entry, {
          prevSeq: seq - 1,
          prevHash,
        })) as LedgerAppendResult | undefined;
        // A pre-0.3.0 store returns undefined here: it appended WITHOUT
        // comparing, which is the fork bug. Refuse loudly — the guard treats
        // this as AUDIT_WRITE_FAILED and denies — instead of letting an
        // outdated store silently be the unsafe path.
        if (!result || typeof result.ok !== "boolean") {
          throw new Error(
            "AuditLedger.append: store did not return a compare-and-append " +
              "result — it predates the 0.3.0 LedgerStore contract and would " +
              "fork under a second writer; update the store implementation",
          );
        }
        if (result.ok) return entry;
        tip = result.tip;
      }
      throw new Error(
        `AuditLedger.append: lost the tip race ${MAX_APPEND_ATTEMPTS} times ` +
          "(a rival writer is committing faster than this one can re-chain); " +
          "failing closed",
      );
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
   *
   * REFUSES a chain whose entry count disagrees with its tip seq. A retained
   * head is the operator's trust anchor; issuing one over a forked chain
   * (duplicate seqs from a second writer) would launder the fork into the
   * anchor itself and bless whatever verify() later reads as "the" history.
   */
  async head(): Promise<LedgerHead> {
    const entries = await this.store.all();
    const last = entries.length > 0 ? entries[entries.length - 1]! : null;
    if (last && entries.length !== last.seq + 1) {
      throw new Error(
        `head() refused: ${entries.length} entries but tip seq ${last.seq} — ` +
          "chain is forked or truncated (concurrent writers?); run verify() " +
          "and repair before retaining a head",
      );
    }
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
      // A duplicated (or regressed) seq and a gap are DIFFERENT events and an
      // operator acts differently on each: seq <= prevSeq means two writers
      // both extended the same parent — a fork, our own race — while
      // seq > prevSeq + 1 means entries are missing — deletion-shaped
      // tampering. Reporting a fork as a "gap" misdiagnoses an honest ledger
      // as tampered-by-deletion, which is how a forensic trail gets discarded.
      if (entry.seq <= prevSeq) {
        return {
          ok: false,
          entries: entries.length,
          firstBadSeq: entry.seq,
          problem: `duplicate or regressed seq: expected ${prevSeq + 1}, got ${entry.seq} (fork — a second writer, not a deletion)`,
        };
      }
      if (entry.seq > prevSeq + 1) {
        return {
          ok: false,
          entries: entries.length,
          firstBadSeq: entry.seq,
          problem: `sequence gap: expected ${prevSeq + 1}, got ${entry.seq} (entries missing)`,
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
