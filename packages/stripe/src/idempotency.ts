import type { StripeHandlerResponse } from "./handler.js";

export interface DecisionRecord {
  response: StripeHandlerResponse;
  decidedAt: string;
}

/**
 * Remembers the decision made for a given authorization id, so a retried
 * webhook delivery returns the SAME answer and never double-counts the spend.
 */
export interface DecisionStore {
  get(authId: string): Promise<DecisionRecord | null>;
  set(authId: string, record: DecisionRecord): Promise<void>;
}

/**
 * In-memory decision store with a TTL AND a hard size cap (single process).
 * Authorization ids are one-shot and unique, so lazy get()-time deletion alone
 * would leak memory in a long-running webhook process — set() also sweeps
 * expired entries and evicts oldest-first past the cap. For multi-instance or
 * very high volume, back DecisionStore with a bounded external store.
 */
export class MemoryDecisionStore implements DecisionStore {
  private readonly map = new Map<string, { record: DecisionRecord; expiresMs: number }>();

  constructor(
    private readonly ttlMs: number = 10 * 60 * 1000,
    private readonly now: () => number = () => Date.now(),
    private readonly maxEntries: number = 10_000,
  ) {}

  async get(authId: string): Promise<DecisionRecord | null> {
    const hit = this.map.get(authId);
    if (!hit) return null;
    if (this.now() > hit.expiresMs) {
      this.map.delete(authId);
      return null;
    }
    return hit.record;
  }

  async set(authId: string, record: DecisionRecord): Promise<void> {
    const t = this.now();
    // Opportunistically drop a bounded batch of expired entries.
    let swept = 0;
    for (const [k, v] of this.map) {
      if (v.expiresMs <= t) {
        this.map.delete(k);
        if (++swept >= 64) break;
      }
    }
    this.map.set(authId, { record, expiresMs: t + this.ttlMs });
    // Hard cap: evict oldest-inserted (Map preserves insertion order).
    while (this.map.size > this.maxEntries) {
      const oldest = this.map.keys().next().value;
      if (oldest === undefined) break;
      this.map.delete(oldest);
    }
  }
}
