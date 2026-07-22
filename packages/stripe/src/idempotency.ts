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

/** In-memory decision store with a TTL (single process). */
export class MemoryDecisionStore implements DecisionStore {
  private readonly map = new Map<string, { record: DecisionRecord; expiresMs: number }>();

  constructor(
    private readonly ttlMs: number = 10 * 60 * 1000,
    private readonly now: () => number = () => Date.now(),
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
    this.map.set(authId, { record, expiresMs: this.now() + this.ttlMs });
  }
}
