import { canonicalJson, sha256Hex } from "../ledger/hash.js";
import type { PaymentIntent } from "../types.js";

/**
 * Runtime mandate enforcement: the machinery that turns "consume-once,
 * time-bound, context-bound" from a signed CLAIM into an enforced RUNTIME
 * property. A validly-signed mandate can still be executed twice by a retry
 * loop, raced by two concurrent workers, or misapplied in a multi-hop
 * orchestration — unless something on the execution path atomically claims
 * each use and idempotently replays the original outcome on duplicates.
 * (See ZTRV/APEX: signature-only verification intercepts 0% of replays;
 * an atomic consume registry intercepts 100%.)
 *
 * The registry is keyed on (mandateId, useKey) where useKey is the intent id:
 * the same payment retried maps to ONE use and ONE outcome; a different
 * payment sneaking in under a used key is caught by the intent digest.
 */

/** Digest of the money-affecting fields a claim covers. A replayed useKey
 * whose digest differs is a DIFFERENT payment wearing the same id — denied,
 * never replayed, never executed. */
export function intentDigest(intent: PaymentIntent): string {
  return sha256Hex(
    "paygent-consume-digest/v1\n" +
      canonicalJson({
        amountMinor: intent.amount.amountMinor,
        currency: intent.amount.currency,
        merchantId: intent.merchant.id,
        merchantUrl: intent.merchant.url ?? null,
        rail: intent.rail,
        mandateId: intent.mandateId ?? null,
      }),
  );
}

/** Total claims allowed during hydration replay — history already passed the
 * budget gate, so rebuilds must never be rejected as exhausted. */
export const UNBOUNDED_USES = Number.MAX_SAFE_INTEGER;

/** Terminal outcome of a claimed use, stored for idempotent replay. */
export interface StoredOutcome {
  /** "executed" = the rail ran; "failed" = the executor threw (money MAY
   * have moved — burn-on-failure). Denials never claim a use. */
  status: "executed" | "failed";
  settledAt: string;
  error?: string;
}

export interface UseClaim {
  mandateId: string;
  /** Idempotency key for this use — the intent id. */
  useKey: string;
  intentDigest: string;
  claimedAt: string;
  /** "pending" = claimed, outcome unknown (in flight or crashed). A pending
   * claim still counts as a use: over-hold, never overspend. */
  status: "pending" | "settled";
  outcome?: StoredOutcome;
}

export type ClaimResult =
  /** This call won the use; `used` = total claims against the mandate now. */
  | { winner: true; used: number }
  /** This exact (mandateId, useKey) was already claimed — replay `existing`. */
  | { winner: false; reason: "duplicate"; existing: UseClaim }
  /** The mandate's use budget was already full — deny (USES_EXHAUSTED). */
  | { winner: false; reason: "exhausted"; used: number };

/**
 * Atomic consume-once registry. The ONE correctness contract every
 * implementation must honor: within a SINGLE call, the duplicate check, the
 * `maxUses` budget check, and the insert happen atomically — across every
 * process sharing the store. So a mandate cannot be consumed more than
 * `maxUses` times even when N processes race with DIFFERENT intent ids, and a
 * retried intent id claims at most one use.
 *
 * `maxUses` is passed INTO claim() (not checked by the caller beforehand)
 * precisely so the count-check-insert is one atomic step under the store's
 * lock — a caller-side count-then-claim is a TOCTOU double-spend.
 */
export interface ConsumeStore {
  claim(claim: UseClaim, maxUses: number): Promise<ClaimResult>;
  /** Record the terminal outcome of a won claim (idempotent; first write wins). */
  settle(mandateId: string, useKey: string, outcome: StoredOutcome): Promise<void>;
  get(mandateId: string, useKey: string): Promise<UseClaim | null>;
  /** Total claims (pending + settled) against a mandate — its used count. */
  countClaims(mandateId: string): Promise<number>;
}

function key(mandateId: string, useKey: string): string {
  // Length-prefixed to make the composite key injective ("a|b|c" ambiguity).
  return `${mandateId.length}:${mandateId}:${useKey}`;
}

/** In-memory store — single-process agents, tests, demos. Every method body
 * runs to completion without an await, so the JS event loop makes claim()
 * atomic for free. */
export class MemoryConsumeStore implements ConsumeStore {
  private readonly claims = new Map<string, UseClaim>();

  async claim(claim: UseClaim, maxUses: number): Promise<ClaimResult> {
    const k = key(claim.mandateId, claim.useKey);
    const existing = this.claims.get(k);
    if (existing) return { winner: false, reason: "duplicate", existing: { ...existing } };
    // Count + check + insert with no intervening await — atomic on one thread.
    let used = 0;
    for (const c of this.claims.values()) {
      if (c.mandateId === claim.mandateId) used += 1;
    }
    if (used >= maxUses) return { winner: false, reason: "exhausted", used };
    this.claims.set(k, { ...claim, status: "pending" });
    return { winner: true, used: used + 1 };
  }

  async settle(mandateId: string, useKey: string, outcome: StoredOutcome): Promise<void> {
    const k = key(mandateId, useKey);
    const existing = this.claims.get(k);
    // Settle only a claim that exists and has no outcome yet: first write wins.
    if (!existing || existing.status === "settled") return;
    this.claims.set(k, { ...existing, status: "settled", outcome });
  }

  async get(mandateId: string, useKey: string): Promise<UseClaim | null> {
    const existing = this.claims.get(key(mandateId, useKey));
    return existing ? { ...existing } : null;
  }

  async countClaims(mandateId: string): Promise<number> {
    let n = 0;
    for (const c of this.claims.values()) {
      if (c.mandateId === mandateId) n += 1;
    }
    return n;
  }
}
