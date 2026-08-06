import type {
  ApprovalHandler,
  ApprovalResponse,
  Money,
  MerchantRef,
  PaymentIntent,
  PolicyReason,
} from "../types.js";
import { canonicalJson, sha256Hex } from "../ledger/hash.js";

/**
 * A binding fingerprint of the money-affecting fields of an intent. A human's
 * approval is tied to THIS fingerprint, so an agent cannot get a small payment
 * approved and then replay that approval to authorize a larger/different one
 * (the queued handler rejects a decision whose fingerprint doesn't match).
 *
 * INJECTIVE BY CONSTRUCTION, and it has to be. This used to `join("|")` over
 * raw attacker-controlled strings, so a merchant could move the separator:
 *
 *   {id: "shop",                     url: "https://good.com|https://evil.com"}
 *   {id: "shop|https://good.com",    url: "https://evil.com"}
 *
 * hashed identically — verified — which let one human approval cover a payment
 * to a DIFFERENT destination, with the real approver's name in the ledger
 * against it. The shipped approval UI renders `merchant.id` and not
 * `merchant.url`, so in the exploitable direction the approver sees a clean
 * name. Now domain-tagged + canonical JSON, the same construction
 * `intentDigest` uses; `canonicalJson` is injective and throws rather than
 * guessing, so no field can impersonate a separator.
 *
 * Changing the construction invalidates fingerprints cached by an approval
 * store across this upgrade: a stale decision no longer matches and the human
 * is asked again. That is the fail-closed direction, and deliberate.
 */
export function approvalFingerprint(
  intent: Pick<PaymentIntent, "amount" | "merchant" | "rail">,
): string {
  return sha256Hex(
    "vaduno-approval-fingerprint/v1\n" +
      canonicalJson({
        amountMinor: intent.amount.amountMinor,
        currency: intent.amount.currency.toUpperCase(),
        merchantId: intent.merchant.id,
        merchantUrl: intent.merchant.url ?? null,
        rail: intent.rail,
      }),
  );
}

/** A payment waiting for a human decision, as surfaced to an approval UI. */
export interface PendingApproval {
  intentId: string;
  agentId: string;
  amount: Money;
  merchant: MerchantRef;
  policyReasons: PolicyReason[];
  requestedAt: string;
  /** Binds the decision to the exact money fields (see approvalFingerprint). */
  fingerprint?: string;
}

export interface ApprovalDecision extends ApprovalResponse {
  decidedAt: string;
  fingerprint?: string;
}

/**
 * Shared queue that decouples "an agent is waiting for approval" from "a human
 * decides". An in-process guard enqueues here and polls for the decision; a
 * dashboard (sharing the same store) lists pending items and resolves them.
 */
export interface ApprovalStore {
  enqueue(pending: PendingApproval): Promise<void>;
  /** Items enqueued but not yet decided. */
  listPending(): Promise<PendingApproval[]>;
  resolve(intentId: string, response: ApprovalResponse): Promise<void>;
  getDecision(intentId: string): Promise<ApprovalDecision | null>;
}

export interface QueuedApprovalOptions {
  /** How often to poll for a decision. Default 1000ms. */
  pollMs?: number;
  /** Deny (fail closed) if no decision within this window. Default 300000ms. */
  timeoutMs?: number;
  now?: () => Date;
  /** Injectable sleep (for tests). */
  sleep?: (ms: number) => Promise<void>;
}

/**
 * Build an ApprovalHandler that enqueues each request into a shared store and
 * waits (by polling) for an out-of-band decision — e.g. from a dashboard. On
 * timeout it resolves the item as rejected and fails closed.
 *
 * The agent process stays alive during the wait (the handler is awaited inside
 * guard.execute); the decision itself can come from anywhere sharing the store.
 */
export function createQueuedApprovalHandler(
  store: ApprovalStore,
  options: QueuedApprovalOptions = {},
): ApprovalHandler {
  const pollMs = options.pollMs ?? 1000;
  const timeoutMs = options.timeoutMs ?? 300_000;
  const now = options.now ?? (() => new Date());
  const sleep =
    options.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));

  return async (req) => {
    const fingerprint = approvalFingerprint(req.intent);
    await store.enqueue({
      intentId: req.intent.id,
      agentId: req.intent.agentId,
      amount: req.intent.amount,
      merchant: req.intent.merchant,
      policyReasons: req.policyResult.reasons,
      requestedAt: req.requestedAt,
      fingerprint,
    });

    const deadline = now().getTime() + timeoutMs;
    for (;;) {
      const decision = await store.getDecision(req.intent.id);
      if (decision) {
        // Fail closed if the decision on file was made for a different payment
        // (replay of an approval to authorize a larger/different charge).
        if (decision.fingerprint !== fingerprint) {
          return { approved: false, note: "approval does not match this payment" };
        }
        return toResponse(decision);
      }
      if (now().getTime() >= deadline) {
        const timedOut: ApprovalResponse = {
          approved: false,
          note: "approval timed out",
        };
        await store.resolve(req.intent.id, timedOut);
        return timedOut;
      }
      await sleep(pollMs);
    }
  };
}

function toResponse(d: ApprovalDecision): ApprovalResponse {
  return {
    approved: d.approved,
    ...(d.approver !== undefined ? { approver: d.approver } : {}),
    ...(d.note !== undefined ? { note: d.note } : {}),
  };
}

/** In-memory ApprovalStore — single process (tests, demos, one-box deploys). */
export class MemoryApprovalStore implements ApprovalStore {
  private pending = new Map<string, PendingApproval>();
  private decisions = new Map<string, ApprovalDecision>();

  constructor(private readonly now: () => Date = () => new Date()) {}

  async enqueue(pending: PendingApproval): Promise<void> {
    if (!this.decisions.has(pending.intentId)) {
      this.pending.set(pending.intentId, pending);
    }
  }

  async listPending(): Promise<PendingApproval[]> {
    return [...this.pending.values()];
  }

  async resolve(intentId: string, response: ApprovalResponse): Promise<void> {
    // Same preconditions FileApprovalStore documents — surfaced by the shared
    // conformance suite, which this class previously FAILED on both counts:
    // only decide something currently pending (no decision can be planted for
    // an id no human was shown), and never overwrite an existing decision (a
    // late timeout must not clobber a human's call). Memory is the reference
    // implementation; it has to hold itself to the semantics it references.
    if (this.decisions.has(intentId)) return;
    const pending = this.pending.get(intentId);
    if (!pending) return;
    this.decisions.set(intentId, {
      ...response,
      decidedAt: this.now().toISOString(),
      ...(pending.fingerprint !== undefined
        ? { fingerprint: pending.fingerprint }
        : {}),
    });
    this.pending.delete(intentId);
  }

  async getDecision(intentId: string): Promise<ApprovalDecision | null> {
    return this.decisions.get(intentId) ?? null;
  }
}
