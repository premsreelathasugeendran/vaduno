import type {
  ApprovalHandler,
  ApprovalResponse,
  Money,
  MerchantRef,
  PolicyReason,
} from "../types.js";

/** A payment waiting for a human decision, as surfaced to an approval UI. */
export interface PendingApproval {
  intentId: string;
  agentId: string;
  amount: Money;
  merchant: MerchantRef;
  policyReasons: PolicyReason[];
  requestedAt: string;
}

export interface ApprovalDecision extends ApprovalResponse {
  decidedAt: string;
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
    await store.enqueue({
      intentId: req.intent.id,
      agentId: req.intent.agentId,
      amount: req.intent.amount,
      merchant: req.intent.merchant,
      policyReasons: req.policyResult.reasons,
      requestedAt: req.requestedAt,
    });

    const deadline = now().getTime() + timeoutMs;
    for (;;) {
      const decision = await store.getDecision(req.intent.id);
      if (decision) return toResponse(decision);
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
    this.decisions.set(intentId, {
      ...response,
      decidedAt: this.now().toISOString(),
    });
    this.pending.delete(intentId);
  }

  async getDecision(intentId: string): Promise<ApprovalDecision | null> {
    return this.decisions.get(intentId) ?? null;
  }
}
