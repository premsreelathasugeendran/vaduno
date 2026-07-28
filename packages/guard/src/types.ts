/**
 * Core types for @vaduno/guard.
 *
 * Money is ALWAYS an integer in the currency's minor unit (cents, paise).
 * Floats are never used for amounts.
 */

export interface Money {
  amountMinor: number;
  /** ISO 4217 code, uppercase (e.g. "USD", "INR"). */
  currency: string;
}

export interface MerchantRef {
  /** Stable identifier chosen by the integrator (e.g. "openai", "aws"). */
  id: string;
  name?: string;
  /** Full URL of the merchant/endpoint being paid, if applicable. */
  url?: string;
}

/**
 * A single payment an agent wants to make. This is the unit the guard
 * evaluates, records, and (if allowed) hands to the executor.
 */
export interface PaymentIntent {
  /** Unique id for this intent (integrator-generated; used for audit joins). */
  id: string;
  /** Which agent instance is asking to spend. */
  agentId: string;
  merchant: MerchantRef;
  amount: Money;
  /** Optional free-form category (e.g. "api-credits", "saas", "travel"). */
  category?: string;
  /** Which rail will execute this (e.g. "x402", "stripe-issuing", "upi", "mock"). */
  rail: string;
  /** Mandate this intent claims authorization under, if any. */
  mandateId?: string;
  /**
   * Task-context blob a context-bound mandate committed to (via
   * `mandateContextHash`). When the mandate carries a contextHash, this exact
   * object must hash to it — and its well-known fields (`agentId`,
   * `merchantId`) must match the intent — or the mandate is refused
   * (CONTEXT_MISMATCH). Binds a mandate to ONE approved task run, so a valid
   * mandate cannot be misapplied by a different orchestration hop.
   */
  context?: Record<string, unknown>;
  description?: string;
  metadata?: Record<string, unknown>;
  /** ISO timestamp set by the caller. */
  requestedAt: string;
}

export type PolicyDecision = "allow" | "deny" | "require_approval";

export interface PolicyReason {
  /** Machine-readable code, e.g. "PER_TXN_LIMIT_EXCEEDED". */
  code: string;
  message: string;
}

export interface PolicyResult {
  decision: PolicyDecision;
  reasons: PolicyReason[];
  policyId: string;
  policyVersion: number;
}

/**
 * Declarative spend policy. All checks are deterministic — no model calls.
 * Windows (day/week/month) are ROLLING: last 24h / 7d / 30d from "now".
 */
export interface SpendPolicy {
  id: string;
  version: number;
  /** Policy base currency. Intents in any other currency are denied (v0.1). */
  currency: string;
  limits?: {
    perTransactionMinor?: number;
    perDayMinor?: number;
    perWeekMinor?: number;
    perMonthMinor?: number;
  };
  merchants?: {
    /** If present, intent merchant must match one of these (id or exact host / dot-boundary subdomain). */
    allow?: string[];
    /** Always wins over allow. */
    block?: string[];
  };
  categories?: {
    allow?: string[];
    block?: string[];
  };
  rails?: {
    /** If present, intent.rail must be one of these. */
    allow?: string[];
  };
  approval?: {
    /** Amounts >= this require human approval. */
    aboveMinor?: number;
    /** Every transaction requires approval. */
    always?: boolean;
  };
  velocity?: {
    /** Max number of executed transactions within the window. */
    maxTransactions?: { count: number; perSeconds: number };
  };
  /** ISO timestamp after which the policy denies everything. */
  expiresAt?: string;
}

/**
 * Read-side interface the policy engine uses to enforce rolling windows.
 * Implementations must count only successfully executed spends.
 *
 * NOTE on `agentId`: the default ledger-backed implementation counts spend
 * GUARD-WIDE (across all agents) and ignores this argument, because
 * `agentId` is attacker-controlled — an agent that could reset its own cap by
 * rotating its id would make per-agent limits meaningless. Run one guard per
 * trust boundary. A custom implementation may key on agentId if the caller
 * guarantees agent identity by other means (e.g. requireMandate).
 */
export interface SpendHistory {
  totalsSince(
    agentId: string,
    sinceIso: string,
    currency: string,
  ): Promise<{ totalMinor: number; count: number }>;
}

export interface ApprovalRequest {
  intent: PaymentIntent;
  policyResult: PolicyResult;
  requestedAt: string;
}

export interface ApprovalResponse {
  approved: boolean;
  approver?: string;
  note?: string;
}

export type ApprovalHandler = (req: ApprovalRequest) => Promise<ApprovalResponse>;

export type GuardStatus =
  | "executed"
  | "denied"
  | "approval_rejected"
  | "failed"
  | "replayed";

/**
 * Discriminated on `status` so `value` and `error` narrow correctly:
 *  - "executed": the executor ran and returned `value`.
 *  - "denied": policy/mandate/freeze/internal-error blocked it; `error` is set
 *    only for internal errors.
 *  - "approval_rejected": a human declined.
 *  - "failed": the executor itself threw; `error` holds the message.
 *  - "replayed": this (mandate, intent id) was ALREADY consumed — the
 *    executor did NOT run again; `original` reports the first attempt's
 *    outcome ("unresolved" = the original claim never settled, e.g. a crash
 *    mid-execution — reconcile before retrying with a new intent).
 */
export type GuardResult<T> =
  | {
      status: "executed";
      intentId: string;
      policyResult: PolicyResult;
      value: T;
      /**
       * True when the charge executed and was counted, but persisting its
       * audit record to the ledger store failed. Spend limits stay correct
       * (an in-memory counter is authoritative), but the durable trail for
       * THIS payment is incomplete — an operator should reconcile.
       */
      auditDegraded?: boolean;
    }
  | {
      status: "denied";
      intentId: string;
      policyResult: PolicyResult;
      error?: string;
    }
  | {
      status: "approval_rejected";
      intentId: string;
      policyResult: PolicyResult;
    }
  | {
      status: "failed";
      intentId: string;
      policyResult?: PolicyResult;
      error: string;
    }
  | {
      status: "replayed";
      intentId: string;
      mandateId: string;
      original: {
        status: "executed" | "failed" | "unresolved";
        settledAt?: string;
        error?: string;
      };
    };
