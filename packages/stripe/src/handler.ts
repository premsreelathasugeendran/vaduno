import type { VadunoGuard, GuardStatus, PolicyReason } from "@vaduno/guard";
import { authorizationToIntent } from "./intent.js";
import { MemoryDecisionStore, type DecisionStore } from "./idempotency.js";
import type {
  StripeAuthorization,
  StripeEvent,
  StripeWebhooksLike,
} from "./types.js";

export interface StripeHandlerResponse {
  status: number;
  body: string;
  headers: Record<string, string>;
}

export interface StripeAuthorizationHandlerOptions {
  guard: VadunoGuard;
  /** The consumer's Stripe client — only `.webhooks.constructEvent` is used. */
  stripe: { webhooks: StripeWebhooksLike };
  /** Your webhook signing secret (whsec_…). */
  webhookSecret: string;
  /**
   * Echoed as the `Stripe-Version` response header — REQUIRED and must be a
   * currently-valid version matching your account/SDK, or Stripe treats the
   * response as a webhook_error and applies the account default instead of
   * your decision.
   */
  apiVersion: string;
  agentIdFor?: (auth: StripeAuthorization) => string;
  category?: string;
  mandateIdFor?: (auth: StripeAuthorization) => string | undefined;
  /** Dedupe by authorization id so a retried delivery can't double-count. */
  idempotencyStore?: DecisionStore;
  /**
   * Hard cap on how long the decision may take before the adapter itself
   * emits an in-window fail-closed DECLINE (default 1300ms). One budget bounds
   * the WHOLE request path — the idempotency store's get(), guard.execute, and
   * the store's set() — so a decision lands inside Stripe's ~2s window even if
   * the ledger store OR the idempotency store is slow or hung; never depend on
   * the account default. The budget is a single timer armed when the request
   * arrives, and that timer is the only arbiter of expiry: once it fires, the
   * answer is a DECLINE — an approval computed after expiry is never honoured,
   * regardless of wall-clock/timer skew. A SLOW get() is treated as a cache
   * miss and the guard decides in the remaining budget; a get() that consumes
   * the whole budget declines with DECISION_TIMEOUT. A hung set() stops being
   * waited on (the write itself keeps running) so the computed decision still
   * reaches Stripe. NOTE: a require_approval verdict whose approval handler
   * blocks will hit this timeout and DECLINE (human approval cannot fit the
   * 2s window on this rail).
   */
  decisionTimeoutMs?: number;
  onDecision?: (d: {
    authId: string;
    approved: boolean;
    status: GuardStatus;
    reasons: PolicyReason[];
    auditDegraded: boolean;
  }) => void;
  /** Called for non-request events (…created/…updated, issuing_transaction.created). */
  onReconcile?: (event: StripeEvent) => void | Promise<void>;
  now?: () => Date;
}

const AUTH_REQUEST = "issuing_authorization.request";
const RECONCILE_TYPES = new Set([
  "issuing_authorization.created",
  "issuing_authorization.updated",
  "issuing_transaction.created",
]);

/**
 * Build a framework-agnostic webhook handler that makes Vaduno's guard the
 * real-time authorization brain for Stripe Issuing cards.
 *
 * On issuing_authorization.request it maps the Authorization to a PaymentIntent,
 * runs guard.execute with a NO-OP executor (Stripe moves the money the instant
 * we answer approved:true, so a guard verdict of "executed" IS the approval,
 * and the guard counts the spend for its rolling windows). The decision is
 * returned within Stripe's ~2s window and recorded in the hash-chained ledger.
 *
 * The request path NEVER throws and NEVER blocks past the deadline — the
 * idempotency store's get() and set() are raced against the same budget as
 * guard.execute, so even a HUNG external store cannot stall the answer into
 * Stripe's account default: any error or timeout fails closed to a decline
 * (a decision the guard already computed still reaches Stripe when only the
 * post-decision set() hangs). Concurrent duplicate deliveries of the
 * same authorization id are coalesced (single-flight) so the spend is counted
 * once and both deliveries get the same answer. For MULTI-INSTANCE deployments,
 * supply an idempotencyStore backed by an atomic (reserve/put-if-absent) store;
 * the default MemoryDecisionStore + single-flight covers one process.
 */
export function createStripeAuthorizationHandler(
  opts: StripeAuthorizationHandlerOptions,
): (rawBody: string | Buffer, signature: string) => Promise<StripeHandlerResponse> {
  const store = opts.idempotencyStore ?? new MemoryDecisionStore();
  const now = opts.now ?? (() => new Date());
  const deadlineMs = opts.decisionTimeoutMs ?? 1300;
  const inflight = new Map<string, Promise<StripeHandlerResponse>>();

  const received: StripeHandlerResponse = {
    status: 200,
    body: JSON.stringify({ received: true }),
    headers: { "Content-Type": "application/json" },
  };

  function respond(
    approved: boolean,
    status: GuardStatus,
    reasons: PolicyReason[],
    authId: string,
  ): StripeHandlerResponse {
    return {
      status: 200,
      headers: { "Content-Type": "application/json", "Stripe-Version": opts.apiVersion },
      body: JSON.stringify({
        approved,
        metadata: {
          vaduno_intent: authId,
          vaduno_decision: status,
          vaduno_reasons: reasons.map((r) => r.code).slice(0, 5).join(","),
        },
      }),
    };
  }

  async function decide(
    auth: StripeAuthorization,
    authId: string,
    deadline: RequestDeadline,
  ): Promise<StripeHandlerResponse> {
    let approved = false;
    let status: GuardStatus = "denied";
    let reasons: PolicyReason[] = [];
    let auditDegraded = false;

    try {
      const intent = authorizationToIntent(auth, {
        ...(opts.agentIdFor ? { agentIdFor: opts.agentIdFor } : {}),
        ...(opts.category !== undefined ? { category: opts.category } : {}),
        ...(opts.mandateIdFor ? { mandateIdFor: opts.mandateIdFor } : {}),
        now,
      });

      // Race the decision against the request's hard deadline (the SAME armed
      // timer that bounded the idempotency-store read before us) so we always
      // answer in-window. The no-op executor also throws once that timer has
      // fired, so a decision that lost the race is recorded by the guard as
      // "failed" (not counted / mandate not consumed) rather than a phantom
      // settled charge — consistent with the DECLINE we return to Stripe.
      // Both checks read deadline.expired — a flag set by the timer callback
      // itself, never a re-derived clock reading — so an approval can never
      // slip through on clock skew after the budget has ended.
      const timedOut = await deadline.race(
        opts.guard.execute(intent, async () => {
          if (deadline.expired) throw new Error("decision deadline exceeded");
          return { approved: true };
        }),
      );
      if (timedOut.timedOut) {
        approved = false;
        status = "failed";
        reasons = [{ code: "DECISION_TIMEOUT", message: `no decision within ${deadlineMs}ms` }];
      } else {
        const result = timedOut.result;
        status = result.status;
        approved = result.status === "executed";
        // "replayed" (this authorization already consumed its mandate use in a
        // prior attempt) carries no policyResult and stays DECLINED here — the
        // idempotency store serves the original answer for true webhook
        // retries; a replay reaching this point is declined fail-closed.
        reasons =
          "policyResult" in result && result.policyResult
            ? result.policyResult.reasons
            : [];
        auditDegraded = result.status === "executed" && result.auditDegraded === true;
      }
    } catch (err) {
      approved = false;
      status = "failed";
      reasons = [{ code: "STRIPE_ADAPTER_ERROR", message: err instanceof Error ? err.message : String(err) }];
    }

    const response = respond(approved, status, reasons, authId);
    // Bounded, NOT fire-and-forget: give the store whatever remains of the
    // window to record the decision (multi-instance retry dedupe reads it),
    // but never let a hung set() keep an already-computed answer from
    // reaching Stripe. The write itself keeps running after we stop waiting;
    // if it lands late, a retried delivery still finds it. If it never lands,
    // the guard's replay protection declines the retry fail-closed.
    await deadline.race(
      store.set(authId, { response, decidedAt: now().toISOString() }).catch(() => undefined),
    );
    // Observability must never flip a decision or blow the deadline.
    try {
      opts.onDecision?.({ authId, approved, status, reasons, auditDegraded });
    } catch {
      /* swallow */
    }
    return response;
  }

  return async function handle(rawBody, signature) {
    let event: StripeEvent;
    try {
      event = opts.stripe.webhooks.constructEvent(rawBody, signature, opts.webhookSecret);
    } catch (err) {
      // Bad signature / wrong secret. Stripe will retry; don't process.
      return {
        status: 400,
        body: `signature verification failed: ${err instanceof Error ? err.message : String(err)}`,
        headers: {},
      };
    }

    if (event.type !== AUTH_REQUEST) {
      if (RECONCILE_TYPES.has(event.type) && opts.onReconcile) {
        // Fully isolated: even a synchronous throw can't affect the ack.
        Promise.resolve()
          .then(() => opts.onReconcile!(event))
          .catch(() => undefined);
      }
      return received;
    }

    const auth = event.data.object as StripeAuthorization;
    const authId = typeof auth?.id === "string" ? auth.id : "(unknown)";

    // ONE deadline bounds the whole request path from here: a single timer,
    // armed BEFORE any awaitable work begins, is the sole arbiter of expiry.
    // The idempotency read, guard.execute, and the idempotency write all race
    // this same timer, so handle() answers in-window no matter which stage
    // stalls — and no stage can re-measure the budget on a different clock.
    const deadline = armDeadline(deadlineMs);
    try {
      // A decision already made for this id (prior completed delivery). A
      // store error is treated as a cache miss — the guard's replay protection
      // declines a true duplicate fail-closed downstream. A HUNG get() eats
      // the whole budget, so the deadline expires and the answer is a
      // fail-closed DECISION_TIMEOUT decline.
      const cachedRace = await deadline.race(store.get(authId).catch(() => null));
      const cached = cachedRace.timedOut ? null : cachedRace.result;
      if (cached) return cached.response;

      // Single-flight: coalesce concurrent duplicate deliveries of the same id
      // so guard.execute runs once and the spend is counted once.
      const existing = inflight.get(authId);
      if (existing) return existing;

      const task = decide(auth, authId, deadline);
      inflight.set(authId, task);
      try {
        return await task;
      } finally {
        inflight.delete(authId);
      }
    } finally {
      deadline.clear();
    }
  };
}

interface Decided<T> {
  timedOut: false;
  result: T;
}
interface TimedOut {
  timedOut: true;
}

/** One request's decision budget. `expired` is flipped by the timer callback
 *  itself and every stage races the same expiry, so "has the budget ended?"
 *  has exactly one answer for the whole request. */
interface RequestDeadline {
  /** True from the instant the deadline timer has fired. */
  readonly expired: boolean;
  /** Resolve with p's value if it settles before the deadline fires, else a
   *  timeout marker. A rejection is treated as a timeout (fail closed).
   *  Never rejects. p keeps running in the background after a timeout. */
  race<T>(p: Promise<T>): Promise<Decided<T> | TimedOut>;
  /** Disarm the timer once the request has been answered. */
  clear(): void;
}

/** Arm the request deadline. A SINGLE setTimeout decides when the budget ends;
 *  nothing re-derives expiry from Date.now(). (Timers fire on the event loop's
 *  monotonic clock, which can disagree with the wall clock by a millisecond or
 *  more under load — re-checking a wall-clock deadline after a timer fired is
 *  how an already-exhausted request once got APPROVED. One clock, one answer.) */
function armDeadline(ms: number): RequestDeadline {
  let expired = false;
  let signalExpiry!: () => void;
  const expiry = new Promise<void>((resolve) => {
    signalExpiry = resolve;
  });
  const timer = setTimeout(() => {
    expired = true;
    signalExpiry();
  }, ms);
  return {
    get expired() {
      return expired;
    },
    race<T>(p: Promise<T>): Promise<Decided<T> | TimedOut> {
      return Promise.race([
        p.then(
          (result) => ({ timedOut: false as const, result }),
          () => ({ timedOut: true as const }),
        ),
        expiry.then(() => ({ timedOut: true as const })),
      ]);
    },
    clear() {
      clearTimeout(timer);
    },
  };
}
