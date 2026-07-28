import type { GuardResult, PolicyResult } from "@vaduno/guard";

/** Thrown when policy/mandate/freeze blocked the payment (money never moved). */
export class X402PaymentBlockedError extends Error {
  readonly policyResult: PolicyResult;
  readonly status: GuardResult<unknown>["status"];
  constructor(result: Extract<GuardResult<unknown>, { status: "denied" | "approval_rejected" }>) {
    const codes = result.policyResult.reasons.map((r) => r.code).join(", ");
    super(`x402 payment blocked (${result.status}): ${codes}`);
    this.name = "X402PaymentBlockedError";
    this.policyResult = result.policyResult;
    this.status = result.status;
  }
}

/**
 * Thrown when a requirement was refused BEFORE any payment was attempted —
 * no acceptable requirement selected, an asset not on the trusted registry, or
 * a resource-origin mismatch. The payer never ran; money did not move.
 */
export class X402RequirementRefusedError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(`x402 requirement refused (${code}): ${message}`);
    this.name = "X402RequirementRefusedError";
    this.code = code;
  }
}

/**
 * Thrown when the payer ran (an X-PAYMENT was transmitted) but the server did
 * not return a success response. IMPORTANT: because X-PAYMENT is a bearer
 * authorization the server can still settle, the spend is counted anyway —
 * funds may have moved. Bind a consume-once mandate to bound retries.
 */
export class X402PaymentFailedError extends Error {
  /** True when an authorization was transmitted (funds may have settled). */
  readonly transmitted: boolean;
  constructor(detail: string, transmitted = false) {
    super(`x402 payment failed: ${detail}`);
    this.name = "X402PaymentFailedError";
    this.transmitted = transmitted;
  }
}
