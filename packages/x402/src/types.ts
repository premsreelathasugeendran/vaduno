/**
 * x402 protocol shapes (v1 and v2). See https://x402.org / the x402 spec.
 *
 * x402 revives HTTP 402 Payment Required. The two protocol versions differ in
 * CARRIER as well as shape:
 *
 *  - v1: the server answers 402 with a JSON BODY `{x402Version: 1, accepts:
 *    [...]}`; the client pays and retries with an `X-PAYMENT` header; the
 *    server settles and returns an `X-PAYMENT-RESPONSE` header.
 *  - v2: all protocol data moves to HEADERS. The 402 carries a
 *    `PAYMENT-REQUIRED` header (base64 JSON `PaymentRequired`); the client
 *    retries with `PAYMENT-SIGNATURE`; settlement comes back in
 *    `PAYMENT-RESPONSE`. The 402 body is a server implementation concern
 *    (the reference server sends `{}`).
 *
 * Vaduno sits at the "before you pay" moment: it turns the chosen requirement
 * into a PaymentIntent, runs it through the guard, and only lets your payer
 * sign if policy allows.
 */

export interface PaymentRequirements {
  /** Payment scheme, e.g. "exact". */
  scheme: string;
  /** Chain/network id, e.g. "base", "base-sepolia", "solana". */
  network: string;
  /** Required amount in the ASSET'S ATOMIC UNITS, as a decimal string. */
  maxAmountRequired: string;
  /** The resource URL being paid for. */
  resource: string;
  description?: string;
  mimeType?: string;
  /** Address that receives the funds. */
  payTo: string;
  maxTimeoutSeconds?: number;
  /** Token contract address (or asset identifier). */
  asset: string;
  /** Token metadata; `decimals`/`symbol` drive human-amount conversion. */
  extra?: {
    name?: string;
    version?: string;
    decimals?: number;
    symbol?: string;
  };
}

/** Body of a 402 response. */
export interface PaymentRequiredBody {
  x402Version: number;
  accepts: PaymentRequirements[];
  error?: string;
}

/**
 * Decoded settlement result (`X-PAYMENT-RESPONSE` in v1, `PAYMENT-RESPONSE`
 * in v2). The v2 shape adds `errorReason` (replacing v1's errorMessage) and an
 * optional `amount` — the ACTUAL settled atomic amount, which under the `upto`
 * scheme may be less than the authorized maximum. NOTE: this arrives from the
 * same untrusted server that demanded payment; Vaduno's pessimistic accounting
 * counts the authorized amount at transmit time and never reconciles downward
 * from this field.
 */
export interface SettlementResponse {
  success: boolean;
  transaction?: string;
  network?: string;
  payer?: string;
  errorReason?: string;
  /** v2: actual settled amount in atomic units (untrusted; informational). */
  amount?: string;
  [key: string]: unknown;
}

// ── v2 shapes ────────────────────────────────────────────────────────────────

/** v2 top-level resource description (moved out of the requirement in v2). */
export interface ResourceInfo {
  /** The resource URL being paid for (the server's CLAIM — audit only). */
  url: string;
  description?: string;
  mimeType?: string;
}

/**
 * One v2 `accepts` entry. Deltas from v1: `maxAmountRequired` is renamed
 * `amount` (still a decimal string of ATOMIC units); `network` is a CAIP-2
 * chain id (`eip155:8453`, not `base`); `resource`/`description`/`mimeType`/
 * `outputSchema` moved out (or vanished); `maxTimeoutSeconds` became REQUIRED;
 * `payTo` may be a role constant (e.g. "merchant") rather than an address —
 * which this adapter refuses by default because an unresolvable recipient
 * cannot be allowlisted.
 */
export interface PaymentRequirementsV2 {
  scheme: string;
  /** CAIP-2 chain id, e.g. "eip155:8453". NOT the same key space as v1 names. */
  network: string;
  /** Required amount in the ASSET'S ATOMIC UNITS, as a decimal string. */
  amount: string;
  /** Recipient address (or a v2 role constant — refused unless allowlisted). */
  payTo: string;
  /** Token contract address, or an ISO 4217 currency code for fiat rails. */
  asset: string;
  /** REQUIRED in v2 (optional in v1). */
  maxTimeoutSeconds: number;
  /** Token metadata; same validated keys as v1. */
  extra?: {
    name?: string;
    version?: string;
    decimals?: number;
    symbol?: string;
  };
}

/**
 * A v2 extension entry: `info` is what the client must echo back in its
 * PaymentPayload; `schema` is a JSON Schema describing it. Both are untrusted
 * server data — validated, size-capped, and defensively copied at parse.
 */
export interface X402Extension {
  info: Record<string, unknown>;
  schema: Record<string, unknown>;
  [key: string]: unknown;
}

/** Decoded `PAYMENT-REQUIRED` header (the v2 PaymentRequired structure). */
export interface PaymentRequiredV2 {
  x402Version: 2;
  /** REQUIRED in v2: one ResourceInfo per body, not per requirement. */
  resource: ResourceInfo;
  accepts: PaymentRequirementsV2[];
  error?: string;
  extensions?: Record<string, X402Extension>;
}
