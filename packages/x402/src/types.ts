/**
 * x402 protocol shapes (v1). See https://x402.org / the x402 spec.
 *
 * x402 revives HTTP 402 Payment Required: a server answers a request with 402
 * and a set of `accepts` payment requirements; the client pays (signs a
 * stablecoin transfer authorization), base64-encodes it into an `X-PAYMENT`
 * header, and retries. The server verifies/settles and returns 200 plus an
 * `X-PAYMENT-RESPONSE` header.
 *
 * Paygent sits at the "before you pay" moment: it turns the chosen requirement
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

/** Decoded `X-PAYMENT-RESPONSE` settlement result. */
export interface SettlementResponse {
  success: boolean;
  transaction?: string;
  network?: string;
  payer?: string;
  [key: string]: unknown;
}
