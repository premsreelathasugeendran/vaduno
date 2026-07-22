import type { PaymentIntent } from "@paygent/guard";
import type { PaymentRequirements } from "./types.js";

export interface RequirementToIntentOptions {
  agentId: string;
  /** Unique id for the produced intent (used for audit joins). */
  intentId: string;
  /**
   * The ACTUAL request URL the agent contacts. merchant.url is set from THIS,
   * never from the server-declared `resource`, so a host allowlist reflects
   * the endpoint truly reached rather than the server's claim.
   */
  requestUrl: string;
  /**
   * Trusted currency label (e.g. from an asset registry). When omitted, falls
   * back to the SERVER-SUPPLIED `extra.symbol` — which is display-only and
   * NOT a security boundary. Supply this (via the fetch layer's `assets`
   * registry) to bind spend limits to a real token.
   */
  currency?: string;
  category?: string;
  mandateId?: string;
  now?: () => Date;
}

/**
 * Map a chosen x402 payment requirement to a Paygent PaymentIntent.
 *
 * AMOUNT UNITS: x402 amounts are the token's ATOMIC units (e.g. 6-decimal
 * USDC: $1 = 1_000_000). Paygent's `amountMinor` must be an integer, so we
 * carry the atomic amount through unchanged. A non-integer / unsafe / non-
 * decimal amount is passed through as NaN so the policy engine denies it.
 *
 * MERCHANT — TWO INDEPENDENT DIMENSIONS, both meaningful:
 *   - merchant.url = the ACTUAL request URL (`requestUrl`). Host allowlists
 *     bind the endpoint you truly contact. The server's `resource` claim is
 *     recorded in metadata only and never drives a decision.
 *   - merchant.id  = payTo, the on-chain fund RECIPIENT. In x402 the recipient
 *     is decoupled from the request host, so a host allowlist does NOT
 *     constrain where money goes — constrain the recipient with an `id:<payTo>`
 *     pattern (or a payTo allowlist) if that matters.
 */
export function requirementToIntent(
  req: PaymentRequirements,
  opts: RequirementToIntentOptions,
): PaymentIntent {
  const now = opts.now ?? (() => new Date());
  const currency = (opts.currency ?? req.extra?.symbol ?? req.asset).toUpperCase();
  const intent: PaymentIntent = {
    id: opts.intentId,
    agentId: opts.agentId,
    merchant: {
      id: req.payTo,
      url: opts.requestUrl,
      ...(req.extra?.name ? { name: req.extra.name } : {}),
    },
    amount: { amountMinor: parseAtomicAmount(req.maxAmountRequired), currency },
    rail: "x402",
    requestedAt: now().toISOString(),
    metadata: {
      scheme: req.scheme,
      network: req.network,
      asset: req.asset,
      payTo: req.payTo,
      requestUrl: opts.requestUrl,
      // The server's own claim about what's being paid for — audit only.
      resourceClaimed: req.resource,
      maxAmountRequired: req.maxAmountRequired,
      ...(req.extra?.decimals !== undefined ? { decimals: req.extra.decimals } : {}),
    },
  };
  if (opts.category !== undefined) intent.category = opts.category;
  if (opts.mandateId !== undefined) intent.mandateId = opts.mandateId;
  if (req.description !== undefined) intent.description = req.description;
  return intent;
}

/**
 * Parse an atomic-unit decimal string to an integer. Returns NaN (not a throw)
 * for anything non-integer, negative, or beyond the safe-integer range, so the
 * downstream policy engine denies it as INVALID_AMOUNT.
 */
export function parseAtomicAmount(s: string): number {
  if (!/^\d+$/.test(s)) return NaN;
  const n = Number(s);
  return Number.isSafeInteger(n) && n > 0 ? n : NaN;
}

/**
 * Convert a human token amount to atomic units for policy limits.
 * Rejects exponential notation (e.g. 3e-7) rather than silently corrupting it.
 */
export function atomic(human: number, decimals: number): number {
  if (!Number.isFinite(human) || human < 0) {
    throw new Error(`atomic(): invalid human amount ${human}`);
  }
  const s = human.toString();
  if (s.includes("e") || s.includes("E")) {
    throw new Error(
      `atomic(): ${human} uses exponential notation; pass a value whose decimal form is exact at ${decimals} decimals`,
    );
  }
  // Integer math on the string to avoid float drift (e.g. 0.1 * 1e6).
  const [whole, frac = ""] = s.split(".");
  if (frac.length > decimals && /[1-9]/.test(frac.slice(decimals))) {
    throw new Error(
      `atomic(): ${human} has more precision than ${decimals} decimals`,
    );
  }
  const fracPadded = (frac + "0".repeat(decimals)).slice(0, decimals);
  const combined = `${whole}${fracPadded}`.replace(/^0+(?=\d)/, "");
  const n = Number(combined);
  if (!Number.isSafeInteger(n)) {
    throw new Error(`atomic(): ${human} at ${decimals} decimals exceeds safe integer range`);
  }
  return n;
}

/** USDC has 6 decimals: usdc(1.5) === 1_500_000. */
export function usdc(human: number): number {
  return atomic(human, 6);
}
