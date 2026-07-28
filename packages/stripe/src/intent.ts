import type { PaymentIntent } from "@swale/guard";
import type { StripeAuthorization } from "./types.js";

export interface AuthorizationToIntentOptions {
  /** Resolve the agent id. Default: card.metadata.agent_id, else card.id. */
  agentIdFor?: (auth: StripeAuthorization) => string;
  /** Static category override (else merchant_data.category / category_code). */
  category?: string;
  mandateIdFor?: (auth: StripeAuthorization) => string | undefined;
  now?: () => Date;
}

/**
 * Map a Stripe Issuing Authorization (from an issuing_authorization.request
 * event) to a Swale PaymentIntent.
 *
 * CRITICAL: the requested amount is read from `pending_request.amount`, never
 * the top-level `auth.amount` (which is 0 on the request event). A missing or
 * invalid pending amount yields NaN so the policy engine denies it (fail closed).
 *
 * MERCHANT: `merchant.id` is the acquirer network merchant id (`network_id`,
 * trusted). When that is absent it falls back to `unverified:<name-slug>` — the
 * `unverified:` prefix keeps the ATTACKER-CONTROLLED merchant name out of the
 * same namespace as a trusted `id:<network_id>` allowlist token, so a hostile
 * merchant can't set its name to match your allowlist. Only trust `id:` matches
 * that came from a real network_id. There is no reliable merchant URL in
 * Issuing, so host-pattern allow/block rules NEVER match on this rail —
 * constrain merchants with `id:` patterns or by category. The full
 * merchant_data is recorded in metadata for audit.
 */
export function authorizationToIntent(
  auth: StripeAuthorization,
  opts: AuthorizationToIntentOptions = {},
): PaymentIntent {
  const now = opts.now ?? (() => new Date());
  const pr = auth.pending_request;
  const amountMinor =
    pr && Number.isSafeInteger(pr.amount) && pr.amount > 0 ? pr.amount : NaN;
  const currency = (pr?.currency ?? auth.currency ?? "").toUpperCase();
  const md = auth.merchant_data ?? {};

  // network_id is the trusted acquirer id; a name-derived fallback is
  // attacker-controlled, so namespace it as unverified: (see docstring).
  const merchantId =
    (md.network_id && md.network_id.trim()) ||
    `unverified:${slug(`${md.name ?? "unknown"}-${md.country ?? ""}`)}`;

  const cardMeta = auth.card?.metadata ?? {};
  const agentId = opts.agentIdFor
    ? opts.agentIdFor(auth)
    : cardMeta.agent_id ?? auth.card?.id ?? "unknown-agent";

  const category = opts.category ?? md.category ?? undefined;

  const intent: PaymentIntent = {
    id: auth.id,
    agentId,
    merchant: {
      id: merchantId,
      ...(md.name ? { name: md.name } : {}),
    },
    amount: { amountMinor, currency },
    rail: "stripe-issuing",
    requestedAt: now().toISOString(),
    metadata: {
      authorization_method: auth.authorization_method,
      merchant_name: md.name,
      merchant_category: md.category,
      merchant_category_code: md.category_code,
      merchant_network_id: md.network_id,
      merchant_country: md.country,
      merchant_city: md.city,
      is_amount_controllable: pr?.is_amount_controllable ?? false,
      merchant_amount: pr?.merchant_amount,
      merchant_currency: pr?.merchant_currency,
      network_risk_score: pr?.network_risk_score,
      card_id: auth.card?.id,
      cardholder: typeof auth.cardholder === "string" ? auth.cardholder : auth.cardholder?.id,
      stripe_created: auth.created,
    },
  };
  if (category !== undefined) intent.category = category;
  if (opts.mandateIdFor) {
    const mid = opts.mandateIdFor(auth);
    if (mid !== undefined) intent.mandateId = mid;
  }
  return intent;
}

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 64) || "unknown";
}
