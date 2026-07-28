import type { SpendPolicy } from "@swale/guard";
import type { StripeIssuingLike } from "./types.js";

export interface SpendingControls {
  spending_limits?: Array<{ amount: number; interval: string }>;
  allowed_categories?: string[];
  blocked_categories?: string[];
}

export interface PolicyControlsResult {
  spendingControls: SpendingControls;
  /** Policy category strings that are NOT valid Stripe MCC enums and were skipped. */
  unmapped: string[];
}

// Stripe MCC category enums are lowercase snake_case (e.g. "gambling",
// "taxicabs_limousines"). Free-form policy categories like "api-credits" are
// not MCCs; we skip them rather than emit an invalid control.
const MCC_ENUM = /^[a-z_]+$/;

/**
 * Mirror a Swale SpendPolicy into Stripe-native card spending_controls, so
 * Stripe enforces the deterministic limits BEFORE the real-time webhook even
 * fires (defense in depth; most-restrictive-wins with the live guard). Native
 * aggregation lags ~30s, so the real-time guard remains the tight gate.
 */
export function policyToSpendingControls(policy: SpendPolicy): PolicyControlsResult {
  const limits = policy.limits ?? {};
  const spending_limits: Array<{ amount: number; interval: string }> = [];
  const push = (amount: number | undefined, interval: string) => {
    if (Number.isSafeInteger(amount) && (amount as number) > 0) {
      spending_limits.push({ amount: amount as number, interval });
    }
  };
  push(limits.perTransactionMinor, "per_authorization");
  push(limits.perDayMinor, "daily");
  push(limits.perWeekMinor, "weekly");
  push(limits.perMonthMinor, "monthly");

  const unmapped: string[] = [];
  const filterMcc = (list: string[] | undefined): string[] => {
    if (!list) return [];
    const ok: string[] = [];
    for (const c of list) {
      if (MCC_ENUM.test(c)) ok.push(c);
      else unmapped.push(c);
    }
    return ok;
  };
  const allowed = filterMcc(policy.categories?.allow);
  const blocked = filterMcc(policy.categories?.block);

  const spendingControls: SpendingControls = {};
  if (spending_limits.length > 0) spendingControls.spending_limits = spending_limits;
  if (allowed.length > 0) spendingControls.allowed_categories = allowed;
  if (blocked.length > 0) spendingControls.blocked_categories = blocked;

  return { spendingControls, unmapped };
}

export interface CardholderParams {
  name: string;
  email?: string;
  phoneNumber?: string;
  type?: "individual" | "company";
  billing: { address: Record<string, string> };
}

/** Create an Issuing cardholder. Thin passthrough with active status default. */
export async function createAgentCardholder(
  stripe: StripeIssuingLike,
  params: CardholderParams,
): Promise<{ id: string } & Record<string, unknown>> {
  return stripe.issuing.cardholders.create({
    name: params.name,
    type: params.type ?? "individual",
    status: "active",
    ...(params.email ? { email: params.email } : {}),
    ...(params.phoneNumber ? { phone_number: params.phoneNumber } : {}),
    billing: params.billing,
  });
}

export interface CreateCardParams {
  cardholder: string;
  agentId: string;
  currency?: string;
  /** Policy to mirror into native spending_controls (defense in depth). */
  policy?: SpendPolicy;
  /** Explicit override of the derived spending_controls. */
  spendingControls?: SpendingControls;
  metadata?: Record<string, string>;
}

/**
 * Create a virtual card bound to an agent. status is set to "active" (Stripe
 * defaults cards to inactive — the #1 footgun) and metadata.agent_id is set so
 * the authorization handler can resolve the agent from card.metadata.
 * Returns the created card. Retrieve the PAN/CVC yourself with
 * `expand: ["number","cvc"]` + an ephemeral key (kept out of this package to
 * stay clear of PCI scope).
 */
export async function createAgentCard(
  stripe: StripeIssuingLike,
  params: CreateCardParams,
): Promise<{ id: string } & Record<string, unknown>> {
  const controls =
    params.spendingControls ??
    (params.policy ? policyToSpendingControls(params.policy).spendingControls : undefined);

  return stripe.issuing.cards.create({
    cardholder: params.cardholder,
    currency: (params.currency ?? "usd").toLowerCase(),
    type: "virtual",
    status: "active",
    ...(controls ? { spending_controls: controls } : {}),
    metadata: { agent_id: params.agentId, ...(params.metadata ?? {}) },
  });
}
