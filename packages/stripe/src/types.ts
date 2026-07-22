/**
 * Narrow structural types for the Stripe Issuing objects this adapter reads.
 * We deliberately do NOT depend on the `stripe` package's types — the consumer
 * passes their real Stripe client, which structurally satisfies these. This
 * keeps @paygent/stripe dependency-free and trivially mockable.
 */

export interface StripeMerchantData {
  name?: string;
  category?: string;
  category_code?: string;
  network_id?: string;
  city?: string;
  state?: string;
  country?: string;
  postal_code?: string;
}

export interface StripePendingRequest {
  /** The requested amount in the card's billing currency, ATOMIC (cents). */
  amount: number;
  currency: string;
  is_amount_controllable?: boolean;
  merchant_amount?: number;
  merchant_currency?: string;
  network_risk_score?: number;
}

export interface StripeAuthorization {
  id: string;
  /** 0 on a request event — DO NOT use for the amount; read pending_request. */
  amount: number;
  currency: string;
  approved: boolean;
  created: number;
  authorization_method?: string;
  merchant_data?: StripeMerchantData;
  pending_request?: StripePendingRequest | null;
  card?: { id?: string; metadata?: Record<string, string> };
  cardholder?: string | { id?: string };
  verification_data?: Record<string, unknown>;
  metadata?: Record<string, string>;
}

export interface StripeEvent {
  id?: string;
  type: string;
  data: { object: unknown };
}

/** The only Stripe surface the webhook handler touches. */
export interface StripeWebhooksLike {
  constructEvent(payload: string | Buffer, signature: string, secret: string): StripeEvent;
}

/** Minimal shape for provisioning helpers (issuing.cardholders/cards.create). */
export interface StripeIssuingLike {
  issuing: {
    cardholders: {
      create(params: Record<string, unknown>): Promise<{ id: string } & Record<string, unknown>>;
    };
    cards: {
      create(params: Record<string, unknown>): Promise<{ id: string } & Record<string, unknown>>;
    };
  };
}
