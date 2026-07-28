import { AuditLedger, MemoryLedgerStore, SwaleGuard } from "@swale/guard";
import type { SpendPolicy } from "@swale/guard";
import type { StripeAuthorization, StripeEvent } from "../src/types.js";

let seq = 0;

export function makeGuard(policyOver: Partial<SpendPolicy> = {}) {
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const guard = new SwaleGuard({
    policy: {
      id: "issuing-policy",
      version: 1,
      currency: "USD",
      limits: { perTransactionMinor: 5_000, perDayMinor: 20_000 },
      ...policyOver,
    },
    ledger,
  });
  return { guard, ledger };
}

export interface AuthOver {
  id?: string;
  amount?: number; // pending_request amount (atomic)
  currency?: string;
  category?: string;
  networkId?: string;
  agentId?: string;
  isAmountControllable?: boolean;
}

/** Build a realistic issuing_authorization.request event. */
export function fakeAuthEvent(over: AuthOver = {}): StripeEvent {
  seq += 1;
  const auth: StripeAuthorization = {
    id: over.id ?? `iauth_${seq}`,
    amount: 0, // 0 on the request event — the truth is in pending_request
    currency: over.currency ?? "usd",
    approved: false,
    created: 1_700_000_000 + seq,
    authorization_method: "online",
    merchant_data: {
      name: "Example Merchant",
      category: over.category ?? "computer_software_stores",
      category_code: "5734",
      network_id: over.networkId ?? "net_abc123",
      country: "US",
      city: "San Francisco",
    },
    pending_request: {
      amount: over.amount ?? 500,
      currency: over.currency ?? "usd",
      is_amount_controllable: over.isAmountControllable ?? false,
      merchant_amount: over.amount ?? 500,
      merchant_currency: over.currency ?? "usd",
    },
    card: { id: "ic_card1", metadata: { agent_id: over.agentId ?? "shopper-agent-1" } },
    cardholder: "ich_holder1",
  };
  return { id: `evt_${seq}`, type: "issuing_authorization.request", data: { object: auth } };
}

/** Mock Stripe whose signature check is a pure branch: "good" verifies. */
export function mockStripe() {
  return {
    webhooks: {
      constructEvent(payload: string | Buffer, signature: string): StripeEvent {
        if (signature !== "good") throw new Error("No signatures found matching the expected signature");
        return JSON.parse(typeof payload === "string" ? payload : payload.toString("utf8")) as StripeEvent;
      },
    },
  };
}

export function raw(event: StripeEvent): string {
  return JSON.stringify(event);
}
