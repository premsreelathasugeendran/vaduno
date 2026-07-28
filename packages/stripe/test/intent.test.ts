import { describe, expect, it } from "vitest";
import { authorizationToIntent } from "../src/intent.js";
import { policyToSpendingControls, createAgentCard } from "../src/provision.js";
import type { StripeAuthorization } from "../src/types.js";
import type { SpendPolicy } from "@swale/guard";

function auth(over: Partial<StripeAuthorization> = {}): StripeAuthorization {
  return {
    id: "iauth_1",
    amount: 0,
    currency: "usd",
    approved: false,
    created: 1_700_000_000,
    merchant_data: { name: "OpenAI", category: "computer_software_stores", network_id: "net_1", country: "US" },
    pending_request: { amount: 2_500, currency: "usd" },
    card: { id: "ic_1", metadata: { agent_id: "agent-1" } },
    ...over,
  };
}

describe("authorizationToIntent", () => {
  it("maps the requested amount from pending_request, not top-level", () => {
    const intent = authorizationToIntent(auth());
    expect(intent.amount).toEqual({ amountMinor: 2_500, currency: "USD" });
    expect(intent.rail).toBe("stripe-issuing");
    expect(intent.merchant.id).toBe("net_1");
    expect(intent.agentId).toBe("agent-1");
    expect(intent.category).toBe("computer_software_stores");
    expect((intent.metadata as { merchant_name: string }).merchant_name).toBe("OpenAI");
  });

  it("yields NaN amount (fail closed) when pending_request is missing", () => {
    const intent = authorizationToIntent(auth({ pending_request: null }));
    expect(Number.isNaN(intent.amount.amountMinor)).toBe(true);
  });

  it("falls back to card.id then a merchant slug when ids are absent", () => {
    const intent = authorizationToIntent(
      auth({ card: { id: "ic_9" }, merchant_data: { name: "Some Shop", country: "US" } }),
    );
    expect(intent.agentId).toBe("ic_9");
    // name-derived id is namespaced so it can't collide with a trusted id: token
    expect(intent.merchant.id).toBe("unverified:some-shop-us");
  });

  it("honors agentIdFor / category / mandateIdFor overrides", () => {
    const intent = authorizationToIntent(auth(), {
      agentIdFor: () => "custom-agent",
      category: "api-credits",
      mandateIdFor: () => "mandate-7",
    });
    expect(intent.agentId).toBe("custom-agent");
    expect(intent.category).toBe("api-credits");
    expect(intent.mandateId).toBe("mandate-7");
  });
});

describe("policyToSpendingControls", () => {
  const policy: SpendPolicy = {
    id: "p",
    version: 1,
    currency: "USD",
    limits: { perTransactionMinor: 5_000, perDayMinor: 20_000, perMonthMinor: 100_000 },
    categories: { allow: ["gambling", "api-credits"], block: ["taxicabs_limousines"] },
  };

  it("maps limits to spending_limits intervals", () => {
    const { spendingControls } = policyToSpendingControls(policy);
    expect(spendingControls.spending_limits).toEqual([
      { amount: 5_000, interval: "per_authorization" },
      { amount: 20_000, interval: "daily" },
      { amount: 100_000, interval: "monthly" },
    ]);
  });

  it("keeps MCC-shaped categories and reports non-MCC ones as unmapped", () => {
    const { spendingControls, unmapped } = policyToSpendingControls(policy);
    expect(spendingControls.allowed_categories).toEqual(["gambling"]);
    expect(spendingControls.blocked_categories).toEqual(["taxicabs_limousines"]);
    expect(unmapped).toContain("api-credits"); // hyphen -> not an MCC enum
  });
});

describe("createAgentCard", () => {
  it("sets status active and metadata.agent_id, and mirrors policy controls", async () => {
    const created: Record<string, unknown>[] = [];
    const stripe = {
      issuing: {
        cardholders: { create: async () => ({ id: "ich_1" }) },
        cards: {
          create: async (p: Record<string, unknown>) => {
            created.push(p);
            return { id: "ic_new", ...p };
          },
        },
      },
    };
    await createAgentCard(stripe, {
      cardholder: "ich_1",
      agentId: "agent-42",
      policy: { id: "p", version: 1, currency: "USD", limits: { perTransactionMinor: 5_000 } },
    });
    const p = created[0]!;
    expect(p.status).toBe("active");
    expect(p.type).toBe("virtual");
    expect((p.metadata as { agent_id: string }).agent_id).toBe("agent-42");
    expect((p.spending_controls as { spending_limits: unknown[] }).spending_limits).toEqual([
      { amount: 5_000, interval: "per_authorization" },
    ]);
  });
});
