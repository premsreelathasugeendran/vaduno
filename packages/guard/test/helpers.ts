import type { PaymentIntent, SpendPolicy } from "../src/types.js";

let seq = 0;

export function makeIntent(over: Partial<PaymentIntent> = {}): PaymentIntent {
  seq += 1;
  return {
    id: `intent-${seq}`,
    agentId: "agent-1",
    merchant: { id: "openai", url: "https://api.openai.com/v1/pay" },
    amount: { amountMinor: 500, currency: "USD" },
    category: "api-credits",
    rail: "mock",
    requestedAt: new Date().toISOString(),
    ...over,
  };
}

export function makePolicy(over: Partial<SpendPolicy> = {}): SpendPolicy {
  return {
    id: "policy-test",
    version: 1,
    currency: "USD",
    limits: {
      perTransactionMinor: 5_000,
      perDayMinor: 10_000,
    },
    ...over,
  };
}

export const emptyHistory = {
  async totalsSince() {
    return { totalMinor: 0, count: 0 };
  },
};
