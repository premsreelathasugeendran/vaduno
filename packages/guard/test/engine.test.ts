import { describe, expect, it } from "vitest";
import { evaluatePolicy, merchantMatches } from "../src/policy/engine.js";
import { merchantKeyOf } from "../src/enforce/spend-limiter.js";
import { emptyHistory, makeIntent, makePolicy } from "./helpers.js";

describe("evaluatePolicy", () => {
  it("allows a compliant intent", async () => {
    const result = await evaluatePolicy(makeIntent(), makePolicy(), emptyHistory);
    expect(result.decision).toBe("allow");
  });

  it("denies non-integer and non-positive amounts", async () => {
    for (const amountMinor of [0, -5, 1.5, NaN]) {
      const result = await evaluatePolicy(
        makeIntent({ amount: { amountMinor, currency: "USD" } }),
        makePolicy(),
        emptyHistory,
      );
      expect(result.decision).toBe("deny");
      expect(result.reasons.map((r) => r.code)).toContain("INVALID_AMOUNT");
    }
  });

  it("denies currency mismatch", async () => {
    const result = await evaluatePolicy(
      makeIntent({ amount: { amountMinor: 100, currency: "INR" } }),
      makePolicy(),
      emptyHistory,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain("CURRENCY_MISMATCH");
  });

  it("denies over per-transaction limit", async () => {
    const result = await evaluatePolicy(
      makeIntent({ amount: { amountMinor: 6_000, currency: "USD" } }),
      makePolicy(),
      emptyHistory,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain(
      "PER_TXN_LIMIT_EXCEEDED",
    );
  });

  it("denies when rolling day window would be exceeded", async () => {
    const history = {
      async totalsSince() {
        return { totalMinor: 9_800, count: 3 };
      },
    };
    const result = await evaluatePolicy(
      makeIntent({ amount: { amountMinor: 300, currency: "USD" } }),
      makePolicy(),
      history,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain(
      "PER_DAY_LIMIT_EXCEEDED",
    );
  });

  it("enforces merchant allowlist and blocklist (block wins)", async () => {
    const policy = makePolicy({
      merchants: { allow: ["openai", "aws"], block: ["openai"] },
    });
    const result = await evaluatePolicy(makeIntent(), policy, emptyHistory);
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain("MERCHANT_BLOCKED");

    const notListed = await evaluatePolicy(
      makeIntent({ merchant: { id: "random-shop" } }),
      makePolicy({ merchants: { allow: ["openai"] } }),
      emptyHistory,
    );
    expect(notListed.decision).toBe("deny");
    expect(notListed.reasons.map((r) => r.code)).toContain(
      "MERCHANT_NOT_ALLOWED",
    );
  });

  it("requires approval at threshold and for always", async () => {
    const threshold = await evaluatePolicy(
      makeIntent({ amount: { amountMinor: 2_000, currency: "USD" } }),
      makePolicy({ approval: { aboveMinor: 2_000 } }),
      emptyHistory,
    );
    expect(threshold.decision).toBe("require_approval");

    const always = await evaluatePolicy(
      makeIntent({ amount: { amountMinor: 1, currency: "USD" } }),
      makePolicy({ approval: { always: true } }),
      emptyHistory,
    );
    expect(always.decision).toBe("require_approval");
  });

  it("denies expired policy", async () => {
    const result = await evaluatePolicy(
      makeIntent(),
      makePolicy({ expiresAt: "2000-01-01T00:00:00.000Z" }),
      emptyHistory,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain("POLICY_EXPIRED");
  });

  it("enforces velocity", async () => {
    const history = {
      async totalsSince() {
        return { totalMinor: 100, count: 5 };
      },
    };
    const result = await evaluatePolicy(
      makeIntent(),
      makePolicy({ velocity: { maxTransactions: { count: 5, perSeconds: 60 } } }),
      history,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain("VELOCITY_EXCEEDED");
  });

  it("enforces rail allowlist and category rules", async () => {
    const rail = await evaluatePolicy(
      makeIntent({ rail: "x402" }),
      makePolicy({ rails: { allow: ["mock"] } }),
      emptyHistory,
    );
    expect(rail.decision).toBe("deny");

    const category = await evaluatePolicy(
      makeIntent({ category: "gambling" }),
      makePolicy({ categories: { block: ["gambling"] } }),
      emptyHistory,
    );
    expect(category.decision).toBe("deny");

    const missingCategory = await evaluatePolicy(
      makeIntent({ category: undefined }),
      makePolicy({ categories: { allow: ["api-credits"] } }),
      emptyHistory,
    );
    expect(missingCategory.decision).toBe("deny");
  });

  it("collects multiple deny reasons", async () => {
    const result = await evaluatePolicy(
      makeIntent({
        amount: { amountMinor: 9_999_999, currency: "EUR" },
        merchant: { id: "shady" },
      }),
      makePolicy({ merchants: { allow: ["openai"] } }),
      emptyHistory,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.length).toBeGreaterThanOrEqual(3);
  });
});

describe("merchantMatches", () => {
  const intent = makeIntent({
    merchant: { id: "amz", url: "https://checkout.amazon.com/pay" },
  });

  it("matches exact id and exact/subdomain host at dot boundary", () => {
    expect(merchantMatches(intent, "amz")).toBe(true);
    expect(merchantMatches(intent, "amazon.com")).toBe(true);
    expect(merchantMatches(intent, "checkout.amazon.com")).toBe(true);
  });

  it("does NOT match lookalike domains", () => {
    expect(merchantMatches(intent, "evil-amazon.com")).toBe(false);
    const evil = makeIntent({
      merchant: { id: "x", url: "https://evil-amazon.com/pay" },
    });
    expect(merchantMatches(evil, "amazon.com")).toBe(false);
  });

  it("host pattern ignores a forged merchant.id (critical bypass fix)", async () => {
    // Agent forges id to look like the allowed host, but pays a drainer host.
    const forged = makeIntent({
      merchant: { id: "api.openai.com", url: "https://wallet-drainer.xyz/pay" },
    });
    expect(merchantMatches(forged, "api.openai.com")).toBe(false);
    const result = await evaluatePolicy(
      forged,
      makePolicy({ merchants: { allow: ["openai.com"] } }),
      emptyHistory,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain("MERCHANT_NOT_ALLOWED");
  });

  it("host pattern fails closed when the intent has no URL", () => {
    const noUrl = makeIntent({ merchant: { id: "openai.com" } });
    expect(merchantMatches(noUrl, "openai.com")).toBe(false);
  });

  it("id: prefix matches merchant.id explicitly", () => {
    const i = makeIntent({ merchant: { id: "openai", url: "https://x.example" } });
    expect(merchantMatches(i, "id:openai")).toBe(true);
    expect(merchantMatches(i, "id:other")).toBe(false);
  });

  it("id match is not evaded by surrounding whitespace in merchant.id", () => {
    const padded = makeIntent({ merchant: { id: "  0xBAD  " } });
    expect(merchantMatches(padded, "id:0xbad")).toBe(true); // still blocked
  });

  it("blocklist is not bypassed by a trailing-dot FQDN", async () => {
    const fqdn = makeIntent({
      merchant: { id: "x", url: "https://amazon.com./pay" },
    });
    const result = await evaluatePolicy(
      fqdn,
      makePolicy({ merchants: { block: ["amazon.com"] } }),
      emptyHistory,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain("MERCHANT_BLOCKED");
  });
});

describe("timestamp handling (non-UTC offsets fail closed)", () => {
  it("policy.expiresAt honors a non-Z offset", async () => {
    // 05:30+05:30 == 00:00Z. "now" is 02:00Z, so the policy is EXPIRED even
    // though the string sorts lexicographically after the now string.
    const now = () => new Date("2026-01-01T02:00:00.000Z");
    const result = await evaluatePolicy(
      makeIntent(),
      makePolicy({ expiresAt: "2026-01-01T05:30:00+05:30" }),
      emptyHistory,
      now,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain("POLICY_EXPIRED");
  });

  it("unparseable policy.expiresAt fails closed", async () => {
    const result = await evaluatePolicy(
      makeIntent(),
      makePolicy({ expiresAt: "not-a-date" }),
      emptyHistory,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain(
      "POLICY_EXPIRY_UNPARSEABLE",
    );
  });

  it("rejects unsafe-integer amounts", async () => {
    const result = await evaluatePolicy(
      makeIntent({ amount: { amountMinor: Number.MAX_SAFE_INTEGER + 2, currency: "USD" } }),
      makePolicy(),
      emptyHistory,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain("INVALID_AMOUNT");
  });
});

describe("velocity v2: multi-window and per-merchant counts", () => {
  it("the existing single-object maxTransactions shape still enforces (backward compat)", async () => {
    // Same shape as the long-standing test above — kept SEPARATELY so array
    // support can never quietly redefine the single-object contract.
    const history = {
      async totalsSince() {
        return { totalMinor: 100, count: 3 };
      },
    };
    const result = await evaluatePolicy(
      makeIntent(),
      makePolicy({ velocity: { maxTransactions: { count: 3, perSeconds: 60 } } }),
      history,
    );
    expect(result.decision).toBe("deny");
    expect(result.reasons.map((r) => r.code)).toContain("VELOCITY_EXCEEDED");
  });

  it("an ARRAY of count limits enforces every listed window (burst AND sustained)", async () => {
    const history = {
      async totalsSince() {
        return { totalMinor: 100, count: 5 };
      },
    };
    const result = await evaluatePolicy(
      makeIntent(),
      makePolicy({
        velocity: {
          maxTransactions: [
            { count: 10, perSeconds: 60 },     // burst window: room to spare
            { count: 5, perSeconds: 86_400 },  // sustained window: full
          ],
        },
      }),
      history,
    );
    expect(result.decision).toBe("deny");
    const velocity = result.reasons.filter((r) => r.code === "VELOCITY_EXCEEDED");
    expect(velocity).toHaveLength(1);
    expect(velocity[0]!.message).toContain("limit is 5");
  });

  it("per-merchant windows deny via merchantCountSince when the merchant is saturated", async () => {
    const history = {
      async totalsSince() {
        return { totalMinor: 0, count: 0 };
      },
      async merchantCountSince(_a: string, merchantKey: string) {
        return { count: merchantKey === "host:api.openai.com" ? 5 : 0 };
      },
    };
    const saturated = await evaluatePolicy(
      makeIntent({ merchant: { id: "openai", url: "https://api.openai.com/v1" } }),
      makePolicy({ velocity: { maxTransactionsPerMerchant: { count: 5, perSeconds: 3_600 } } }),
      history,
    );
    expect(saturated.decision).toBe("deny");
    expect(saturated.reasons.map((r) => r.code)).toContain("MERCHANT_VELOCITY_EXCEEDED");

    const other = await evaluatePolicy(
      makeIntent({ merchant: { id: "aws", url: "https://aws.amazon.com/pay" } }),
      makePolicy({ velocity: { maxTransactionsPerMerchant: { count: 5, perSeconds: 3_600 } } }),
      history,
    );
    expect(other.decision).toBe("allow");
  });

  it("a history WITHOUT merchantCountSince skips the merchant check (advisory only — the limiter still enforces)", async () => {
    const result = await evaluatePolicy(
      makeIntent(),
      makePolicy({ velocity: { maxTransactionsPerMerchant: { count: 1, perSeconds: 3_600 } } }),
      emptyHistory, // totalsSince only
    );
    expect(result.decision).toBe("allow");
  });

  it("malformed velocity config denies SPEND_WINDOW_INVALID instead of enforcing nothing", async () => {
    const cases = [
      { maxTransactions: { count: Number.NaN, perSeconds: 60 } },
      { maxTransactions: { count: 5, perSeconds: 0 } },
      { maxTransactions: { count: 0, perSeconds: 60 } },
      { maxTransactions: { count: 2.5, perSeconds: 60 } },
      // Type-illegal runtime shapes a JSON config can smuggle in: never
      // coerced, always refused.
      { maxTransactions: "5" as unknown as { count: number; perSeconds: number } },
      { maxTransactionsPerMerchant: { count: Number.NaN, perSeconds: 60 } },
    ];
    for (const velocity of cases) {
      const result = await evaluatePolicy(
        makeIntent(),
        makePolicy({ velocity }),
        emptyHistory,
      );
      expect(result.decision, JSON.stringify(velocity)).toBe("deny");
      expect(
        result.reasons.map((r) => r.code),
        JSON.stringify(velocity),
      ).toContain("SPEND_WINDOW_INVALID");
    }
  });
});

describe("merchantKeyOf: the ONE merchant-identity function", () => {
  it("URL host wins, normalized: lowercased, trailing FQDN dot stripped", () => {
    expect(merchantKeyOf({ id: "stripe", url: "https://API.Stripe.com./v1" })).toBe(
      "host:api.stripe.com",
    );
  });

  it("no url falls back to the trimmed, lowercased id", () => {
    expect(merchantKeyOf({ id: "x" })).toBe("id:x");
    expect(merchantKeyOf({ id: "  OpenAI  " })).toBe("id:openai");
  });

  it("an id crafted to look like a host key cannot collide with a url-derived key", () => {
    // The two prefix families are disjoint by construction.
    expect(merchantKeyOf({ id: "host:evil" })).toBe("id:host:evil");
    expect(merchantKeyOf({ id: "host:evil" })).not.toBe(
      merchantKeyOf({ id: "anything", url: "https://evil" }),
    );
  });

  it("an unparseable or hostless url falls back to the id family", () => {
    expect(merchantKeyOf({ id: "x", url: "::not a url::" })).toBe("id:x");
    expect(merchantKeyOf({ id: "x", url: "file:///local/path" })).toBe("id:x");
  });
});
