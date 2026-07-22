import { describe, expect, it } from "vitest";
import { evaluatePolicy, merchantMatches } from "../src/policy/engine.js";
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
