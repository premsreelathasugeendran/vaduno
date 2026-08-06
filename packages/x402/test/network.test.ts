import { describe, expect, it, vi } from "vitest";
import { requirementToIntent, requirementToIntentV2 } from "../src/intent.js";
import { createX402Fetch } from "../src/fetch.js";
import {
  X402PaymentBlockedError,
  X402RequirementRefusedError,
} from "../src/errors.js";
import { makeGuard, mockServer } from "./helpers.js";

/**
 * FINDING A, rail side. The adapter always knew the network — it put it in
 * `metadata.network`, which no policy rule reads. A guard configured for one
 * chain therefore authorized a payment on another. Promote it to the
 * first-class `intent.network` so `policy.networks` can actually gate it.
 */

const V1_REQ = {
  scheme: "exact",
  network: "base-sepolia",
  maxAmountRequired: "1000000",
  resource: "https://api.example.com/x",
  payTo: "0xMerchant",
  asset: "0xUSDC",
  extra: { symbol: "USDC", decimals: 6 },
};

const V2_REQ = {
  scheme: "exact",
  network: "eip155:84532",
  amount: "1000000",
  payTo: "0xMerchant",
  asset: "0xUSDC",
  maxTimeoutSeconds: 300,
  extra: { symbol: "USDC", decimals: 6 },
};

describe("x402 intents carry the settlement network", () => {
  it("v1: intent.network is the requirement's network name", () => {
    const intent = requirementToIntent(V1_REQ, {
      agentId: "a",
      intentId: "i",
      requestUrl: "https://api.example.com/x",
    });
    expect(intent.network).toBe("base-sepolia");
    // still in metadata too — the audit shape does not regress
    expect((intent.metadata as { network?: string }).network).toBe("base-sepolia");
  });

  it("v2: intent.network is the requirement's CAIP-2 id", () => {
    const intent = requirementToIntentV2(
      V2_REQ,
      { url: "https://api.example.com/x" },
      { agentId: "a", intentId: "i", requestUrl: "https://api.example.com/x" },
    );
    expect(intent.network).toBe("eip155:84532");
  });

  it("a wrong-chain payment is now DENIED by policy, not by caller config", async () => {
    // The SAME asset symbol on a different chain. Before intent.network the
    // policy had nothing to object to: same shape, same currency, wrong chain.
    const server = mockServer({ network: "ethereum-sepolia" });
    const { guard } = makeGuard({ networks: { allow: ["base-sepolia"] } });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({ guard, agentId: "a", pay, fetch: server.fetch });

    const err = await x402("https://api.example.com/data").catch((e) => e);
    expect(err).toBeInstanceOf(X402PaymentBlockedError);
    // Specifically NETWORK_NOT_ALLOWED — the guard SAW the chain and rejected
    // it. A NETWORK_MISSING here would mean the adapter never told the guard
    // which chain this was, which is the whole defect.
    expect(
      (err as X402PaymentBlockedError).policyResult.reasons.map((r) => r.code),
    ).toContain("NETWORK_NOT_ALLOWED");
    expect(pay).not.toHaveBeenCalled();
    expect(server.paidCalls()).toBe(0);
  });

  it("the same payment on the allowlisted chain still settles", async () => {
    const server = mockServer({ network: "base-sepolia" });
    const { guard } = makeGuard({ networks: { allow: ["base-sepolia"] } });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({ guard, agentId: "a", pay, fetch: server.fetch });

    const res = await x402("https://api.example.com/data");
    expect(res.status).toBe(200);
    expect(server.paidCalls()).toBe(1);
  });
});

/**
 * THE OPT-IN HOLE. `policy.networks` made the chain constraint EXPRESSIBLE,
 * but a policy that omits it constrains chain not at all — the original
 * chain-blind finding survived as the default. The x402 adapter, unlike the
 * rail-agnostic guard, ALWAYS knows the settlement network (every requirement
 * carries it, and the EIP-712 domain the payer will sign commits to the
 * chain), so on THIS rail a deployment with no chain gate anywhere is never a
 * deliberate configuration. Default-deny it: pay only when the deployment
 * states chain knowledge somewhere — a trusted asset registry (which gates
 * (network, asset) pairs), a policy.networks constraint, or the explicit
 * `allowChainBlind: true` opt-out.
 */
describe("chain-blind x402 deployments are refused by default", () => {
  it("no asset registry, no policy.networks, no opt-out => NETWORK_UNGATED before pay()", async () => {
    const server = mockServer();
    const { guard } = makeGuard({ networks: undefined });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({ guard, agentId: "a", pay, fetch: server.fetch });

    const err = await x402("https://api.example.com/data").catch((e) => e);
    expect(err).toBeInstanceOf(X402RequirementRefusedError);
    expect((err as X402RequirementRefusedError).code).toBe("NETWORK_UNGATED");
    expect(pay).not.toHaveBeenCalled();
    expect(server.paidCalls()).toBe(0);
  });

  it("the explicit opt-out restores chain-agnostic behavior", async () => {
    const server = mockServer();
    const { guard } = makeGuard({ networks: undefined });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({
      guard,
      agentId: "a",
      pay,
      fetch: server.fetch,
      allowChainBlind: true,
    });
    const res = await x402("https://api.example.com/data");
    expect(res.status).toBe(200);
    expect(server.paidCalls()).toBe(1);
  });

  it("a trusted asset registry counts as the chain gate", async () => {
    const server = mockServer();
    const { guard } = makeGuard({ networks: undefined });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({
      guard,
      agentId: "a",
      pay,
      fetch: server.fetch,
      assets: [
        { network: "base-sepolia", asset: "0xUSDCContract", symbol: "USDC", decimals: 6 },
      ],
    });
    const res = await x402("https://api.example.com/data");
    expect(res.status).toBe(200);
    expect(server.paidCalls()).toBe(1);
  });

  it("a policy.networks constraint counts as the chain gate", async () => {
    const server = mockServer();
    const { guard } = makeGuard({ networks: { allow: ["base-sepolia"] } });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({ guard, agentId: "a", pay, fetch: server.fetch });
    const res = await x402("https://api.example.com/data");
    expect(res.status).toBe(200);
    expect(server.paidCalls()).toBe(1);
  });

  it("a block list ALONE does not satisfy the gate: networks.block is a subtraction from an unbounded set", async () => {
    // Measured before the fix: `networks: { block: [] }` and
    // `networks: { block: ["solana:x"] }` both PAID on base-sepolia — the gate
    // accepted the mere presence of a `networks` key as proof of constraint,
    // but a blocklist admits every chain it does not name. Only an ALLOW list
    // (or the assets registry) positively constrains the chain.
    for (const block of [[], ["solana:x"]]) {
      const server = mockServer({ network: "base-sepolia" });
      const { guard } = makeGuard({ networks: { block } });
      const pay = vi.fn(async () => "payload");
      const x402 = createX402Fetch({ guard, agentId: "a", pay, fetch: server.fetch });

      const err = await x402("https://api.example.com/data").catch((e) => e);
      expect(err).toBeInstanceOf(X402RequirementRefusedError);
      expect((err as X402RequirementRefusedError).code).toBe("NETWORK_UNGATED");
      expect(pay).not.toHaveBeenCalled();
      expect(server.paidCalls()).toBe(0);
    }
  });

  it("a block list BESIDE an allow list still gates (and still denies its entries)", async () => {
    const server = mockServer({ network: "base-sepolia" });
    const { guard } = makeGuard({
      networks: { allow: ["base-sepolia"], block: ["eip155:1"] },
    });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({ guard, agentId: "a", pay, fetch: server.fetch });
    const res = await x402("https://api.example.com/data");
    expect(res.status).toBe(200);
    expect(server.paidCalls()).toBe(1);
  });

  it("the gate re-checks the LIVE policy: setPolicy() dropping networks re-closes payment (network)", async () => {
    const server = mockServer();
    const { guard } = makeGuard({ networks: { allow: ["base-sepolia"] } });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({ guard, agentId: "a", pay, fetch: server.fetch });
    expect((await x402("https://api.example.com/data")).status).toBe(200);

    await guard.setPolicy({
      id: "x402-policy",
      version: 2,
      currency: "USDC",
      limits: { perTransactionMinor: 5_000_000, perDayMinor: 20_000_000 },
    });
    const err = await x402("https://api.example.com/data").catch((e) => e);
    expect(err).toBeInstanceOf(X402RequirementRefusedError);
    expect((err as X402RequirementRefusedError).code).toBe("NETWORK_UNGATED");
  });
});
