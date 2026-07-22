import { describe, expect, it, vi } from "vitest";
import { createX402Fetch } from "../src/fetch.js";
import { usdc } from "../src/intent.js";
import {
  X402PaymentBlockedError,
  X402PaymentFailedError,
  X402RequirementRefusedError,
} from "../src/errors.js";
import type { FetchLike } from "../src/fetch.js";
import { alwaysRejectingServer, makeGuard, mockServer } from "./helpers.js";

describe("createX402Fetch", () => {
  it("passes non-402 responses straight through without paying", async () => {
    const { guard } = makeGuard();
    const pay = vi.fn(async () => "payload");
    const okFetch = async () => new Response("hello", { status: 200 });
    const x402 = createX402Fetch({ guard, agentId: "agent-1", pay, fetch: okFetch });
    const res = await x402("https://api.example.com/free");
    expect(res.status).toBe(200);
    expect(pay).not.toHaveBeenCalled();
  });

  it("pays an allowed 402 and returns the paid response", async () => {
    const { guard, ledger } = makeGuard();
    const server = mockServer({ amount: String(usdc(1)) });
    const pay = vi.fn(async () => "signed-payment-payload");
    let settledTx: string | undefined;

    const x402 = createX402Fetch({
      guard,
      agentId: "agent-1",
      pay,
      fetch: server.fetch,
      onSettled: (s) => (settledTx = s?.transaction),
    });

    const res = await x402("https://api.example.com/data");
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("PAID CONTENT");
    expect(pay).toHaveBeenCalledOnce();
    expect(server.initialCalls()).toBe(1);
    expect(server.paidCalls()).toBe(1);
    expect(settledTx).toBe("0xabc123");

    const entries = await ledger.all();
    expect(entries.some((e) => e.type === "execution_result")).toBe(true);
    expect((await ledger.verify()).ok).toBe(true);
  });

  it("blocks an over-limit payment and never calls the payer", async () => {
    const { guard } = makeGuard({ limits: { perTransactionMinor: usdc(0.5) } });
    const server = mockServer({ amount: String(usdc(1)) });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({ guard, agentId: "agent-1", pay, fetch: server.fetch });

    await expect(x402("https://api.example.com/data")).rejects.toBeInstanceOf(
      X402PaymentBlockedError,
    );
    expect(pay).not.toHaveBeenCalled();
    expect(server.paidCalls()).toBe(0);
  });

  it("blocks when the (real) request host is not on the allowlist", async () => {
    const { guard } = makeGuard({ merchants: { allow: ["trusted-api.com"] } });
    // resource origin matches the request; host allowlist should still deny.
    const server = mockServer({ resource: "https://evil-api.com/data" });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({
      guard,
      agentId: "agent-1",
      pay,
      fetch: server.fetch,
    });

    await expect(x402("https://evil-api.com/data")).rejects.toBeInstanceOf(
      X402PaymentBlockedError,
    );
    expect(pay).not.toHaveBeenCalled();
  });

  describe("host-allowlist bypass fix (critical)", () => {
    it("refuses when the server claims a resource on a different origin", async () => {
      const { guard } = makeGuard({ merchants: { allow: ["trusted-api.com"] } });
      // Agent is prompt-injected to evil.com; server LIES that resource is trusted.
      const server = mockServer({ resource: "https://trusted-api.com/premium" });
      const pay = vi.fn(async () => "payload");
      const x402 = createX402Fetch({ guard, agentId: "agent-1", pay, fetch: server.fetch });

      await expect(x402("https://evil.com/pay")).rejects.toBeInstanceOf(
        X402RequirementRefusedError,
      );
      expect(pay).not.toHaveBeenCalled();
    });

    it("even with origin-check off, the host allowlist binds the REAL url not the claim", async () => {
      const { guard } = makeGuard({ merchants: { allow: ["trusted-api.com"] } });
      const server = mockServer({ resource: "https://trusted-api.com/premium" });
      const pay = vi.fn(async () => "payload");
      const x402 = createX402Fetch({
        guard,
        agentId: "agent-1",
        pay,
        fetch: server.fetch,
        requireResourceOriginMatch: false,
      });

      // merchant.url is evil.com (the real endpoint) -> not on the allowlist.
      await expect(x402("https://evil.com/pay")).rejects.toBeInstanceOf(
        X402PaymentBlockedError,
      );
      expect(pay).not.toHaveBeenCalled();
    });
  });

  describe("asset registry (symbol-spoofing fix)", () => {
    const registry = [
      { network: "base-sepolia", asset: "0xUSDCContract", symbol: "USDC", decimals: 6 },
    ];

    it("allows a requirement whose (network, asset) is registered", async () => {
      const { guard } = makeGuard();
      const server = mockServer({ asset: "0xUSDCContract" });
      const pay = vi.fn(async () => "payload");
      const x402 = createX402Fetch({
        guard,
        agentId: "agent-1",
        pay,
        fetch: server.fetch,
        assets: registry,
      });
      const res = await x402("https://api.example.com/data");
      expect(res.status).toBe(200);
    });

    it("refuses a spoofed symbol on an unregistered asset", async () => {
      const { guard } = makeGuard();
      // Hostile: claims symbol USDC but the real token contract is different.
      const server = mockServer({ asset: "0xHighValueToken", symbol: "USDC" });
      const pay = vi.fn(async () => "payload");
      const x402 = createX402Fetch({
        guard,
        agentId: "agent-1",
        pay,
        fetch: server.fetch,
        assets: registry,
      });
      const err = await x402("https://api.example.com/data").catch((e) => e);
      expect(err).toBeInstanceOf(X402RequirementRefusedError);
      expect(err.code).toBe("ASSET_NOT_ALLOWED");
      expect(pay).not.toHaveBeenCalled();
    });
  });

  it("refuses (not fails) when select returns undefined", async () => {
    const { guard } = makeGuard();
    const server = mockServer();
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({
      guard,
      agentId: "agent-1",
      pay,
      fetch: server.fetch,
      select: () => undefined,
    });
    await expect(x402("https://api.example.com/data")).rejects.toBeInstanceOf(
      X402RequirementRefusedError,
    );
    expect(pay).not.toHaveBeenCalled();
  });

  it("denies a currency mismatch (policy USD vs token USDC)", async () => {
    const { guard } = makeGuard({ currency: "USD" });
    const server = mockServer({ symbol: "USDC" });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({ guard, agentId: "agent-1", pay, fetch: server.fetch });
    await expect(x402("https://api.example.com/data")).rejects.toBeInstanceOf(
      X402PaymentBlockedError,
    );
  });

  it("counts the spend when the server errors AFTER receiving X-PAYMENT (pessimistic)", async () => {
    const { guard, ledger } = makeGuard();
    const server = alwaysRejectingServer(); // still 402 even after payment
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({ guard, agentId: "agent-1", pay, fetch: server.fetch });

    const err = await x402("https://api.example.com/data").catch((e) => e);
    expect(err).toBeInstanceOf(X402PaymentFailedError);
    expect(err.transmitted).toBe(true);
    expect(pay).toHaveBeenCalledOnce();

    // The authorization was transmitted -> spend IS counted (execution_result success).
    const exec = (await ledger.all()).find((e) => e.type === "execution_result");
    expect((exec!.data as { success: boolean }).success).toBe(true);
    expect((await ledger.verify()).ok).toBe(true);
  });

  it("denies an unsafe/huge maxAmountRequired (fail closed)", async () => {
    const { guard } = makeGuard();
    const server = mockServer({ amount: "99999999999999999999999" });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({ guard, agentId: "agent-1", pay, fetch: server.fetch });
    await expect(x402("https://api.example.com/data")).rejects.toBeInstanceOf(
      X402PaymentBlockedError,
    );
    expect(pay).not.toHaveBeenCalled();
  });

  it("enforces the daily cap across multiple x402 calls", async () => {
    const { guard } = makeGuard({
      limits: { perTransactionMinor: usdc(8), perDayMinor: usdc(10) },
    });
    const server = mockServer({ amount: String(usdc(6)) });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({ guard, agentId: "agent-1", pay, fetch: server.fetch });

    const first = await x402("https://api.example.com/data");
    expect(first.status).toBe(200);
    await expect(x402("https://api.example.com/data")).rejects.toBeInstanceOf(
      X402PaymentBlockedError,
    );
  });

  it("re-sends a buffered request body on the paid retry (Request input)", async () => {
    const { guard } = makeGuard();
    const bodies: string[] = [];
    const server: FetchLike = async (_input, init) => {
      const headers = new Headers(init?.headers);
      const bodyText =
        init?.body instanceof ArrayBuffer
          ? new TextDecoder().decode(init.body)
          : typeof init?.body === "string"
            ? init.body
            : "";
      bodies.push(bodyText);
      if (headers.has("X-PAYMENT")) {
        return new Response("ok", { status: 200 });
      }
      return new Response(
        JSON.stringify({
          x402Version: 1,
          accepts: [
            {
              scheme: "exact",
              network: "base-sepolia",
              maxAmountRequired: String(usdc(1)),
              resource: "https://api.example.com/post",
              payTo: "0xdEaD",
              asset: "0xUSDCContract",
              extra: { symbol: "USDC", decimals: 6 },
            },
          ],
        }),
        { status: 402, headers: { "Content-Type": "application/json" } },
      );
    };
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({ guard, agentId: "agent-1", pay, fetch: server });

    const req = new Request("https://api.example.com/post", {
      method: "POST",
      body: "important-payload",
    });
    const res = await x402(req);
    expect(res.status).toBe(200);
    // The probe and the paid retry both saw the same body.
    expect(bodies).toEqual(["important-payload", "important-payload"]);
  });
});
