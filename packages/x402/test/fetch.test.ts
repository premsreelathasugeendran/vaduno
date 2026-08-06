import { describe, expect, it, vi } from "vitest";
import { createX402Fetch } from "../src/fetch.js";
import { X402ProtocolError } from "../src/parse.js";
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
      // This test is ABOUT host-form allowlisting — that merchant.url is
      // derived from the REAL request URL. The adapter now refuses host-form
      // `allow` entries unless the operator opts in (they widen the recipient
      // constraint; see assertRecipientGated), so the opt-in is stated here
      // rather than the property being dropped. The assertion is unchanged.
      allowHostOnlyMerchantPolicy: true,
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
        // See the note above: host-form allowlisting is the property under
        // test here, so the opt-in is explicit.
        allowHostOnlyMerchantPolicy: true,
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

  describe("402 body cap (DoS guard)", () => {
    const CAP = 64 * 1024;

    it("aborts a chunked 402 body (no Content-Length) at the byte cap instead of buffering it all", async () => {
      const { guard } = makeGuard();
      // A hostile server streaming a large body with NO Content-Length header
      // (chunked / HTTP-2 style). 4 MiB total — small enough to run fast, big
      // enough that buffering it all is unambiguous in the counters below.
      const CHUNK = new Uint8Array(16 * 1024).fill(0x61);
      const TOTAL_CHUNKS = 256; // 4 MiB
      let enqueuedBytes = 0;
      let pushed = 0;
      let cancelled = false;
      const stream = new ReadableStream<Uint8Array>({
        pull(controller) {
          if (pushed >= TOTAL_CHUNKS) {
            controller.close();
            return;
          }
          pushed += 1;
          enqueuedBytes += CHUNK.byteLength;
          controller.enqueue(CHUNK);
        },
        cancel() {
          cancelled = true;
        },
      });
      const hostileFetch: FetchLike = async () => new Response(stream, { status: 402 });
      const pay = vi.fn(async () => "payload");
      const x402 = createX402Fetch({ guard, agentId: "agent-1", pay, fetch: hostileFetch });

      const err = await x402("https://api.example.com/data").catch((e) => e);
      expect(err).toBeInstanceOf(X402ProtocolError);
      expect(err.message).toMatch(/too large/);
      expect(pay).not.toHaveBeenCalled();
      // The abort must FIRE: the source stream was cancelled, and only the cap
      // plus a few in-flight chunks was ever pulled — nowhere near the 4 MiB
      // the server offered.
      expect(cancelled).toBe(true);
      expect(enqueuedBytes).toBeLessThanOrEqual(CAP + 4 * CHUNK.byteLength);
    });

    it("measures the cap in BYTES, not UTF-16 code units", async () => {
      const { guard } = makeGuard();
      // 30,000 x U+20AC ("€", 3 bytes in UTF-8) = 90,000 bytes but only
      // 30,000 code units — under the cap by .length, over it by bytes.
      const body = "€".repeat(30_000);
      const sneakyFetch: FetchLike = async () => new Response(body, { status: 402 });
      const pay = vi.fn(async () => "payload");
      const x402 = createX402Fetch({ guard, agentId: "agent-1", pay, fetch: sneakyFetch });

      const err = await x402("https://api.example.com/data").catch((e) => e);
      expect(err).toBeInstanceOf(X402ProtocolError);
      // "too large", NOT the "not an object" parse failure the old code hit
      // after accepting the oversized body.
      expect(err.message).toMatch(/too large/);
      expect(pay).not.toHaveBeenCalled();
    });

    it("still rejects an honest over-cap Content-Length before reading the body", async () => {
      const { guard } = makeGuard();
      // NOTE: the stream machinery itself pre-pulls ONE chunk at construction
      // (default highWaterMark 1) before any reader attaches, so "unread"
      // asserts pulls <= 1 — had the code ignored Content-Length and streamed
      // the body, it would have pulled up to the 64 KB cap (4+ chunks).
      let pulls = 0;
      const CHUNK = new Uint8Array(16 * 1024).fill(0x61);
      const stream = new ReadableStream<Uint8Array>({
        pull(controller) {
          pulls += 1;
          controller.enqueue(CHUNK);
        },
      });
      const declaringFetch: FetchLike = async () =>
        new Response(stream, {
          status: 402,
          headers: { "Content-Length": String(200 * 1024 * 1024) },
        });
      const pay = vi.fn(async () => "payload");
      const x402 = createX402Fetch({ guard, agentId: "agent-1", pay, fetch: declaringFetch });

      const err = await x402("https://api.example.com/data").catch((e) => e);
      expect(err).toBeInstanceOf(X402ProtocolError);
      expect(err.message).toMatch(/too large/);
      expect(pulls).toBeLessThanOrEqual(1);
      expect(pay).not.toHaveBeenCalled();
    });
  });

  it("a wrong-typed extra.symbol surfaces as X402ProtocolError, not a bare TypeError", async () => {
    const { guard } = makeGuard();
    const server: FetchLike = async () =>
      new Response(
        JSON.stringify({
          x402Version: 1,
          accepts: [
            {
              scheme: "exact",
              network: "base-sepolia",
              maxAmountRequired: String(usdc(1)),
              resource: "https://api.example.com/data",
              payTo: "0xdEaD",
              asset: "0xUSDCContract",
              extra: { symbol: 12345, decimals: 6 },
            },
          ],
        }),
        { status: 402, headers: { "Content-Type": "application/json" } },
      );
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({ guard, agentId: "agent-1", pay, fetch: server });

    // A caller catching the documented X402* set must see this failure.
    const err = await x402("https://api.example.com/data").catch((e) => e);
    expect(err).toBeInstanceOf(X402ProtocolError);
    expect(pay).not.toHaveBeenCalled();
  });
});

describe("the v1 path carries the same redirect protection as v2", () => {
  it("redirect:'manual' rides on BOTH the probe and the paid retry", async () => {
    // A 3xx must never carry the probe — or, far worse, the paid retry with its
    // X-PAYMENT bearer — to a different origin: that would defeat both the
    // resource-origin check and the host allowlist in one hop. v2 pinned this
    // from the start; v1 relied on the option being set and nothing asserted it,
    // so a change to "follow" was caught only by the v2 suite.
    const redirects: Array<RequestInit["redirect"]> = [];
    const inner = mockServer();
    const spying: FetchLike = async (input, init) => {
      redirects.push(init?.redirect);
      return inner.fetch(input, init);
    };
    const { guard } = makeGuard();
    const x402 = createX402Fetch({
      guard,
      agentId: "a",
      pay: async () => "v1-payload",
      fetch: spying,
    });
    await x402("https://api.example.com/data");
    expect(redirects).toEqual(["manual", "manual"]);
  });
});
