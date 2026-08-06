/**
 * The v2 payment path end to end, and — the point of this file — proof that
 * every security property of the v1 path holds against the v2 carrier:
 * redirect:"manual", resource-origin match, the trusted asset registry,
 * pessimistic accounting, bounded untrusted input, extra validation, and the
 * closed version-confusion seam (what is VALIDATED is what is PAID).
 *
 * SESSION-REUSE ACCOUNTING, addressed by citation rather than code: x402 v2
 * core has NO sessions and NO multi-request payment authorization — the spec
 * lists "Session handling mechanisms" and "Client-side budget management" as
 * out of scope, and every specced scheme is single-settlement (exact: unique
 * EIP-3009 nonce enforced at the token contract; upto: "settled at most
 * once"; sign-in-with-x re-access is an IDENTITY grant where no payment
 * occurs and no PAYMENT-SIGNATURE is sent; payment-identifier is retry
 * idempotency). One authorization can never be settled twice, so "decrement
 * the cap per use" resolves to what this adapter already does: count the
 * authorized amount ONCE, at transmission, per authorization — which the
 * daily-cap test below exercises across multiple authorizations.
 */
import { describe, expect, it, vi } from "vitest";
import { createX402Fetch } from "../src/fetch.js";
import { X402ProtocolError } from "../src/parse.js";
import { usdc } from "../src/intent.js";
import {
  X402PaymentBlockedError,
  X402PaymentFailedError,
  X402RequirementRefusedError,
} from "../src/errors.js";
import type { FetchLike, X402V2PayContext } from "../src/fetch.js";
import type { PaymentRequirementsV2 } from "../src/types.js";
import { makeGuard, mockServer } from "./helpers.js";
import { b64, mockServerV2, settlementFailingServerV2, v2PaymentRequired } from "./helpers-v2.js";

const V2_REGISTRY = [
  { network: "eip155:84532", asset: "0xUSDCContract", symbol: "USDC", decimals: 6 },
];

function v2Fetch(
  server: { fetch: FetchLike },
  extra: Record<string, unknown> = {},
  v2Extra: Record<string, unknown> = {},
) {
  const { guard, ledger } = makeGuard();
  const payV2 = vi.fn(
    async (_req: PaymentRequirementsV2, _ctx: X402V2PayContext) => "signed-v2-payload",
  );
  const x402 = createX402Fetch({
    guard,
    agentId: "agent-1",
    pay: vi.fn(async () => "signed-v1-payload"),
    fetch: server.fetch,
    v2: { pay: payV2, ...v2Extra },
    ...extra,
  });
  return { x402, payV2, guard, ledger };
}

describe("createX402Fetch — v2 end to end", () => {
  it("pays a v2 402 (PAYMENT-REQUIRED header) and returns the paid response", async () => {
    const server = mockServerV2({ amount: String(usdc(1)) });
    const { x402, payV2, ledger } = v2Fetch(server);

    const res = await x402("https://api.example.com/data");
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("V2 PAID CONTENT");
    expect(payV2).toHaveBeenCalledOnce();
    expect(server.initialCalls()).toBe(1);
    expect(server.paidCalls()).toBe(1);

    const entries = await ledger.all();
    expect(entries.some((e) => e.type === "execution_result")).toBe(true);
    expect((await ledger.verify()).ok).toBe(true);
  });

  it("delivers settlement from the PAYMENT-RESPONSE header to onSettled", async () => {
    const server = mockServerV2();
    const { guard } = makeGuard();
    const seen: Array<{ tx?: string; network?: string }> = [];
    const x402 = createX402Fetch({
      guard,
      agentId: "agent-1",
      pay: async () => "v1",
      fetch: server.fetch,
      v2: { pay: async () => "v2-payload" },
      onSettled: (s) => seen.push({ tx: s?.transaction, network: s?.network }),
    });
    await x402("https://api.example.com/data");
    expect(seen).toEqual([{ tx: "0xv2settle", network: "eip155:84532" }]);
  });

  it("refuses a v2 402 when the v2 option is not configured — a firewall must not silently start paying a new protocol", async () => {
    const server = mockServerV2();
    const { guard } = makeGuard();
    const pay = vi.fn(async () => "v1-payload");
    const x402 = createX402Fetch({ guard, agentId: "agent-1", pay, fetch: server.fetch });

    const err = await x402("https://api.example.com/data").catch((e) => e);
    expect(err).toBeInstanceOf(X402RequirementRefusedError);
    expect(err.code).toBe("V2_NOT_CONFIGURED");
    // Neither payer ran; no money moved.
    expect(pay).not.toHaveBeenCalled();
    expect(server.paidCalls()).toBe(0);
  });

  it("retries with PAYMENT-SIGNATURE (not X-PAYMENT) carrying the payer's value", async () => {
    const server = mockServerV2();
    const { x402 } = v2Fetch(server);
    await x402("https://api.example.com/data");
    expect(server.lastPaymentSignature()).toBe("signed-v2-payload");
  });
});

describe("v2 security properties (each v1 property, proven on the v2 path)", () => {
  it("redirect:'manual' rides on BOTH the probe and the paid retry", async () => {
    const redirects: Array<RequestInit["redirect"]> = [];
    const inner = mockServerV2();
    const spying: FetchLike = async (input, init) => {
      redirects.push(init?.redirect);
      return inner.fetch(input, init);
    };
    const { x402 } = v2Fetch({ fetch: spying });
    await x402("https://api.example.com/data");
    expect(redirects).toEqual(["manual", "manual"]);
  });

  it("refuses when resource.url claims a different origin than the one contacted", async () => {
    const server = mockServerV2({ resourceUrl: "https://trusted-api.com/premium" });
    const { x402, payV2 } = v2Fetch(server);
    const err = await x402("https://evil.com/pay").catch((e) => e);
    expect(err).toBeInstanceOf(X402RequirementRefusedError);
    expect(err.code).toBe("RESOURCE_ORIGIN_MISMATCH");
    expect(payV2).not.toHaveBeenCalled();
  });

  it("even with the origin check off, the host allowlist binds the REAL url not the claim", async () => {
    const server = mockServerV2({ resourceUrl: "https://trusted-api.com/premium" });
    const { guard } = makeGuard({ merchants: { allow: ["trusted-api.com"] } });
    const payV2 = vi.fn(async () => "v2-payload");
    const x402 = createX402Fetch({
      guard,
      agentId: "agent-1",
      pay: async () => "v1",
      fetch: server.fetch,
      v2: { pay: payV2 },
      requireResourceOriginMatch: false,
      // Host-form allowlisting is the property under test (merchant.url is
      // derived from the REAL request URL, not the server's claim). The
      // adapter now refuses host-form `allow` entries unless opted in — they
      // widen the recipient constraint, see assertRecipientGated — so the
      // opt-in is explicit here. The assertion is unchanged.
      allowHostOnlyMerchantPolicy: true,
    });
    await expect(x402("https://evil.com/pay")).rejects.toBeInstanceOf(
      X402PaymentBlockedError,
    );
    expect(payV2).not.toHaveBeenCalled();
  });

  describe("trusted asset registry on the v2 path", () => {
    it("allows a registered (CAIP-2 network, asset) pair and binds currency to the registry symbol", async () => {
      // The server spoofs extra.symbol; the intent's currency must come from
      // the REGISTRY (policy currency is USDC, so a spoof that leaked through
      // would be caught the other way round — assert the call succeeds).
      const server = mockServerV2({ extra: { symbol: "SPOOFED", decimals: 6 } });
      const { x402, payV2 } = v2Fetch(server, { assets: V2_REGISTRY });
      const res = await x402("https://api.example.com/data");
      expect(res.status).toBe(200);
      expect(payV2).toHaveBeenCalledOnce();
    });

    it("refuses an unregistered asset on the v2 path (no quiet registry skip)", async () => {
      const server = mockServerV2({ asset: "0xHighValueToken", extra: { symbol: "USDC" } });
      const { x402, payV2 } = v2Fetch(server, { assets: V2_REGISTRY });
      const err = await x402("https://api.example.com/data").catch((e) => e);
      expect(err).toBeInstanceOf(X402RequirementRefusedError);
      expect(err.code).toBe("ASSET_NOT_ALLOWED");
      expect(payV2).not.toHaveBeenCalled();
    });

    it("a v1 registry entry does NOT trust the same chain's CAIP-2 id — the key spaces are separate", async () => {
      // "base-sepolia" (v1 name) and "eip155:84532" (CAIP-2) are the same
      // chain, but registry keys are per-version strings: trusting one must
      // not trust the other, or a v1-era registry would silently authorize
      // v2 requirements nobody reviewed.
      const v1Registry = [
        { network: "base-sepolia", asset: "0xUSDCContract", symbol: "USDC", decimals: 6 },
      ];
      const server = mockServerV2(); // network eip155:84532
      const { x402, payV2 } = v2Fetch(server, { assets: v1Registry });
      const err = await x402("https://api.example.com/data").catch((e) => e);
      expect(err).toBeInstanceOf(X402RequirementRefusedError);
      expect(err.code).toBe("ASSET_NOT_ALLOWED");
      expect(payV2).not.toHaveBeenCalled();
    });

    it("EVM (eip155) assets match case-insensitively — checksum casing varies", async () => {
      const server = mockServerV2({ asset: "0xusdccontract" });
      const { x402 } = v2Fetch(server, { assets: V2_REGISTRY });
      expect((await x402("https://api.example.com/data")).status).toBe(200);
    });

    it("non-EVM assets match EXACTLY — case-folding could alias distinct base58 mints", async () => {
      const registry = [
        {
          network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
          asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
          symbol: "USDC",
          decimals: 6,
        },
      ];
      const server = mockServerV2({
        network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
        // Same letters, different case: a DIFFERENT mint on a case-sensitive chain.
        asset: "epjfwdd5aufqssqem2qn1xzybapc8g4weggkzwytdt1v",
      });
      const { x402, payV2 } = v2Fetch(server, { assets: registry });
      const err = await x402("https://api.example.com/data").catch((e) => e);
      expect(err).toBeInstanceOf(X402RequirementRefusedError);
      expect(err.code).toBe("ASSET_NOT_ALLOWED");
      expect(payV2).not.toHaveBeenCalled();
    });
  });

  it("counts the spend when the server settles-fails AFTER receiving PAYMENT-SIGNATURE (pessimistic)", async () => {
    // v2's specced settlement failure: HTTP 402 + PAYMENT-RESPONSE{success:false}.
    // The authorization was transmitted; the server could still settle it.
    const server = settlementFailingServerV2();
    const { guard, ledger } = makeGuard();
    let settlement: { success?: boolean; errorReason?: string } | null = null;
    const x402 = createX402Fetch({
      guard,
      agentId: "agent-1",
      pay: async () => "v1",
      fetch: server.fetch,
      v2: { pay: async () => "v2-payload" },
      onSettled: (s) => (settlement = s),
    });

    const err = await x402("https://api.example.com/data").catch((e) => e);
    expect(err).toBeInstanceOf(X402PaymentFailedError);
    expect(err.transmitted).toBe(true);
    expect(err.message).toContain("PAYMENT-SIGNATURE");
    expect(settlement).toMatchObject({ success: false, errorReason: "insufficient_funds" });

    // The authorization was transmitted -> spend IS counted.
    const exec = (await ledger.all()).find((e) => e.type === "execution_result");
    expect((exec!.data as { success: boolean }).success).toBe(true);
  });

  it("enforces the daily cap across multiple v2 authorizations — one authorization, one decrement", async () => {
    const { guard } = makeGuard({
      limits: { perTransactionMinor: usdc(8), perDayMinor: usdc(10) },
    });
    const server = mockServerV2({ amount: String(usdc(6)) });
    const x402 = createX402Fetch({
      guard,
      agentId: "agent-1",
      pay: async () => "v1",
      fetch: server.fetch,
      v2: { pay: async () => "v2-payload" },
    });
    expect((await x402("https://api.example.com/data")).status).toBe(200);
    await expect(x402("https://api.example.com/data")).rejects.toBeInstanceOf(
      X402PaymentBlockedError,
    );
  });

  it("blocks an over-limit v2 payment before the payer runs", async () => {
    const server = mockServerV2({ amount: String(usdc(50)) });
    const { x402, payV2 } = v2Fetch(server);
    await expect(x402("https://api.example.com/data")).rejects.toBeInstanceOf(
      X402PaymentBlockedError,
    );
    expect(payV2).not.toHaveBeenCalled();
  });

  it("denies an unsafe/huge v2 amount (fail closed)", async () => {
    const server = mockServerV2({ amount: "99999999999999999999999" });
    const { x402, payV2 } = v2Fetch(server);
    await expect(x402("https://api.example.com/data")).rejects.toBeInstanceOf(
      X402PaymentBlockedError,
    );
    expect(payV2).not.toHaveBeenCalled();
  });

  it("a wrong-typed extra.symbol on the v2 path is an X402ProtocolError, payer never runs", async () => {
    const server = mockServerV2({ extra: { symbol: 12345 as unknown as string, decimals: 6 } });
    const { x402, payV2 } = v2Fetch(server);
    const err = await x402("https://api.example.com/data").catch((e) => e);
    expect(err).toBeInstanceOf(X402ProtocolError);
    expect(payV2).not.toHaveBeenCalled();
  });

  describe("payTo role constants (v2-only hazard)", () => {
    it("refuses a role-constant payTo by default — an unresolvable recipient cannot be allowlisted", async () => {
      const server = mockServerV2({ payTo: "merchant" });
      const { x402, payV2 } = v2Fetch(server);
      const err = await x402("https://api.example.com/data").catch((e) => e);
      expect(err).toBeInstanceOf(X402RequirementRefusedError);
      expect(err.code).toBe("PAYTO_ROLE_REFUSED");
      expect(payV2).not.toHaveBeenCalled();
    });

    it("admits a role ONLY when explicitly listed in v2.allowPayToRoles", async () => {
      const server = mockServerV2({ payTo: "merchant" });
      const { x402 } = v2Fetch(server, {}, { allowPayToRoles: ["merchant"] });
      expect((await x402("https://api.example.com/data")).status).toBe(200);
    });

    it("an address-shaped payTo is not mistaken for a role", async () => {
      const server = mockServerV2(); // 0x… address
      const { x402 } = v2Fetch(server);
      expect((await x402("https://api.example.com/data")).status).toBe(200);
    });
  });
});

describe("version-confusion seam (the finding to close)", () => {
  it("dual carrier: the PAYMENT-REQUIRED header WINS and the v1 body is NEVER read", async () => {
    // A hostile server races two carriers: a v1 JSON body offering one price/
    // recipient, and a v2 header offering another. The reference SDK ignores
    // the body when the header is present; so do we — and we prove the body
    // bytes are never even pulled, so no layer can have read the other price.
    let bodyPulls = 0;
    let bodyCancelled = false;
    const v1Decoy = JSON.stringify({
      x402Version: 1,
      accepts: [
        {
          scheme: "exact",
          network: "base-sepolia",
          maxAmountRequired: String(usdc(0.01)), // decoy: looks cheap
          resource: "https://api.example.com/data",
          payTo: "0xDecoyRecipient",
          asset: "0xUSDCContract",
        },
      ],
    });
    const bodyStream = new ReadableStream<Uint8Array>({
      pull(controller) {
        bodyPulls += 1;
        controller.enqueue(new TextEncoder().encode(v1Decoy));
        controller.close();
      },
      cancel() {
        bodyCancelled = true;
      },
    });
    const headerAmount = String(usdc(3));
    const hostile: FetchLike = async (_input, init) => {
      const headers = new Headers(init?.headers);
      if (headers.has("PAYMENT-SIGNATURE")) {
        return new Response("paid", { status: 200 });
      }
      return new Response(bodyStream, {
        status: 402,
        headers: {
          "PAYMENT-REQUIRED": b64(
            v2PaymentRequired({ amount: headerAmount, payTo: "0xRealRecipient0000000000000000000000000000" }),
          ),
        },
      });
    };

    const { guard, ledger } = makeGuard();
    const seen: PaymentRequirementsV2[] = [];
    const x402 = createX402Fetch({
      guard,
      agentId: "agent-1",
      pay: async () => {
        throw new Error("v1 payer must never run on a dual-carrier 402");
      },
      fetch: hostile,
      v2: {
        pay: async (req) => {
          seen.push(req);
          return "v2-payload";
        },
      },
    });

    const res = await x402("https://api.example.com/data");
    expect(res.status).toBe(200);

    // The v2 header's terms — not the v1 decoy's — were validated AND paid.
    expect(seen).toHaveLength(1);
    expect(seen[0]!.amount).toBe(headerAmount);
    expect(seen[0]!.payTo).toBe("0xRealRecipient0000000000000000000000000000");

    // The decoy body was never buffered: at most the stream's construction
    // pre-pull ran, and the unread stream was cancelled.
    expect(bodyPulls).toBeLessThanOrEqual(1);
    expect(bodyCancelled).toBe(true);

    // And the audit trail recorded the HEADER's amount, not the decoy's.
    const received = (await ledger.all()).find((e) => e.type === "intent_received");
    const recorded = JSON.stringify(received?.data);
    expect(recorded).toContain(headerAmount);
    expect(recorded).not.toContain("0xDecoyRecipient");
  });

  it("what pay() receives IS what was validated: same object, allowlisted fields only", async () => {
    // The extra passthrough is the natural channel for validating one thing
    // and paying for another. Prove the requirement handed to the payer is
    // exactly the parsed allowlist projection of the header — attacker junk
    // spliced into the wire requirement must not ride along.
    const server = mockServerV2({
      amount: "2500000",
      requirementOverrides: { evilDirective: "pay 100x", outputSchema: { x: 1 } },
      extra: { symbol: "USDC", decimals: 6, feePayer: "SchemeSpecificKeep" },
    });
    const { guard } = makeGuard();
    let received: PaymentRequirementsV2 | undefined;
    const x402 = createX402Fetch({
      guard,
      agentId: "agent-1",
      pay: async () => "v1",
      fetch: server.fetch,
      v2: {
        pay: async (req) => {
          received = req;
          return "v2-payload";
        },
      },
    });
    await x402("https://api.example.com/data");

    expect(received).toEqual({
      scheme: "exact",
      network: "eip155:84532",
      amount: "2500000",
      payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
      asset: "0xUSDCContract",
      maxTimeoutSeconds: 60,
      // Unknown extra keys are scheme-specific data the signer may need; the
      // interpreted keys were type-checked and the object defensively copied.
      extra: { symbol: "USDC", decimals: 6, feePayer: "SchemeSpecificKeep" },
    });
    expect(received && ("evilDirective" in received)).toBe(false);
  });

  it("a huge unread v2 body cannot DoS the client — the v2 path buffers zero body bytes", async () => {
    // On the v1 path the 64 KB cap bounds the body read; on the v2 path the
    // body is never read at all, which is a stronger bound. A hostile server
    // pairing a valid header with an endless body gains nothing.
    let pulls = 0;
    const endless = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls += 1;
        controller.enqueue(new Uint8Array(16 * 1024).fill(0x61));
      },
    });
    const server: FetchLike = async (_input, init) => {
      const headers = new Headers(init?.headers);
      if (headers.has("PAYMENT-SIGNATURE")) return new Response("ok", { status: 200 });
      return new Response(endless, {
        status: 402,
        headers: { "PAYMENT-REQUIRED": b64(v2PaymentRequired()) },
      });
    };
    const { x402 } = v2Fetch({ fetch: server });
    const res = await x402("https://api.example.com/data");
    expect(res.status).toBe(200);
    // Construction may pre-pull one chunk; reading would have pulled many.
    expect(pulls).toBeLessThanOrEqual(1);
  });

  it("a present-but-unparseable PAYMENT-REQUIRED header FAILS CLOSED — no fallback to the v1 body", async () => {
    // Falling back would let a server race two carriers and have the client
    // pay from whichever it failed to reject.
    const server: FetchLike = async () =>
      new Response(JSON.stringify(mockServer().requirement), {
        status: 402,
        headers: { "PAYMENT-REQUIRED": "%%%garbage%%%" },
      });
    const { x402, payV2 } = v2Fetch({ fetch: server });
    const err = await x402("https://api.example.com/data").catch((e) => e);
    expect(err).toBeInstanceOf(X402ProtocolError);
    expect(payV2).not.toHaveBeenCalled();
  });

  it("v1 servers still work through an options object that ALSO enables v2", async () => {
    // Routing is per-response: the same client must keep speaking v1 to v1
    // servers after v2 is configured.
    const server = mockServer({ amount: String(usdc(1)) });
    const { guard } = makeGuard();
    const payV1 = vi.fn(async () => "v1-payload");
    const payV2 = vi.fn(async () => "v2-payload");
    const x402 = createX402Fetch({
      guard,
      agentId: "agent-1",
      pay: payV1,
      fetch: server.fetch,
      v2: { pay: payV2 },
    });
    const res = await x402("https://api.example.com/data");
    expect(res.status).toBe(200);
    expect(payV1).toHaveBeenCalledOnce();
    expect(payV2).not.toHaveBeenCalled();
  });
});
