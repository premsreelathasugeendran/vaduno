/**
 * v2 test doubles. Kept OUT of helpers.ts so the v1 helper file the existing
 * suite depends on stays byte-identical — the point of the port is that v1
 * behavior is provably unchanged.
 */
import type { FetchLike } from "../src/fetch.js";
import { usdc } from "../src/intent.js";

export const b64 = (v: unknown): string =>
  Buffer.from(JSON.stringify(v), "utf8").toString("base64");

export interface MockServerV2Options {
  amount?: string; // atomic string; default 1 USDC
  payTo?: string;
  resourceUrl?: string;
  asset?: string;
  network?: string;
  scheme?: string;
  maxTimeoutSeconds?: number;
  extra?: Record<string, unknown> | null;
  extensions?: Record<string, unknown>;
  /** Raw keys spliced into the requirement — for hostile-shape tests. */
  requirementOverrides?: Record<string, unknown>;
  /** The 402 body (a server implementation concern in v2). Default "{}". */
  body?: BodyInit;
}

export function v2Requirement(o: MockServerV2Options = {}) {
  const req: Record<string, unknown> = {
    scheme: o.scheme ?? "exact",
    network: o.network ?? "eip155:84532",
    amount: o.amount ?? String(usdc(1)),
    payTo: o.payTo ?? "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    asset: o.asset ?? "0xUSDCContract",
    maxTimeoutSeconds: o.maxTimeoutSeconds ?? 60,
    ...(o.extra === null ? {} : { extra: o.extra ?? { symbol: "USDC", decimals: 6 } }),
    ...(o.requirementOverrides ?? {}),
  };
  return req;
}

export function v2PaymentRequired(o: MockServerV2Options = {}) {
  return {
    x402Version: 2,
    resource: { url: o.resourceUrl ?? "https://api.example.com/data" },
    accepts: [v2Requirement(o)],
    ...(o.extensions !== undefined ? { extensions: o.extensions } : {}),
  };
}

/**
 * An in-process x402 v2 server: 402 + PAYMENT-REQUIRED header until a
 * PAYMENT-SIGNATURE header arrives, then 200 + PAYMENT-RESPONSE. The 402 body
 * defaults to "{}" per the reference server.
 */
export function mockServerV2(o: MockServerV2Options = {}) {
  const paymentRequired = v2PaymentRequired(o);
  let initialCalls = 0;
  let paidCalls = 0;
  let lastPaymentSignature: string | null = null;

  const fetch: FetchLike = async (_input, init) => {
    const headers = new Headers(init?.headers);
    if (headers.has("PAYMENT-SIGNATURE")) {
      paidCalls += 1;
      lastPaymentSignature = headers.get("PAYMENT-SIGNATURE");
      const settle = b64({
        success: true,
        transaction: "0xv2settle",
        network: (paymentRequired.accepts[0] as { network: string }).network,
        payer: "0x857b06519E91e3A54538791bDbb0E22373e36b66",
      });
      return new Response("V2 PAID CONTENT", {
        status: 200,
        headers: { "PAYMENT-RESPONSE": settle },
      });
    }
    initialCalls += 1;
    return new Response(o.body ?? "{}", {
      status: 402,
      headers: {
        "Content-Type": "application/json",
        "PAYMENT-REQUIRED": b64(paymentRequired),
      },
    });
  };

  return {
    fetch,
    paymentRequired,
    initialCalls: () => initialCalls,
    paidCalls: () => paidCalls,
    lastPaymentSignature: () => lastPaymentSignature,
  };
}

/**
 * A v2 server whose settlement FAILS the specced way: after receiving
 * PAYMENT-SIGNATURE it answers HTTP 402 again, with a
 * PAYMENT-RESPONSE{success:false} header. The authorization was transmitted,
 * so a correct client counts the spend anyway.
 */
export function settlementFailingServerV2(o: MockServerV2Options = {}) {
  const base = mockServerV2(o);
  let paidCalls = 0;
  const fetch: FetchLike = async (_input, init) => {
    const headers = new Headers(init?.headers);
    if (headers.has("PAYMENT-SIGNATURE")) {
      paidCalls += 1;
      const settle = b64({
        success: false,
        errorReason: "insufficient_funds",
        transaction: "",
        network: (base.paymentRequired.accepts[0] as { network: string }).network,
      });
      return new Response("{}", {
        status: 402,
        headers: { "PAYMENT-RESPONSE": settle },
      });
    }
    return new Response("{}", {
      status: 402,
      headers: {
        "Content-Type": "application/json",
        "PAYMENT-REQUIRED": b64(base.paymentRequired),
      },
    });
  };
  return { ...base, fetch, paidCalls: () => paidCalls };
}
