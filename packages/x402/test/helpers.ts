import { AuditLedger, MemoryLedgerStore, PaygentGuard } from "@paygent/guard";
import type { SpendPolicy } from "@paygent/guard";
import type { FetchLike } from "../src/fetch.js";
import { usdc } from "../src/intent.js";

export function makeGuard(policyOver: Partial<SpendPolicy> = {}) {
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const guard = new PaygentGuard({
    policy: {
      id: "x402-policy",
      version: 1,
      currency: "USDC",
      limits: { perTransactionMinor: usdc(5), perDayMinor: usdc(20) },
      ...policyOver,
    },
    ledger,
  });
  return { guard, ledger };
}

export interface MockServerOptions {
  amount?: string; // atomic string; default 1 USDC
  payTo?: string;
  resource?: string;
  asset?: string;
  symbol?: string;
  decimals?: number;
  scheme?: string;
  network?: string;
}

/**
 * An in-process x402 server: 402 with requirements until an X-PAYMENT header
 * arrives, then 200 with an X-PAYMENT-RESPONSE settlement header.
 */
export function mockServer(o: MockServerOptions = {}) {
  const requirement = {
    scheme: o.scheme ?? "exact",
    network: o.network ?? "base-sepolia",
    maxAmountRequired: o.amount ?? String(usdc(1)),
    resource: o.resource ?? "https://api.example.com/data",
    payTo: o.payTo ?? "0x000000000000000000000000000000000000dEaD",
    asset: o.asset ?? "0xUSDCContract",
    extra: { symbol: o.symbol ?? "USDC", decimals: o.decimals ?? 6 },
  };
  const body = { x402Version: 1, accepts: [requirement] };
  let initialCalls = 0;
  let paidCalls = 0;

  const fetch: FetchLike = async (_input, init) => {
    const headers = new Headers(init?.headers);
    if (headers.has("X-PAYMENT")) {
      paidCalls += 1;
      const settle = Buffer.from(
        JSON.stringify({ success: true, transaction: "0xabc123", network: requirement.network }),
        "utf8",
      ).toString("base64");
      return new Response("PAID CONTENT", {
        status: 200,
        headers: { "X-PAYMENT-RESPONSE": settle },
      });
    }
    initialCalls += 1;
    return new Response(JSON.stringify(body), {
      status: 402,
      headers: { "Content-Type": "application/json" },
    });
  };

  return {
    fetch,
    requirement,
    initialCalls: () => initialCalls,
    paidCalls: () => paidCalls,
  };
}

/** A server that keeps returning 402 even after payment (settlement failure). */
export function alwaysRejectingServer(o: MockServerOptions = {}) {
  const base = mockServer(o);
  const fetch: FetchLike = async (_input, _init) =>
    new Response(JSON.stringify({ x402Version: 1, accepts: [base.requirement] }), {
      status: 402,
      headers: { "Content-Type": "application/json" },
    });
  return { ...base, fetch };
}
