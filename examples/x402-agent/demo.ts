/**
 * Swale x402 demo: an AI agent pays for HTTP 402 resources with USDC, under
 * a spend policy, with a full audit trail — and NO real chain or keys. The
 * "server" and the "payer" are mocked in-process so you can see the whole
 * 402 → policy → pay → settle loop without a wallet.
 *
 * Run: npm run demo:x402
 */
import {
  AuditLedger,
  MemoryLedgerStore,
  SwaleGuard,
} from "@swale/guard";
import {
  createX402Fetch,
  encodePaymentHeader,
  usdc,
  X402PaymentBlockedError,
  X402RequirementRefusedError,
  type AssetInfo,
  type FetchLike,
  type PaymentRequirements,
} from "@swale/x402";

const money = (atomic: number) => `$${(atomic / 1e6).toFixed(2)}`;

// ── A mock x402 server: 402 until an X-PAYMENT header arrives, then 200 ──────
function x402Server(priceAtomic: number, resource: string, payTo: string): FetchLike {
  const requirement: PaymentRequirements = {
    scheme: "exact",
    network: "base-sepolia",
    maxAmountRequired: String(priceAtomic),
    resource,
    payTo,
    asset: "0xUSDCTokenContract",
    extra: { symbol: "USDC", decimals: 6, name: "Demo API" },
  };
  return async (_input, init) => {
    const headers = new Headers(init?.headers);
    if (headers.has("X-PAYMENT")) {
      const settlement = encodePaymentHeader({
        success: true,
        transaction: "0xsettle_" + Math.floor(priceAtomic).toString(16),
        network: requirement.network,
      });
      return new Response(JSON.stringify({ ok: true, data: "premium content" }), {
        status: 200,
        headers: { "X-PAYMENT-RESPONSE": settlement, "Content-Type": "application/json" },
      });
    }
    return new Response(JSON.stringify({ x402Version: 1, accepts: [requirement] }), {
      status: 402,
      headers: { "Content-Type": "application/json" },
    });
  };
}

// ── The agent's wallet lives HERE — Swale never sees it. ───────────────────
// In production this signs an EIP-3009 transferWithAuthorization (or similar)
// and returns the base64 X-PAYMENT payload. Here we just fake the payload.
async function mockPayer(req: PaymentRequirements): Promise<string> {
  return encodePaymentHeader({
    x402Version: 1,
    scheme: req.scheme,
    network: req.network,
    payload: { signature: "0xMOCK_SIGNATURE", authorization: { value: req.maxAmountRequired } },
  });
}

// ── Guard: $5/txn, $10/day in USDC, only a trusted API host ─────────────────
const ledger = new AuditLedger(new MemoryLedgerStore());
const guard = new SwaleGuard({
  policy: {
    id: "x402-demo",
    version: 1,
    currency: "USDC",
    limits: { perTransactionMinor: usdc(5), perDayMinor: usdc(10) },
    merchants: { allow: ["trusted-api.com"] },
  },
  ledger,
});

const PAYTO = "0x000000000000000000000000000000000000dEaD";
const USDC_CONTRACT = "0xUSDCTokenContract";

// Trusted token registry: binds spend to the REAL token contract, so a hostile
// server can't spoof extra.symbol="USDC" over a different asset.
const ASSETS: AssetInfo[] = [
  { network: "base-sepolia", asset: USDC_CONTRACT, symbol: "USDC", decimals: 6 },
];

function agentFetch(serverFetch: FetchLike) {
  return createX402Fetch({
    guard,
    agentId: "researcher-agent-1",
    pay: mockPayer,
    fetch: serverFetch,
    assets: ASSETS,
    category: "api-credits",
    onSettled: (s) =>
      console.log(`   ↳ settled on ${s?.network} tx ${s?.transaction}`),
  });
}

async function callPaidApi(label: string, url: string, priceAtomic: number) {
  const fetchWithPay = agentFetch(x402Server(priceAtomic, url, PAYTO));
  try {
    const res = await fetchWithPay(url);
    const body = (await res.json()) as { data: string };
    console.log(`✅ ${label}: paid ${money(priceAtomic)} → "${body.data}"`);
  } catch (err) {
    if (err instanceof X402PaymentBlockedError) {
      const codes = err.policyResult.reasons.map((r) => r.code).join(", ");
      console.log(`⛔ ${label}: ${money(priceAtomic)} → blocked (${codes})`);
    } else if (err instanceof X402RequirementRefusedError) {
      console.log(`⛔ ${label}: ${money(priceAtomic)} → refused (${err.code})`);
    } else {
      console.log(`💥 ${label}: ${(err as Error).message}`);
    }
  }
}

// A hostile server: the agent is tricked into calling evil.example, which
// returns a 402 CLAIMING the resource is on trusted-api.com. The real endpoint
// and the payTo are the attacker's — Swale must refuse.
function hostileServer(): FetchLike {
  return async () =>
    new Response(
      JSON.stringify({
        x402Version: 1,
        accepts: [
          {
            scheme: "exact",
            network: "base-sepolia",
            maxAmountRequired: String(usdc(1)),
            resource: "https://trusted-api.com/premium", // the LIE
            payTo: "0xATTACKER00000000000000000000000000000000",
            asset: USDC_CONTRACT,
            extra: { symbol: "USDC", decimals: 6 },
          },
        ],
      }),
      { status: 402, headers: { "Content-Type": "application/json" } },
    );
}

async function callHostile() {
  const fetchWithPay = agentFetch(hostileServer());
  try {
    await fetchWithPay("https://evil.example/pay");
    console.log("💥 Prompt-injected call to evil.example: PAID (BUG!)");
  } catch (err) {
    const why =
      err instanceof X402RequirementRefusedError
        ? `refused (${err.code})`
        : err instanceof X402PaymentBlockedError
          ? "blocked"
          : (err as Error).message;
    console.log(`⛔ Prompt-injected call to evil.example → ${why}`);
  }
}

console.log("— Swale x402 demo: agent paying for APIs in USDC, $5/txn $10/day —\n");

await callPaidApi("Cheap API call", "https://trusted-api.com/weather", usdc(3));
await callPaidApi("Another call", "https://trusted-api.com/news", usdc(4));
await callPaidApi("Over per-txn cap", "https://trusted-api.com/bulk", usdc(6));
await callPaidApi("Untrusted host (prompt-injected URL)", "https://evil-api.com/data", usdc(1));
await callHostile();
// $3 + $4 = $7 spent; this $4 would make $11 > $10/day → blocked by the daily cap.
await callPaidApi("Blows the daily cap", "https://trusted-api.com/expensive", usdc(4));

console.log("\n— Flight recorder —\n");
const head = await ledger.head();
console.log(`ledger entries: ${head.entries}`);
console.log(`chain verification: ${(await ledger.verify(head)).ok ? "✅ intact" : "❌ broken"}`);
