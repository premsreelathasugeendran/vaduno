/**
 * Vaduno x402 demo: an AI agent pays for HTTP 402 resources with USDC, under
 * a spend policy, with a full audit trail — and NO real chain or keys. The
 * "server" and the "payer" are mocked in-process so you can see the whole
 * 402 → policy → pay → settle loop without a wallet.
 *
 * Run: npm run demo:x402
 */
import {
  AuditLedger,
  MemoryLedgerStore,
  VadunoGuard,
} from "@vaduno/guard";
import {
  createX402Fetch,
  encodePaymentHeader,
  usdc,
  X402PaymentBlockedError,
  X402RequirementRefusedError,
  type AssetInfo,
  type FetchLike,
  type PaymentRequirements,
  type PaymentRequirementsV2,
  type X402V2PayContext,
} from "@vaduno/x402";

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

// ── A mock x402 V2 server: all protocol data in HEADERS, body is just "{}" ──
// 402 + PAYMENT-REQUIRED (base64 PaymentRequired) until a PAYMENT-SIGNATURE
// header arrives, then 200 + PAYMENT-RESPONSE.
function x402ServerV2(priceAtomic: number, resourceUrl: string, payTo: string): FetchLike {
  const paymentRequired = {
    x402Version: 2,
    resource: { url: resourceUrl, description: "Demo API (x402 v2)" },
    accepts: [
      {
        scheme: "exact",
        network: "eip155:84532", // CAIP-2 in v2 — a different registry key than "base-sepolia"
        amount: String(priceAtomic),
        payTo,
        asset: "0xUSDCTokenContract",
        maxTimeoutSeconds: 60,
        extra: { symbol: "USDC", decimals: 6, name: "Demo API" },
      },
    ],
  };
  return async (_input, init) => {
    const headers = new Headers(init?.headers);
    if (headers.has("PAYMENT-SIGNATURE")) {
      const settlement = encodePaymentHeader({
        success: true,
        transaction: "0xv2settle_" + Math.floor(priceAtomic).toString(16),
        network: "eip155:84532",
      });
      return new Response(JSON.stringify({ ok: true, data: "premium content (v2)" }), {
        status: 200,
        headers: { "PAYMENT-RESPONSE": settlement, "Content-Type": "application/json" },
      });
    }
    return new Response("{}", {
      status: 402,
      headers: {
        "Content-Type": "application/json",
        "PAYMENT-REQUIRED": encodePaymentHeader(paymentRequired),
      },
    });
  };
}

// ── The agent's wallet lives HERE — Vaduno never sees it. ───────────────────
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

// The v2 payer builds the PAYMENT-SIGNATURE value. It MUST echo exactly the
// requirement it was handed as `accepted` — the same object Vaduno validated.
async function mockPayerV2(
  req: PaymentRequirementsV2,
  ctx: X402V2PayContext,
): Promise<string> {
  return encodePaymentHeader({
    x402Version: 2,
    resource: ctx.resource,
    accepted: req,
    payload: { signature: "0xMOCK_SIGNATURE_V2", authorization: { value: req.amount } },
    ...(ctx.extensions
      ? {
          extensions: Object.fromEntries(
            Object.entries(ctx.extensions).map(([id, e]) => [id, { info: e.info }]),
          ),
        }
      : {}),
  });
}

const PAYTO = "0x000000000000000000000000000000000000dEaD";
const USDC_CONTRACT = "0xUSDCTokenContract";

// ── Guard: $5/txn, $10/day in USDC, one allowed RECIPIENT ───────────────────
// The allowlist names the recipient (`id:<payTo>`), not the host. On x402 the
// two are decoupled: `payTo` is an arbitrary address the server puts in its
// 402, and `payTo` — not the request URL — is what the payer's authorization
// commits to. A host-form entry in `merchants.allow` therefore reads as a
// merchant control while constraining no recipient, and because `allow` is
// disjunctive it can only ever WIDEN, so @vaduno/x402 refuses such a policy up
// front (RECIPIENT_UNGATED). This demo used to carry exactly that mistake.
//
// Host patterns still belong in `merchants.block`, where a match always denies
// and disjunction only tightens — that is what stops the off-allowlist call
// below. A blocklist does not scale to the open web; it is the honest half of
// what a host pattern can do on this rail.
const ledger = new AuditLedger(new MemoryLedgerStore());
const guard = new VadunoGuard({
  policy: {
    id: "x402-demo",
    version: 1,
    currency: "USDC",
    limits: { perTransactionMinor: usdc(5), perDayMinor: usdc(10) },
    merchants: { allow: [`id:${PAYTO}`], block: ["evil-api.com"] },
    // Currency is not a chain: USDC exists on many of them, and the v1 network
    // NAME and the v2 CAIP-2 id are separate key spaces, so the same chain is
    // authored twice — exactly like the asset registry below.
    networks: { allow: ["base-sepolia", "eip155:84532"] },
  },
  ledger,
});

// Trusted token registry: binds spend to the REAL token contract, so a hostile
// server can't spoof extra.symbol="USDC" over a different asset. v1 names and
// v2 CAIP-2 ids are SEPARATE keys — the same chain must be authored twice.
const ASSETS: AssetInfo[] = [
  { network: "base-sepolia", asset: USDC_CONTRACT, symbol: "USDC", decimals: 6 },
  { network: "eip155:84532", asset: USDC_CONTRACT, symbol: "USDC", decimals: 6 },
];

function agentFetch(serverFetch: FetchLike) {
  return createX402Fetch({
    guard,
    agentId: "researcher-agent-1",
    pay: mockPayer,
    v2: { pay: mockPayerV2 }, // opt-in: without this, v2 402s are refused
    fetch: serverFetch,
    assets: ASSETS,
    category: "api-credits",
    onSettled: (s) =>
      console.log(`   ↳ settled on ${s?.network} tx ${s?.transaction}`),
  });
}

async function callApi(label: string, priceAtomic: number, url: string, server: FetchLike) {
  const fetchWithPay = agentFetch(server);
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

async function callPaidApi(label: string, url: string, priceAtomic: number) {
  await callApi(label, priceAtomic, url, x402Server(priceAtomic, url, PAYTO));
}

async function callPaidApiV2(label: string, url: string, priceAtomic: number) {
  await callApi(label, priceAtomic, url, x402ServerV2(priceAtomic, url, PAYTO));
}

// A hostile server: the agent is tricked into calling evil.example, which
// returns a 402 CLAIMING the resource is on trusted-api.com. The real endpoint
// and the payTo are the attacker's — Vaduno must refuse.
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

// A v2 server offering a payTo ROLE CONSTANT instead of an address. Vaduno
// refuses it by default: an unresolvable recipient cannot be allowlisted.
async function callV2RolePayTo() {
  const url = "https://trusted-api.com/role";
  await callApi("v2 server with payTo role \"merchant\"", usdc(1), url,
    x402ServerV2(usdc(1), url, "merchant"));
}

console.log("— Vaduno x402 demo: agent paying for APIs in USDC, $5/txn $10/day —\n");

await callPaidApi("Cheap API call (v1)", "https://trusted-api.com/weather", usdc(3));
await callPaidApi("Another call (v1)", "https://trusted-api.com/news", usdc(4));
// Same agent, same policy, same caps — but this server speaks x402 v2:
// PaymentRequired arrives in the PAYMENT-REQUIRED header, the paid retry
// carries PAYMENT-SIGNATURE, and the network id is CAIP-2.
await callPaidApiV2("Premium call (v2, header transport)", "https://trusted-api.com/quotes", usdc(2));
await callPaidApi("Over per-txn cap", "https://trusted-api.com/bulk", usdc(6));
// A prompt-injected URL on a blocklisted host — note the server there names the
// SAME allowed payTo, so the recipient allowlist alone would have paid it. The
// host blocklist is what refuses.
await callPaidApi("Blocklisted host (prompt-injected URL)", "https://evil-api.com/data", usdc(1));
await callHostile();
await callV2RolePayTo();
// $3 + $4 + $2 = $9 spent; this $4 would make $13 > $10/day → daily cap blocks
// it, and v1/v2 spends share ONE budget — the protocol version cannot reset caps.
await callPaidApi("Blows the daily cap", "https://trusted-api.com/expensive", usdc(4));

console.log("\n— Flight recorder —\n");
const head = await ledger.head();
console.log(`ledger entries: ${head.entries}`);
console.log(`chain verification: ${(await ledger.verify(head)).ok ? "✅ intact" : "❌ broken"}`);
