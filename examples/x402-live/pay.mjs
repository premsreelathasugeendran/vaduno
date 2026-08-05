/**
 * A REAL x402 payment, on a real chain, through the Vaduno guard.
 *
 * Target: https://x402.org/protected — the x402 project's own reference seller.
 * We operate exactly one role in this loop: the payer. The seller, the
 * facilitator, the chain and the faucet are all somebody else's.
 *
 * WHERE THE KEY LIVES: in this file's signer, never in Vaduno. `pay()` is the
 * host's callback; the guard decides whether it may be invoked and records that
 * it was. That separation is the project's central constraint, and this example
 * is what it looks like in practice.
 *
 * RAILS, because a mistake here should be impossible rather than unlikely:
 *  - the chain is pinned to Base Sepolia (84532) and anything else aborts
 *  - the asset is pinned to the known Base Sepolia USDC contract
 *  - the amount is capped far below anything a faucet would give you
 *  - the policy caps it again, independently, inside the guard
 */
import { readFileSync, existsSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicClient, http, erc20Abi } from "viem";
import { baseSepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import {
  AuditLedger,
  JsonlLedgerStore,
  MemorySpendLimiter,
  VadunoGuard,
} from "@vaduno/guard";
import { createX402Fetch } from "@vaduno/x402";

const here = dirname(fileURLToPath(import.meta.url));
const walletPath = join(here, ".wallet");

// ---- rails ----------------------------------------------------------------
const CHAIN_ID = 84532; // Base Sepolia. Nothing else is acceptable.
const NETWORK = "eip155:84532";
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"; // Base Sepolia USDC
const MAX_UNITS = 100_000n; // 0.10 USDC. The endpoint asks 0.01.
const TARGET = "https://x402.org/protected";

if (!existsSync(walletPath)) {
  console.error("No .wallet — run `npm -w x402-live run keygen` first.");
  process.exit(1);
}
const account = privateKeyToAccount(readFileSync(walletPath, "utf8").trim());
const chain = createPublicClient({ chain: baseSepolia, transport: http() });

console.log("payer:", account.address);
const balance = await chain.readContract({
  address: USDC,
  abi: erc20Abi,
  functionName: "balanceOf",
  args: [account.address],
});
console.log("testnet USDC balance:", (Number(balance) / 1e6).toFixed(6));
if (balance === 0n) {
  console.error("\nBalance is zero. Fund at https://faucet.circle.com (Base Sepolia).");
  process.exit(1);
}

// ---- the guard ------------------------------------------------------------
// A deliberately tight policy: $0.05 per transaction, $0.20 per day. The
// endpoint asks $0.01, so the first payment passes and a fifth would not.
const ledgerPath = join(here, "ledger.jsonl");
const ledger = new AuditLedger(new JsonlLedgerStore(ledgerPath));
const guard = new VadunoGuard({
  policy: {
    id: "x402-live",
    version: 1,
    currency: "USDC",
    limits: { perTransactionMinor: 50_000, perDayMinor: 200_000 },
    merchants: { allow: [`id:${"0x209693Bc6afc0C5328bA36FaF03C514EF312287C".toLowerCase()}`] },
  },
  ledger,
  limiter: new MemorySpendLimiter(),
});

// ---- the signer: this is the host's job, not Vaduno's ----------------------
// x402 `exact` on an EVM chain is EIP-3009 transferWithAuthorization: the payer
// signs an off-chain authorization and the FACILITATOR submits it and pays the
// gas. So this wallet needs USDC and no ETH.
async function signExact(req) {
  if (req.network !== NETWORK) throw new Error(`refusing: network ${req.network} is not ${NETWORK}`);
  if (req.asset.toLowerCase() !== USDC.toLowerCase()) {
    throw new Error(`refusing: asset ${req.asset} is not Base Sepolia USDC`);
  }
  const value = BigInt(req.amount);
  if (value > MAX_UNITS) throw new Error(`refusing: ${req.amount} exceeds the example's own cap`);

  const now = Math.floor(Date.now() / 1000);
  const authorization = {
    from: account.address,
    to: req.payTo,
    value,
    validAfter: 0n,
    validBefore: BigInt(now + (req.maxTimeoutSeconds ?? 300)),
    // 32 random bytes: EIP-3009 nonces are arbitrary and single-use, which is
    // what makes an `exact` authorization non-replayable on-chain.
    nonce: `0x${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex")}`,
  };

  const signature = await account.signTypedData({
    domain: {
      name: req.extra?.name ?? "USDC",
      version: req.extra?.version ?? "2",
      chainId: CHAIN_ID,
      verifyingContract: USDC,
    },
    types: {
      TransferWithAuthorization: [
        { name: "from", type: "address" },
        { name: "to", type: "address" },
        { name: "value", type: "uint256" },
        { name: "validAfter", type: "uint256" },
        { name: "validBefore", type: "uint256" },
        { name: "nonce", type: "bytes32" },
      ],
    },
    primaryType: "TransferWithAuthorization",
    message: authorization,
  });

  const payload = {
    x402Version: 2,
    scheme: req.scheme,
    network: req.network,
    payload: {
      signature,
      authorization: {
        from: authorization.from,
        to: authorization.to,
        value: authorization.value.toString(),
        validAfter: authorization.validAfter.toString(),
        validBefore: authorization.validBefore.toString(),
        nonce: authorization.nonce,
      },
    },
  };
  console.log("  signed an EIP-3009 authorization for", req.amount, "units to", req.payTo);
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
}

// ---- run ------------------------------------------------------------------
const x402 = createX402Fetch({
  guard,
  agentId: "live-demo",
  // The reference endpoint declares resource.url on its Vercel deployment while
  // it is served from x402.org. See packages/x402/README.md — the check is right
  // to fire, so we disable it deliberately and pin the RECIPIENT instead, via
  // the id:<payTo> merchant pattern in the policy above. That binds the address
  // that actually receives the money, which is the thing worth binding.
  requireResourceOriginMatch: false,
  assets: [{ network: NETWORK, asset: USDC, symbol: "USDC", decimals: 6 }],
  pay: async () => {
    throw new Error("this endpoint is v2; the v1 path should never be reached");
  },
  v2: { pay: signExact },
  onSettled: (settlement, intentId) => {
    console.log("  settlement:", JSON.stringify(settlement));
    writeFileSync(join(here, "last-settlement.json"), JSON.stringify({ intentId, settlement }, null, 2));
  },
});

console.log(`\nGET ${TARGET}`);
const res = await x402(TARGET);
console.log("HTTP", res.status);
console.log("body:", (await res.text()).slice(0, 300));

console.log("\n--- audit trail ---");
for (const e of await ledger.all()) console.log(" ", e.seq, e.type);
const v = await ledger.verify();
console.log("ledger verify:", JSON.stringify(v));

const after = await chain.readContract({
  address: USDC, abi: erc20Abi, functionName: "balanceOf", args: [account.address],
});
console.log("\nbalance before:", (Number(balance) / 1e6).toFixed(6));
console.log("balance after: ", (Number(after) / 1e6).toFixed(6));
console.log("spent:", (Number(balance - after) / 1e6).toFixed(6), "USDC");
