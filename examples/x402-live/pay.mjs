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
import { createPublicClient, http, erc20Abi, parseEventLogs } from "viem";
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
async function signExact(req, ctx) {
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

  // The v2 PaymentPayload (x402 spec §5.2): `accepted` is a REQUIRED verbatim
  // echo of the requirement we are paying — the server deep-equals it against
  // its own requirement, and the facilitator cross-checks the authorization
  // against it. Omitting it is what every earlier attempt got wrong.
  const payload = {
    x402Version: 2,
    resource: ctx.resource,
    accepted: {
      scheme: req.scheme,
      network: req.network,
      amount: req.amount,
      payTo: req.payTo,
      asset: req.asset,
      maxTimeoutSeconds: req.maxTimeoutSeconds,
      extra: req.extra,
    },
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
/** The facilitator's settlement tx hash, captured from onSettled. */
let settlementTx = null;

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
    settlementTx = typeof settlement?.transaction === "string" ? settlement.transaction : null;
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

// WAIT FOR THE SETTLEMENT TX BEFORE READING THE BALANCE. The 200 comes back as
// soon as the facilitator ACCEPTS the authorization; the transfer lands a block
// or two later. Reading the balance straight after the response therefore
// printed "spent: 0.000000 USDC" for a payment that had, in fact, settled — a
// report that understates what happened is as wrong as one that overstates it,
// and this one told a reader the example costs nothing. Block on the receipt
// the facilitator named, and say plainly when there is nothing to block on.
// WHAT ACTUALLY MOVED, taken from the settlement transaction's own Transfer
// log rather than from a balance read.
//
// Two balance-based versions of this block printed "spent: 0.000000 USDC" for
// a payment that had genuinely settled, for two different reasons. Reading
// right after the 200: the 200 means the facilitator ACCEPTED the
// authorization, not that the transfer landed. Reading "latest" right after
// waiting for the receipt: the public RPC is load-balanced, and the node
// answering the balance call was behind the one that answered the receipt
// call. Pinning the read to the settlement block failed too — that node did
// not have the block yet ("block not found"). Every one of those is the same
// mistake, which is asking a node about STATE when the evidence is an EVENT:
// the receipt carries the ERC-20 Transfer log, it is exact, and it cannot lag
// because it arrived with the receipt. A report that understates a payment is
// as wrong as one that overstates it.
if (settlementTx) {
  console.log(`\nwaiting for settlement tx ${settlementTx} …`);
  const receipt = await chain.waitForTransactionReceipt({ hash: settlementTx });
  console.log(`  mined in block ${receipt.blockNumber}, status: ${receipt.status}`);
  const transfers = parseEventLogs({ abi: erc20Abi, eventName: "Transfer", logs: receipt.logs })
    .filter(
      (l) =>
        l.address.toLowerCase() === USDC.toLowerCase() &&
        l.args.from.toLowerCase() === account.address.toLowerCase(),
    );
  if (transfers.length === 0) {
    console.log("  no USDC Transfer FROM this payer in that transaction — nothing left this wallet");
  }
  for (const t of transfers) {
    console.log(
      `  moved ${(Number(t.args.value) / 1e6).toFixed(6)} USDC -> ${t.args.to} ` +
        "(decoded from the settlement transaction's own log)",
    );
  }
} else {
  console.log("\nno settlement tx was reported, so there is no receipt to decode.");
}
// Secondary, and labelled as such: the wallet balance at whatever height this
// RPC is currently serving. Indicative only — see above.
console.log("balance at start:", (Number(balance) / 1e6).toFixed(6));
const latest = await chain.readContract({
  address: USDC, abi: erc20Abi, functionName: "balanceOf", args: [account.address],
});
console.log("balance now:     ", (Number(latest) / 1e6).toFixed(6), "(read at 'latest', which may lag)");
