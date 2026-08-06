/**
 * The SAME live x402 purchase as examples/x402-live/pay.mjs — but with the
 * guard inside the SIGNER instead of wrapped around fetch.
 *
 * The point being proven: this script's HTTP flow is deliberately naive. It
 * consults no policy, checks no allowlist, holds no budget. Every control in
 * this run lives inside the GuardedAccount, at the one place a payment
 * signature can come into existence. If the guard says no, there is no
 * signature — and a payment that was never signed cannot be settled by
 * anyone, anywhere.
 *
 * That is the answer to "a seatbelt the driver must choose to buckle is
 * telemetry, not a firewall": here the belt is welded to the ignition. The
 * driver (this script) does not get a vote at signing time. The remaining
 * honest caveat — the developer chooses to construct the car this way — is
 * documented in README.md, not hidden.
 *
 * RAILS, same as the reference example:
 *  - Base Sepolia (84532) only; the asset registry contains ONLY Base Sepolia
 *    USDC, so any other chain or token is refused before a signature exists
 *  - the script's own cap aborts anything over 0.10 USDC
 *  - the guard's policy caps again at 0.05 USDC per txn / 0.20 per day
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
import { createGuardedAccount, GuardSignerRefusedError } from "./guarded-account.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const walletPath = join(here, "..", "x402-live", ".wallet");

// ---- rails ----------------------------------------------------------------
const CHAIN_ID = 84532; // Base Sepolia. Nothing else is acceptable.
const NETWORK = "eip155:84532";
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"; // Base Sepolia USDC
const SELLER = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"; // x402.org payTo
const MAX_UNITS = 100_000n; // 0.10 USDC. The endpoint asks 0.01.
const TARGET = "https://x402.org/protected";

if (!existsSync(walletPath)) {
  console.error("No wallet — run `npm -w x402-live run keygen` first (reuses that example's wallet).");
  process.exit(1);
}
const realAccount = privateKeyToAccount(readFileSync(walletPath, "utf8").trim());
const chain = createPublicClient({ chain: baseSepolia, transport: http() });

// ---- the guard, living INSIDE the signer ----------------------------------
const ledgerPath = join(here, "ledger.jsonl");
const ledger = new AuditLedger(new JsonlLedgerStore(ledgerPath));
const guard = new VadunoGuard({
  policy: {
    id: "guarded-signer-live",
    version: 1,
    currency: "USDC",
    limits: { perTransactionMinor: 50_000, perDayMinor: 200_000 }, // $0.05 / $0.20
    merchants: { allow: [`id:${SELLER.toLowerCase()}`] },
  },
  ledger,
  limiter: new MemorySpendLimiter(),
});

const guarded = createGuardedAccount({
  account: realAccount,
  guard,
  agentId: "guarded-signer-demo",
  assets: [{ chainId: CHAIN_ID, address: USDC, symbol: "USDC", decimals: 6 }],
  // The policy above is denominated in USDC atomic units (perTransactionMinor
  // 50000 = $0.05), so the currency's minor unit has 6 decimals. Stated
  // explicitly rather than inferred: a registry that ever gained a second
  // "USDC" asset at a different granularity would otherwise become
  // unresolvable, and this is the one number that says which one is meant.
  currencyDecimals: 6,
  merchantUrl: TARGET,
});
console.log("payer:", guarded.address);

// ---- helpers ---------------------------------------------------------------
const eip3009Types = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};

function randomNonce() {
  return `0x${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex")}`;
}

function transferTypedData({ to, value, chainId = CHAIN_ID, asset = USDC, name = "USDC", version = "2" }) {
  const now = Math.floor(Date.now() / 1000);
  return {
    domain: { name, version, chainId, verifyingContract: asset },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: {
      from: guarded.address,
      to,
      value,
      validAfter: 0n,
      validBefore: BigInt(now + 300),
      nonce: randomNonce(),
    },
  };
}

/** A hostile/buggy call MUST throw. Producing a signature is fatal. */
async function mustRefuse(label, fn) {
  try {
    await fn();
  } catch (err) {
    const tag = err instanceof GuardSignerRefusedError ? err.code : err.name;
    console.log(`  refused [${tag}] — ${label}`);
    return;
  }
  console.error(`\nFATAL: "${label}" produced a signature. The guard is NOT in the mandatory path.`);
  process.exit(1);
}

// ---- phase 1: prove the choke point, offline -------------------------------
// None of these touch the network or move anything; each one must fail to
// produce a signature. A single signature here disproves the whole claim.
console.log("\n[1/3] adversarial signing attempts (all must be refused):");

await mustRefuse("0.06 USDC to the allowlisted seller (over the $0.05 per-txn cap)", () =>
  guarded.signTypedData(transferTypedData({ to: SELLER, value: 60_000n })),
);
await mustRefuse("0.01 USDC to a NON-allowlisted recipient", () =>
  guarded.signTypedData(transferTypedData({ to: "0xdeAD00000000000000000000000000000000dEAd", value: 10_000n })),
);
await mustRefuse("0.01 'USDC' on Base MAINNET (chain 8453 — unknown asset, refused)", () =>
  guarded.signTypedData(
    transferTypedData({
      to: SELLER,
      value: 10_000n,
      chainId: 8453,
      asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    }),
  ),
);
await mustRefuse("an EIP-2612 Permit (open-ended approval, unrecognized shape)", () =>
  guarded.signTypedData({
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: { Permit: [{ name: "owner", type: "address" }, { name: "spender", type: "address" }, { name: "value", type: "uint256" }, { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" }] },
    primaryType: "Permit",
    message: { owner: guarded.address, spender: SELLER, value: 2n ** 256n - 1n, nonce: 0n, deadline: 2n ** 48n },
  }),
);
await mustRefuse("signTransaction() — the raw-tx capability is stubbed out", () =>
  guarded.signTransaction({ to: SELLER, value: 0n, chainId: CHAIN_ID }),
);
await mustRefuse("signMessage() — ditto for raw message signing", () =>
  guarded.signMessage({ message: "sign anything" }),
);

// The wrapped account must not be reachable through the wrapper.
for (const [key, value] of Object.entries(guarded)) {
  if (value === realAccount) {
    console.error(`FATAL: guarded.${key} exposes the real account — that is a bypass.`);
    process.exit(1);
  }
}
console.log("  verified — no property of the wrapper references the real account");

// ---- phase 2: the live purchase, policy enforced ONLY by the signer --------
console.log("\n[2/3] live x402 v2 purchase (Base Sepolia testnet):");

const balance = await chain.readContract({
  address: USDC, abi: erc20Abi, functionName: "balanceOf", args: [guarded.address],
});
console.log("  testnet USDC balance:", (Number(balance) / 1e6).toFixed(6));
if (balance === 0n) {
  console.error("  Balance is zero. Fund at https://faucet.circle.com (Base Sepolia).");
  process.exit(1);
}

const seqBeforePurchase = (await ledger.all()).length;

console.log(`  GET ${TARGET}`);
const first = await fetch(TARGET);
if (first.status !== 402) {
  console.error(`  expected 402, got ${first.status} — aborting`);
  process.exit(1);
}
const prHeader = first.headers.get("PAYMENT-REQUIRED");
if (!prHeader) {
  console.error("  no PAYMENT-REQUIRED header (endpoint no longer v2?) — aborting");
  process.exit(1);
}
const paymentRequired = JSON.parse(Buffer.from(prHeader, "base64").toString("utf8"));
if (paymentRequired.x402Version !== 2 || !Array.isArray(paymentRequired.accepts)) {
  console.error("  malformed PAYMENT-REQUIRED payload — aborting");
  process.exit(1);
}
const req = paymentRequired.accepts.find(
  (r) => r?.scheme === "exact" && r?.network === NETWORK && r?.asset?.toLowerCase() === USDC.toLowerCase(),
);
if (!req) {
  console.error("  no exact/eip155:84532/USDC requirement offered — aborting (testnet only, ever)");
  process.exit(1);
}
if (!/^\d+$/.test(req.amount) || BigInt(req.amount) > MAX_UNITS) {
  console.error(`  requirement asks ${req.amount} units > example cap ${MAX_UNITS} — aborting`);
  process.exit(1);
}
console.log(`  requirement: ${req.amount} units to ${req.payTo} on ${req.network}`);

// The authorization to sign. Note what this script does NOT do here: no
// merchant check, no cap check, no budget. The signer is the firewall.
const now = Math.floor(Date.now() / 1000);
const authorization = {
  from: guarded.address,
  to: req.payTo,
  value: BigInt(req.amount),
  validAfter: 0n,
  validBefore: BigInt(now + (req.maxTimeoutSeconds ?? 300)),
  nonce: randomNonce(),
};
const typedData = {
  domain: {
    name: req.extra?.name ?? "USDC",
    version: req.extra?.version ?? "2",
    chainId: CHAIN_ID,
    verifyingContract: req.asset,
  },
  types: eip3009Types,
  primaryType: "TransferWithAuthorization",
  message: authorization,
};

// THE ONLY GATE IN THIS ENTIRE FILE. Policy, spend limiter and audit ledger
// all run inside this call, before the key is touched.
const signature = await guarded.signTypedData(typedData);
console.log("  guard allowed; EIP-3009 authorization signed");

// v2 PaymentPayload — `accepted` is a REQUIRED verbatim echo of the chosen
// requirement (x402 spec §5.2); omitting it is what every early attempt got
// wrong. Same construction as examples/x402-live/pay.mjs.
const payload = {
  x402Version: 2,
  resource: paymentRequired.resource,
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

const paid = await fetch(TARGET, {
  headers: { "PAYMENT-SIGNATURE": Buffer.from(JSON.stringify(payload), "utf8").toString("base64") },
});
console.log("  HTTP", paid.status);
console.log("  body:", (await paid.text()).slice(0, 200));
const settlementHeader = paid.headers.get("PAYMENT-RESPONSE");
let settlementTx = null;
if (settlementHeader) {
  const settlement = JSON.parse(Buffer.from(settlementHeader, "base64").toString("utf8"));
  console.log("  settlement:", JSON.stringify(settlement));
  settlementTx = typeof settlement?.transaction === "string" ? settlement.transaction : null;
  writeFileSync(join(here, "last-settlement.json"), JSON.stringify(settlement, null, 2));
}

// ---- phase 3: idempotency + the evidence -----------------------------------
console.log("\n[3/3] idempotent replay of the SAME authorization:");
const again = await guarded.signTypedData(typedData);
if (again !== signature) {
  console.error("FATAL: replay produced a different signature");
  process.exit(1);
}
console.log("  same signature re-issued; guard counted the spend ONCE (replay, not a new charge)");

console.log("\n--- audit trail (this run's entries) ---");
const entries = await ledger.all();
for (const e of entries.slice(seqBeforePurchase)) console.log(" ", e.seq, e.type);
const successRows = entries
  .slice(seqBeforePurchase)
  .filter((e) => e.type === "execution_result" && e.data && e.data.success === true);
if (successRows.length !== 1) {
  console.error(`FATAL: expected exactly 1 countable success row for this purchase, found ${successRows.length}`);
  process.exit(1);
}
console.log("countable success rows for this purchase: 1 (the replay added none)");
const v = await ledger.verify();
console.log("ledger verify:", JSON.stringify(v));

// WHAT MOVED, FROM THE TRANSACTION'S OWN LOG — not from a balance read.
//
// A balance poll is the wrong instrument here, and the sibling example proved
// it twice: the 200 means the facilitator ACCEPTED the authorization, not that
// the transfer landed, and even after waiting for the receipt the public RPC
// is load-balanced, so the node answering `balanceOf` can be behind the node
// that answered the receipt (pinning the read to the settlement block fails
// differently again — "block not found"). Each of those printed a spend of
// ZERO for a payment that had settled. The receipt carries the ERC-20 Transfer
// event, it is exact, and it arrived with the receipt, so it cannot lag. The
// loop that used to live here got the right answer on the runs it was tried
// on, which is not the same as being right.
if (settlementTx) {
  console.log(`\nwaiting for settlement tx ${settlementTx} …`);
  const receipt = await chain.waitForTransactionReceipt({ hash: settlementTx });
  console.log(`  mined in block ${receipt.blockNumber}, status: ${receipt.status}`);
  const transfers = parseEventLogs({ abi: erc20Abi, eventName: "Transfer", logs: receipt.logs })
    .filter(
      (l) =>
        l.address.toLowerCase() === USDC.toLowerCase() &&
        l.args.from.toLowerCase() === guarded.address.toLowerCase(),
    );
  if (transfers.length === 0) {
    console.log("  no USDC Transfer FROM this payer in that transaction");
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
const latest = await chain.readContract({
  address: USDC, abi: erc20Abi, functionName: "balanceOf", args: [guarded.address],
});
console.log("balance at start:", (Number(balance) / 1e6).toFixed(6));
console.log("balance now:     ", (Number(latest) / 1e6).toFixed(6), "(read at 'latest', which may lag)");
