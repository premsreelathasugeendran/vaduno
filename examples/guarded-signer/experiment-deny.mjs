/**
 * EXPERIMENT 2 — DENY. Identical naive live flow to pay.mjs, but the guard's
 * policy caps a transaction at 0.005 USDC while the endpoint asks 0.01. The
 * merchant stays allowlisted so the ONLY denial reason is the cap.
 *
 * Instrumentation: the REAL account is wrapped in a spy before it enters the
 * GuardedAccount. If the guard ever lets a signing call through, the spy
 * records it and prints the signature loudly. Zero spy calls = the denial
 * happened BEFORE a signature existed — not "signed but failed to submit".
 *
 * On-chain proof: payer USDC balance is read from Base Sepolia before the
 * attempt and polled again afterwards; it must be byte-identical.
 */
import { readFileSync } from "node:fs";
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
import { createGuardedAccount, GuardSignerRefusedError } from "./guarded-account.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const CHAIN_ID = 84532;
const NETWORK = "eip155:84532";
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const SELLER = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const MAX_UNITS = 100_000n; // hard testnet rail: never over 0.10 USDC
const TARGET = "https://x402.org/protected";

const realAccount = privateKeyToAccount(
  readFileSync(join(here, "..", "x402-live", ".wallet"), "utf8").trim(),
);
const chain = createPublicClient({ chain: baseSepolia, transport: http() });

// ---- instrumentation: a spy between the guard and the raw key --------------
const spy = { calls: 0, signatures: [] };
const spiedAccount = {
  ...realAccount,
  signTypedData: async (t) => {
    spy.calls += 1;
    const sig = await realAccount.signTypedData(t);
    spy.signatures.push(sig);
    console.log("!!! SPY: real key PRODUCED A SIGNATURE:", sig);
    return sig;
  },
};

// ---- the DENY policy: per-txn cap 0.005 USDC < the 0.01 the seller asks ----
const ledger = new AuditLedger(new JsonlLedgerStore(join(here, "ledger-deny.jsonl")));
const guard = new VadunoGuard({
  policy: {
    id: "guarded-signer-deny-experiment",
    version: 1,
    currency: "USDC",
    limits: { perTransactionMinor: 5_000, perDayMinor: 200_000 }, // $0.005 cap
    merchants: { allow: [`id:${SELLER.toLowerCase()}`] }, // seller IS allowed — only the cap denies
  },
  ledger,
  limiter: new MemorySpendLimiter(),
});

const guarded = createGuardedAccount({
  account: spiedAccount,
  guard,
  agentId: "guarded-signer-deny",
  assets: [{ chainId: CHAIN_ID, address: USDC, symbol: "USDC", decimals: 6 }],
  merchantUrl: TARGET,
});
console.log("payer:", guarded.address);

// ---- balance BEFORE, read from the chain -----------------------------------
const before = await chain.readContract({
  address: USDC, abi: erc20Abi, functionName: "balanceOf", args: [guarded.address],
});
console.log("balance BEFORE:", String(before), "atomic units =", (Number(before) / 1e6).toFixed(6), "USDC");

// ---- the SAME naive purchase flow as pay.mjs -------------------------------
let paidRequestSent = false;
console.log(`GET ${TARGET}`);
const first = await fetch(TARGET);
if (first.status !== 402) {
  console.error(`expected 402, got ${first.status} — aborting`);
  process.exit(1);
}
const paymentRequired = JSON.parse(
  Buffer.from(first.headers.get("PAYMENT-REQUIRED"), "base64").toString("utf8"),
);
const req = paymentRequired.accepts.find(
  (r) => r?.scheme === "exact" && r?.network === NETWORK && r?.asset?.toLowerCase() === USDC.toLowerCase(),
);
if (!req || !/^\d+$/.test(req.amount) || BigInt(req.amount) > MAX_UNITS) {
  console.error("no acceptable testnet requirement — aborting");
  process.exit(1);
}
console.log(`requirement: ${req.amount} units to ${req.payTo} on ${req.network} (policy cap: 5000 units)`);

const now = Math.floor(Date.now() / 1000);
const typedData = {
  domain: {
    name: req.extra?.name ?? "USDC",
    version: req.extra?.version ?? "2",
    chainId: CHAIN_ID,
    verifyingContract: req.asset,
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
  message: {
    from: guarded.address,
    to: req.payTo,
    value: BigInt(req.amount),
    validAfter: 0n,
    validBefore: BigInt(now + (req.maxTimeoutSeconds ?? 300)),
    nonce: `0x${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex")}`,
  },
};

let signature;
try {
  signature = await guarded.signTypedData(typedData);
  // If we get here the guard failed. Complete the purchase so the failure is
  // undeniable in the on-chain evidence, then flag it fatally.
  paidRequestSent = true;
  console.error("FATAL: guard authorized a payment the policy should deny");
} catch (err) {
  if (err instanceof GuardSignerRefusedError) {
    console.log(`guard REFUSED [${err.code}]: ${err.message}`);
  } else {
    throw err;
  }
}

// ---- the proof -------------------------------------------------------------
console.log("\n--- evidence ---");
console.log("signature variable:", signature === undefined ? "undefined (never assigned)" : signature);
console.log("spy: real signTypedData invocations:", spy.calls, "| signatures produced:", spy.signatures.length);
console.log("paid retry request ever sent:", paidRequestSent);

console.log("\naudit ledger rows (deny must be RECORDED, not silent):");
for (const e of await ledger.all()) {
  const extra = e.type === "policy_decision" ? ` ${JSON.stringify(e.data?.reasons ?? e.data)}` : "";
  console.log(" ", e.seq, e.type + extra);
}
console.log("ledger verify:", JSON.stringify(await ledger.verify()));

// Poll the chain: any settlement (there cannot be one — nothing was signed)
// would show as a balance change. Three reads over ~12s.
let after = before;
for (let i = 0; i < 3; i++) {
  await new Promise((r) => setTimeout(r, 4000));
  after = await chain.readContract({
    address: USDC, abi: erc20Abi, functionName: "balanceOf", args: [guarded.address],
  });
  console.log(`balance poll ${i + 1}:`, String(after));
}

console.log("\nbalance BEFORE:", String(before));
console.log("balance AFTER: ", String(after));
if (spy.calls !== 0 || spy.signatures.length !== 0) {
  console.error("RESULT: FAIL — a signature existed. The denial was submit-level, not signer-level.");
  process.exit(1);
}
if (after !== before) {
  console.error("RESULT: FAIL — balance changed despite no signature (impossible unless another spender exists)");
  process.exit(1);
}
console.log(
  "RESULT: DENIED BEFORE SIGNING — zero invocations of the raw key, zero signatures in existence,",
  "\nzero paid requests sent, on-chain balance unchanged. This is a signer-level denial,",
  "\nnot a signed-but-unsubmitted one.",
);
