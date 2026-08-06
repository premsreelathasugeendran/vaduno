/**
 * Does the LEDGER record what was actually SIGNED?
 *
 * The audit ledger keys every row on `intentId = sig:<EIP-712 digest>`. That is
 * a claim about cryptography, so it should be checked against the chain rather
 * than against the wrapper that wrote it.
 *
 * This script trusts NOTHING from the wrapper, the seller, or the facilitator:
 *
 *   1. Fetch the settlement transaction from Base Sepolia and decode its INPUT
 *      data as USDC's `transferWithAuthorization(from,to,value,validAfter,
 *      validBefore,nonce,v,r,s)`. Those are the authorization fields the token
 *      contract actually consumed.
 *   2. Read `DOMAIN_SEPARATOR()` from the USDC contract itself — not from a
 *      hardcoded {name, version}, so the domain is the token's own, not ours.
 *   3. Recompute the EIP-712 digest: keccak256(0x1901 ‖ domainSeparator ‖
 *      structHash) over the decoded fields.
 *   4. Recover the signer from (digest, r, s, v) and require it to equal `from`.
 *   5. Require that digest to equal the digest embedded in the ledger's
 *      intentId, and the ledger's merchant/amount to equal the on-chain
 *      `to`/`value`.
 *   6. Verify the hash chain.
 *
 * If all six hold, the row the guard wrote is bound to the bytes the key
 * signed — the ledger cannot be certifying a payment other than the one that
 * settled.
 *
 * Usage: node verify-ledger-binding.mjs [txHash]
 *        (defaults to the tx in last-settlement.json)
 */
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createPublicClient,
  http,
  decodeFunctionData,
  parseAbi,
  encodeAbiParameters,
  keccak256,
  concatHex,
  recoverAddress,
} from "viem";
import { baseSepolia } from "viem/chains";
import { AuditLedger, JsonlLedgerStore } from "@vaduno/guard";

const here = dirname(fileURLToPath(import.meta.url));
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";

const txHash =
  process.argv[2] ??
  JSON.parse(readFileSync(join(here, "last-settlement.json"), "utf8")).transaction;

const chain = createPublicClient({ chain: baseSepolia, transport: http() });

const fail = (msg) => {
  console.error(`FAIL: ${msg}`);
  process.exit(1);
};

// ---------------------------------------------------------------- 1. on-chain
const tx = await chain.getTransaction({ hash: txHash });
const receipt = await chain.getTransactionReceipt({ hash: txHash });
if (receipt.status !== "success") fail(`receipt status is ${receipt.status}`);
if (tx.to.toLowerCase() !== USDC.toLowerCase())
  fail(`tx target ${tx.to} is not Base Sepolia USDC`);

const abi = parseAbi([
  "function transferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce,uint8 v,bytes32 r,bytes32 s)",
]);
let decoded;
try {
  decoded = decodeFunctionData({ abi, data: tx.input });
} catch (err) {
  fail(`tx input is not transferWithAuthorization: ${err.message}`);
}
const [from, to, value, validAfter, validBefore, nonce, v, r, s] = decoded.args;
console.log("1. on-chain authorization, decoded from the transaction INPUT:");
console.log(`   from=${from}`);
console.log(`   to=${to}`);
console.log(`   value=${value}  validAfter=${validAfter}  validBefore=${validBefore}`);
console.log(`   nonce=${nonce}`);

// ------------------------------------------------- 2. the token's OWN domain
const domainSeparator = await chain.readContract({
  address: USDC,
  abi: parseAbi(["function DOMAIN_SEPARATOR() view returns (bytes32)"]),
  functionName: "DOMAIN_SEPARATOR",
});
console.log(`\n2. DOMAIN_SEPARATOR() read from the USDC contract: ${domainSeparator}`);

// ------------------------------------------------------- 3. recompute digest
const TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
  new TextEncoder().encode(
    "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
  ),
);
const structHash = keccak256(
  encodeAbiParameters(
    [
      { type: "bytes32" },
      { type: "address" },
      { type: "address" },
      { type: "uint256" },
      { type: "uint256" },
      { type: "uint256" },
      { type: "bytes32" },
    ],
    [TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce],
  ),
);
const digest = keccak256(concatHex(["0x1901", domainSeparator, structHash]));
console.log(`\n3. recomputed EIP-712 digest: ${digest}`);

// -------------------------------------------------------- 4. recover the signer
const signature = concatHex([r, s, `0x${v.toString(16).padStart(2, "0")}`]);
const recovered = await recoverAddress({ hash: digest, signature });
if (recovered.toLowerCase() !== from.toLowerCase())
  fail(`recovered signer ${recovered} != authorization from ${from}`);
console.log(`\n4. recovered signer from (digest, r, s, v): ${recovered}  == from ✓`);

// --------------------------------------------------------- 5. the ledger row
const ledger = new AuditLedger(new JsonlLedgerStore(join(here, "ledger.jsonl")));
const rows = await ledger.all();
const wantId = `sig:${digest.toLowerCase()}`;
const mine = rows.filter((e) => String(e.intentId).toLowerCase() === wantId);
if (mine.length === 0) {
  fail(
    `no ledger row is keyed on ${wantId} — the ledger is NOT keyed on the digest that settled`,
  );
}
console.log(`\n5. ledger rows keyed on ${wantId}: ${mine.length}`);
for (const e of mine) console.log(`   seq ${e.seq}  ${e.type}`);

const received = mine.find((e) => e.type === "intent_received");
if (!received) fail("no intent_received row for the settled digest");
const intent = received.data.intent;

const checks = [
  [
    "ledger merchant.id == on-chain Transfer recipient",
    String(intent.merchant.id).toLowerCase(),
    to.toLowerCase(),
  ],
  [
    "ledger amountMinor == on-chain value (6-decimal USDC, identity scaling)",
    String(intent.amount.amountMinor),
    String(value),
  ],
  [
    "ledger metadata.digest == recomputed digest",
    String(intent.metadata.digest).toLowerCase(),
    digest.toLowerCase(),
  ],
  ["ledger metadata.asset == USDC", String(intent.metadata.asset).toLowerCase(), USDC.toLowerCase()],
  ["ledger metadata.chainId == 84532", String(intent.metadata.chainId), "84532"],
  ["ledger network == eip155:84532", String(intent.network), "eip155:84532"],
];
let bad = 0;
console.log("");
for (const [label, got, want] of checks) {
  const ok = got === want;
  if (!ok) bad++;
  console.log(`   ${ok ? "✓" : "✗"} ${label}\n       ledger=${got}  chain=${want}`);
}
if (bad) fail(`${bad} ledger field(s) disagree with the chain`);

const decision = mine.find((e) => e.type === "policy_decision");
if (!decision) fail("no policy_decision row for the settled digest");
if (decision.data.policyResult.decision !== "allow")
  fail(`policy_decision for the settled payment is "${decision.data.policyResult.decision}"`);
console.log(`\n   ✓ a policy_decision=allow row exists for this exact digest`);

// ------------------------------------------------------- 6. the hash chain
const verified = await ledger.verify();
console.log(`\n6. ledger.verify(): ${JSON.stringify(verified)}`);
if (!verified.ok) fail("hash chain does not verify");

console.log(
  "\nVERIFIED: the ledger row is keyed on the EIP-712 digest of the authorization\n" +
    "that the USDC contract actually executed, that digest recovers to the payer,\n" +
    "and the recorded payee/amount/asset/chain equal the on-chain ones.",
);
