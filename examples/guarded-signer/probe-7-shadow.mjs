/**
 * PROBE 7 — how does viem DECIDE whether a field type is a struct or an atom?
 *
 * `missingCommitment` asserts "types.X declares field `to` with type `address`,
 * therefore the digest commits to an address". That inference is only sound if
 * viem hashes `address` as an address. viem's encodeField checks
 * `types[type] !== undefined` BEFORE any atomic branch, so a caller who DEFINES
 * a struct named `address` changes what the digest covers while every string in
 * the type declaration stays byte-identical to the honest one.
 *
 * This probe measures viem, not the wrapper.
 */
import { hashTypedData, hashStruct } from "viem";

const SELLER = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const ATTACKER = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
const domain = { name: "USDC", version: "2", chainId: 84532, verifyingContract: "0x036CbD53842c5426634e7929541eC2318f3dCF7e" };
const base = {
  from: "0x1111111111111111111111111111111111111111",
  value: 10_000n,
  validAfter: 0n,
  validBefore: 4_000_000_000n,
  nonce: `0x${"11".repeat(32)}`,
};
const honestTypes = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};

function tryHash(types, to) {
  try {
    return hashTypedData({ domain, types, primaryType: "TransferWithAuthorization", message: { ...base, to } });
  } catch (e) {
    return `THREW: ${String(e.message).split("\n")[0]}`;
  }
}

console.log("=== 7a. baseline: an honest declaration ===");
console.log(`  to=SELLER   ${tryHash(honestTypes, SELLER)}`);
console.log(`  to=ATTACKER ${tryHash(honestTypes, ATTACKER)}`);

console.log("\n=== 7b. types declares an EMPTY struct named `address` ===");
{
  const shadow = { ...honestTypes, address: [] };
  const a = tryHash(shadow, SELLER);
  const b = tryHash(shadow, ATTACKER);
  console.log(`  to=SELLER   ${a}`);
  console.log(`  to=ATTACKER ${b}`);
  console.log(
    a === b && String(a).startsWith("0x")
      ? "  >> COLLISION: one digest, two payees — `to` is declared `address` and hashed as a struct"
      : "  >> no collision",
  );
}

console.log("\n=== 7c. types declares a NON-empty struct named `address` ===");
{
  const shadow = { ...honestTypes, address: [{ name: "x", type: "uint256" }] };
  console.log(`  to=SELLER   ${tryHash(shadow, SELLER)}`);
  console.log(`  to=ATTACKER ${tryHash(shadow, ATTACKER)}`);
}

console.log("\n=== 7d. shadowing `uint256` (the amount) with an empty struct ===");
{
  const shadow = { ...honestTypes, uint256: [] };
  const lo = (() => { try { return hashTypedData({ domain, types: shadow, primaryType: "TransferWithAuthorization", message: { ...base, to: SELLER, value: 1n } }); } catch (e) { return `THREW: ${String(e.message).split("\n")[0]}`; } })();
  const hi = (() => { try { return hashTypedData({ domain, types: shadow, primaryType: "TransferWithAuthorization", message: { ...base, to: SELLER, value: 10n ** 18n } }); } catch (e) { return `THREW: ${String(e.message).split("\n")[0]}`; } })();
  console.log(`  value=1     ${lo}`);
  console.log(`  value=1e18  ${hi}`);
  console.log(lo === hi && String(lo).startsWith("0x") ? "  >> COLLISION: the amount is not in the digest" : "  >> no collision");
}

console.log("\n=== 7e. a self-referential type ===");
{
  const t = { A: [{ name: "a", type: "A" }] };
  try {
    console.log(`  hashStruct: ${hashStruct({ data: { a: {} }, primaryType: "A", types: t })}`);
  } catch (e) {
    console.log(`  THREW: ${String(e.message).split("\n")[0]}`);
  }
}

console.log("\n=== 7f. duplicate field names in a struct ===");
{
  const t = {
    TransferWithAuthorization: [
      { name: "from", type: "address" },
      { name: "to", type: "address" },
      { name: "to", type: "bytes32" },
      { name: "value", type: "uint256" },
      { name: "validAfter", type: "uint256" },
      { name: "validBefore", type: "uint256" },
      { name: "nonce", type: "bytes32" },
    ],
  };
  console.log(`  to=SELLER   ${tryHash(t, SELLER)}`);
}

console.log("\n=== 7g. a type referenced but not defined ===");
{
  const t = { TransferWithAuthorization: [...honestTypes.TransferWithAuthorization, { name: "extra", type: "Undefined" }] };
  try {
    console.log(`  ${hashTypedData({ domain, types: t, primaryType: "TransferWithAuthorization", message: { ...base, to: SELLER, extra: { q: 1 } } })}`);
  } catch (e) {
    console.log(`  THREW: ${String(e.message).split("\n")[0]}`);
  }
}
