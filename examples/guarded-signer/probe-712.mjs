/**
 * Probe: which of the fields the wrapper POLICES actually enter the EIP-712
 * digest that the key signs? The wrapper reads them off the request object;
 * viem hashes only what the `types` declaration says to hash.
 */
import { hashTypedData } from "viem";

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const SELLER = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const ATTACKER = "0xdead00000000000000000000000000000000dead";

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

const base = {
  types: eip3009Types,
  primaryType: "TransferWithAuthorization",
  message: {
    from: SELLER,
    to: SELLER,
    value: 10_000n,
    validAfter: 0n,
    validBefore: 9_999_999_999n,
    nonce: `0x${"11".repeat(32)}`,
  },
};

// ---- 1. Caller-narrowed EIP712Domain: does viem honour it? ----------------
const narrow = [
  { name: "name", type: "string" },
  { name: "version", type: "string" },
];
const a = hashTypedData({
  ...base,
  types: { ...eip3009Types, EIP712Domain: narrow },
  domain: { name: "USDC", version: "2", chainId: 84532, verifyingContract: USDC },
});
const b = hashTypedData({
  ...base,
  types: { ...eip3009Types, EIP712Domain: narrow },
  domain: { name: "USDC", version: "2", chainId: 1, verifyingContract: ATTACKER },
});
console.log("narrowed EIP712Domain -> chainId/verifyingContract excluded from digest:", a === b);
console.log("  digest(84532/USDC) =", a);
console.log("  digest(1/ATTACKER) =", b);

// ---- 2. Extra message fields not present in the type list -----------------
const witnessTypesWithTo = {
  PermitWitnessTransferFrom: [
    { name: "permitted", type: "TokenPermissions" },
    { name: "spender", type: "address" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
    { name: "witness", type: "Witness" },
  ],
  TokenPermissions: [
    { name: "token", type: "address" },
    { name: "amount", type: "uint256" },
  ],
  Witness: [
    { name: "to", type: "address" },
    { name: "facilitator", type: "address" },
    { name: "validAfter", type: "uint256" },
  ],
};
const witnessTypesNoTo = {
  ...witnessTypesWithTo,
  Witness: [{ name: "facilitator", type: "address" }],
};
const permitMsg = (to) => ({
  permitted: { token: USDC, amount: 10_000n },
  spender: ATTACKER,
  nonce: 1n,
  deadline: 9_999_999_999n,
  witness: { to, facilitator: SELLER, validAfter: 0n },
});
const permitDomain = {
  name: "Permit2",
  chainId: 84532,
  verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3",
};
let noToOk = true;
let c;
let d;
try {
  c = hashTypedData({
    domain: permitDomain,
    types: witnessTypesNoTo,
    primaryType: "PermitWitnessTransferFrom",
    message: permitMsg(SELLER),
  });
  d = hashTypedData({
    domain: permitDomain,
    types: witnessTypesNoTo,
    primaryType: "PermitWitnessTransferFrom",
    message: permitMsg(ATTACKER),
  });
} catch (err) {
  noToOk = false;
  console.log("witness without `to`: viem threw ->", String(err.message).slice(0, 160));
}
if (noToOk) {
  console.log("witness type omits `to`; message still carries it -> digest ignores it:", c === d);
  console.log("  digest(witness.to=SELLER)   =", c);
  console.log("  digest(witness.to=ATTACKER) =", d);
}

// ---- 3. Does viem reject a domain field absent from EIP712Domain? ---------
try {
  const e = hashTypedData({
    ...base,
    types: eip3009Types, // no EIP712Domain at all -> viem infers from domain keys
    domain: { name: "USDC", version: "2", chainId: 84532, verifyingContract: USDC, salt: `0x${"22".repeat(32)}` },
  });
  console.log("inferred domain incl. salt =", e);
} catch (err) {
  console.log("inferred domain w/ salt threw:", String(err.message).slice(0, 160));
}
