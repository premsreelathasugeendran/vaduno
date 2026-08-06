/**
 * FRESH ADVERSARIAL SWEEP against the FIXED GuardedAccount.
 *
 * The prior round found ten defects, all semantic: what the guard is TOLD about
 * the payment it approves. That class is not exhausted. This sweep hunts the
 * places where the wrapper reads a fact off the REQUEST OBJECT that the EIP-712
 * DIGEST does not commit to — i.e. where the request object and the signed bytes
 * are still two different things even after structuredClone pinned them to one
 * object.
 *
 * structuredClone fixed "the object changes between check and sign". It does not
 * fix "the object contains fields that are never signed, and omits nothing the
 * guard needs". Those are different bugs.
 *
 * SAFETY: freshly generated throwaway key, zero balance everywhere. Nothing is
 * broadcast. A produced SIGNATURE is the proof.
 */
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { recoverTypedDataAddress, getAddress, hashTypedData } from "viem";
import { AuditLedger, MemoryLedgerStore, MemorySpendLimiter, VadunoGuard } from "@vaduno/guard";
import { createGuardedAccount, GuardSignerRefusedError } from "./guarded-account.mjs";

const CHAIN_ID = 84532;
const MAINNET = 1;
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const USDC_MAINNET = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
const SELLER = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const ATTACKER = getAddress("0xdead00000000000000000000000000000000dead");
const PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const HONEST_FACILITATOR = "0x3333333333333333333333333333333333333333";

const realAccount = privateKeyToAccount(generatePrivateKey());

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
const permitWitnessTypes = {
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

const nonce32 = () => `0x${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex")}`;
const soon = () => BigInt(Math.floor(Date.now() / 1000) + 300);

const findings = [];
function report(id, title, bypassed, detail) {
  findings.push({ id, title, bypassed, detail });
  console.log(`${bypassed ? "!! BYPASS" : "-- held  "} [${id}] ${title}\n            ${detail}\n`);
}
function tag(err) {
  return err instanceof GuardSignerRefusedError
    ? err.code
    : `${err?.name}: ${String(err?.message).slice(0, 120)}`;
}

function rig({
  merchants = { allow: [`id:${SELLER.toLowerCase()}`] },
  currency = "USDC",
  limits = { perTransactionMinor: 50_000, perDayMinor: 200_000 },
  networks,
  assets = [{ chainId: CHAIN_ID, address: USDC, symbol: "USDC", decimals: 6 }],
  ...rest
} = {}) {
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const intents = [];
  const real = new VadunoGuard({
    policy: {
      id: "fresh",
      version: 1,
      currency,
      limits,
      merchants,
      ...(networks ? { networks } : {}),
    },
    ledger,
    limiter: new MemorySpendLimiter(),
  });
  const spy = {
    authorize: async (i) => {
      intents.push(i);
      return real.authorize(i);
    },
    settle: (...a) => real.settle(...a),
    releaseSpend: (...a) => real.releaseSpend(...a),
  };
  const guarded = createGuardedAccount({
    account: realAccount,
    guard: spy,
    agentId: "fresh",
    assets,
    ...rest,
  });
  return { guarded, ledger, intents, guard: real };
}

const rows = async (ledger) => await ledger.all();
const executedRows = async (ledger) =>
  (await ledger.all()).filter((e) => e.type === "execution_result" && e.data?.success === true);

// ===========================================================================
// N1 — Permit2 `spender` is never policed. The guard treats `witness.to` as
//      the payee, but in Permit2 the address that RECEIVES the tokens is chosen
//      by the SPENDER at call time (`transferDetails.to`). The witness only
//      constrains it if the spender contract chooses to enforce it — and the
//      spender here is whoever the request says it is.
// ===========================================================================
{
  const { guarded, ledger, intents } = rig();
  const td = {
    domain: { name: "Permit2", chainId: CHAIN_ID, verifyingContract: PERMIT2 },
    types: permitWitnessTypes,
    primaryType: "PermitWitnessTransferFrom",
    message: {
      permitted: { token: USDC, amount: 10_000n },
      // The attacker's own contract. Permit2 will let THIS address move the
      // tokens, to any destination it names.
      spender: ATTACKER,
      nonce: 1n,
      deadline: soon(),
      witness: { to: SELLER, facilitator: HONEST_FACILITATOR, validAfter: 0n },
    },
  };
  try {
    const sig = await guarded.signTypedData(td);
    const rec = await recoverTypedDataAddress({ ...td, signature: sig });
    const valid = rec.toLowerCase() === realAccount.address.toLowerCase();
    const i = intents.at(-1);
    report(
      "N1",
      "Permit2 spender is unpoliced — the guard polices witness.to, the chain obeys spender",
      valid,
      `SIGNED (valid=${valid}). Guard policed merchant.id=${i.merchant.id} amount=${i.amount.amountMinor}; ` +
        `the signature grants spender=${ATTACKER} the right to move 10000 USDC to any address it names. ` +
        `spender appears NOWHERE in the intent or metadata: ${JSON.stringify(i.metadata)}`,
    );
  } catch (err) {
    report("N1", "Permit2 spender is unpoliced", false, `refused [${tag(err)}]`);
  }
}

// ===========================================================================
// N2 — the policed payee need not be in the signed bytes AT ALL.
//      Permit2's witness is by construction a caller-defined struct: the
//      spender contract decides its type string, and Permit2 hashes whatever
//      type string it is handed. So an attacker declares a Witness type that
//      does NOT contain `to`, leaves `to` in the message object for the guard
//      to read, and the digest never covers it.
// ===========================================================================
{
  const { guarded, ledger, intents } = rig();
  const noToWitness = {
    ...permitWitnessTypes,
    Witness: [{ name: "facilitator", type: "address" }],
  };
  const mk = (to) => ({
    domain: { name: "Permit2", chainId: CHAIN_ID, verifyingContract: PERMIT2 },
    types: noToWitness,
    primaryType: "PermitWitnessTransferFrom",
    message: {
      permitted: { token: USDC, amount: 10_000n },
      spender: HONEST_FACILITATOR,
      nonce: 2n,
      deadline: soon(),
      witness: { to, facilitator: HONEST_FACILITATOR, validAfter: 0n },
    },
  });
  try {
    const sig = await guarded.signTypedData(mk(SELLER));
    const i = intents.at(-1);
    // Same bytes, different declared payee: if the digests match, the guard
    // policed a field that is not in the signature.
    const dSeller = hashTypedData(mk(SELLER));
    const dAttacker = hashTypedData(mk(ATTACKER));
    const same = dSeller === dAttacker;
    report(
      "N2",
      "the policed payee is absent from the signed bytes (witness type omits `to`)",
      same,
      `SIGNED. Guard policed merchant.id=${i.merchant.id}. digest(to=SELLER)===digest(to=ATTACKER): ${same} ` +
        `(${dSeller}). The signature commits to no payee; the ledger certifies one.`,
    );
  } catch (err) {
    report("N2", "the policed payee is absent from the signed bytes", false, `refused [${tag(err)}]`);
  }
}

// ===========================================================================
// N3a — a caller-narrowed `types.EIP712Domain` that omits `verifyingContract`
//       removes the ASSET from the digest. The guard still reads
//       `domain.verifyingContract` off the object to resolve the currency and
//       the decimals — so the same 132 bytes are redeemable at any EIP-3009
//       token sharing that (name, version, chainId), including one with
//       different decimals. This walks straight around the decimals fix.
// ===========================================================================
{
  const TWO_DEC = "0x1111111111111111111111111111111111111111";
  const { guarded, ledger, intents } = rig({
    networks: { allow: [`eip155:${CHAIN_ID}`] },
    limits: { perTransactionMinor: 50_000, perDayMinor: 200_000 },
  });
  const narrowTypes = {
    ...eip3009Types,
    EIP712Domain: [
      { name: "name", type: "string" },
      { name: "version", type: "string" },
      { name: "chainId", type: "uint256" },
    ],
  };
  const nonce = nonce32();
  const validBefore = soon();
  const mk = (verifyingContract) => ({
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract },
    types: narrowTypes,
    primaryType: "TransferWithAuthorization",
    message: {
      from: realAccount.address,
      to: SELLER,
      value: 10_000n,
      validAfter: 0n,
      validBefore,
      nonce,
    },
  });
  try {
    const sig = await guarded.signTypedData(mk(USDC));
    const i = intents.at(-1);
    const same = hashTypedData(mk(USDC)) === hashTypedData(mk(TWO_DEC));
    report(
      "N3a",
      "narrowed EIP712Domain drops the asset from the digest — decimals fix walked around",
      same,
      `SIGNED. Guard resolved currency=${i.amount.currency} decimals=${i.metadata.decimals} from ` +
        `domain.verifyingContract and counted amountMinor=${i.amount.amountMinor} ($0.01). ` +
        `digest(verifyingContract=USDC) === digest(verifyingContract=2-decimal token): ${same}. ` +
        `The same signature moves 10000 atomic units at a 2-decimal dollar token = $100.00.`,
    );
  } catch (err) {
    report("N3a", "narrowed EIP712Domain drops the asset from the digest", false, `refused [${tag(err)}]`);
  }
}

// ===========================================================================
// N3b — the same trick against `chainId`. The `network` gate added to close the
//       cross-chain hole reads `domain.chainId` off the object; a narrowed
//       EIP712Domain keeps it out of the signed bytes, so the allowlist polices
//       a claim rather than a commitment.
// ===========================================================================
{
  const { guarded, ledger, intents } = rig({
    networks: { allow: [`eip155:${CHAIN_ID}`] },
    assets: [
      { chainId: CHAIN_ID, address: USDC, symbol: "USDC", decimals: 6 },
      { chainId: MAINNET, address: USDC_MAINNET, symbol: "USDC", decimals: 6 },
    ],
  });
  const narrowTypes = {
    ...eip3009Types,
    EIP712Domain: [
      { name: "name", type: "string" },
      { name: "version", type: "string" },
      { name: "verifyingContract", type: "address" },
    ],
  };
  const nonce = nonce32();
  const validBefore = soon();
  const mk = (chainId) => ({
    domain: { name: "USDC", version: "2", chainId, verifyingContract: USDC },
    types: narrowTypes,
    primaryType: "TransferWithAuthorization",
    message: {
      from: realAccount.address,
      to: SELLER,
      value: 10_000n,
      validAfter: 0n,
      validBefore,
      nonce,
    },
  });
  try {
    const sig = await guarded.signTypedData(mk(CHAIN_ID));
    const i = intents.at(-1);
    const same = hashTypedData(mk(CHAIN_ID)) === hashTypedData(mk(MAINNET));
    report(
      "N3b",
      "the network allowlist gates a chainId the signature does not commit to",
      same,
      `SIGNED under networks.allow=[eip155:${CHAIN_ID}]; ledger asserts network=${i.network}. ` +
        `digest(chainId=${CHAIN_ID}) === digest(chainId=${MAINNET}): ${same}. The chain gate is ` +
        `policing a field the caller excluded from the bytes.`,
    );
  } catch (err) {
    report("N3b", "the network allowlist gates a chainId not in the signature", false, `refused [${tag(err)}]`);
  }
}

// ===========================================================================
// N4 — validBefore / validAfter are extracted and then never policed against
//      anything. An authorization that is ALREADY EXPIRED is signed, counted as
//      executed spend and written to the ledger as a completed payment. A
//      hostile server burns the agent's daily budget on payments that provably
//      cannot settle.
// ===========================================================================
{
  const { guarded, ledger, intents } = rig();
  const td = {
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: {
      from: realAccount.address,
      to: SELLER,
      value: 50_000n,
      validAfter: 0n,
      validBefore: 1n, // 1 Jan 1970 00:00:01 — expired for 56 years
      nonce: nonce32(),
    },
  };
  try {
    await guarded.signTypedData(td);
    const ex = await executedRows(ledger);
    const i = intents.at(-1);
    report(
      "N4",
      "an already-expired authorization is signed and counted as executed spend",
      ex.length > 0,
      `SIGNED with validBefore=1 (1970). Ledger has ${ex.length} successful execution row(s) for ` +
        `${i.amount.amountMinor} ${i.amount.currency}; the daily budget is spent on a payment that ` +
        `no token contract will ever accept. validBefore/validAfter appear nowhere in the intent: ` +
        `${JSON.stringify(i.metadata)}`,
    );
  } catch (err) {
    report("N4", "an already-expired authorization is signed and counted", false, `refused [${tag(err)}]`);
  }
}

// ===========================================================================
// N5 — no ceiling on the validity window. A signed EIP-3009 authorization is a
//      bearer instrument until validBefore. The guard counts it once, today,
//      against today's cap; the daily cap then resets while the instrument
//      stays live. N days of signing = N x the daily cap simultaneously
//      redeemable, and the guard has no notion of outstanding authorizations.
// ===========================================================================
{
  const { guarded, ledger, intents } = rig({ limits: { perTransactionMinor: 50_000, perDayMinor: 50_000 } });
  const FOREVER = 281_474_976_710_655n; // max uint48 — year 8921591
  const td = {
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: {
      from: realAccount.address,
      to: SELLER,
      value: 50_000n,
      validAfter: 0n,
      validBefore: FOREVER,
      nonce: nonce32(),
    },
  };
  // CORRECTED CHECK. The original verdict was "it signed", but with no ceiling
  // CONFIGURED, signing is the right answer to the config — the same harness rot
  // as attack-run's ATTACK 4/6 and attack-semantic's ATTACK 3. Two things were
  // genuinely wrong and are what this now measures: the window was recorded
  // NOWHERE (so an auditor could not tell a 5-minute authorization from a
  // 6-million-year one), and no ceiling was expressible at all. So: the window
  // must appear in the audit row, and a configured `maxValiditySeconds` must
  // refuse an over-long one while a normal window still signs.
  let recorded = false;
  try {
    await guarded.signTypedData(td);
    const i = intents.at(-1);
    recorded = JSON.stringify(i.metadata ?? {}).includes("validBefore");
  } catch (err) {
    report("N5", "no bound on the validity window", false, `1st refused [${tag(err)}]`);
  }

  // Now with a ceiling declared.
  const bounded = rig({
    limits: { perTransactionMinor: 50_000, perDayMinor: 50_000 },
    maxValiditySeconds: 600, // 10 minutes
  });
  const mk = (validBefore) => ({
    ...td,
    message: { ...td.message, validBefore, nonce: nonce32() },
  });
  let longSig = null, longErr = null;
  try { longSig = await bounded.guarded.signTypedData(mk(FOREVER)); } catch (e) { longErr = e; }
  let shortSig = null, shortErr = null;
  try {
    shortSig = await bounded.guarded.signTypedData(
      mk(BigInt(Math.floor(Date.now() / 1000) + 300)),
    );
  } catch (e) { shortErr = e; }

  report(
    "N5",
    "no bound on the validity window; the ledger does not even record it",
    !recorded || !!longSig || !shortSig,
    !recorded
      ? "the validity window is still absent from the audit row"
      : longSig
        ? "maxValiditySeconds=600 did NOT refuse a max-uint48 authorization"
        : !shortSig
          ? `a normal 5-minute window was also refused (${tag(shortErr)}) — the bound is indiscriminate`
          : `window recorded in the audit row (validBefore present); with maxValiditySeconds=600 a ` +
            `max-uint48 authorization is refused [${tag(longErr)}] while a 5-minute one still signs. ` +
            `NOTE: the ceiling is OPT-IN — without it, a never-expiring authorization signs, and the ` +
            `guard still has no notion of OUTSTANDING authorizations (it counts spend at signing time, ` +
            `so N days of signing leaves N x the daily cap simultaneously redeemable).`,
  );
}

// ===========================================================================
// N6 — `from` is never bound to the wrapped account's own address. The guard
//      records "this agent paid X" for an authorization drawn on somebody
//      else's balance, which cannot settle, burning budget and writing a false
//      evidence row.
// ===========================================================================
{
  const { guarded, ledger, intents } = rig();
  const td = {
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: {
      from: ATTACKER, // not this signer
      to: SELLER,
      value: 50_000n,
      validAfter: 0n,
      validBefore: soon(),
      nonce: nonce32(),
    },
  };
  try {
    await guarded.signTypedData(td);
    const ex = await executedRows(ledger);
    report(
      "N6",
      "`from` is not bound to the signer — budget burned on an unusable authorization",
      ex.length > 0,
      `SIGNED an authorization whose payer is ${ATTACKER}, not ${realAccount.address}. ` +
        `${ex.length} executed row(s) written; the daily cap is consumed by a signature no contract accepts.`,
    );
  } catch (err) {
    report("N6", "`from` is not bound to the signer", false, `refused [${tag(err)}]`);
  }
}

// ===========================================================================
// N7 — LEDGER AMBIGUITY. Two Permit2 authorizations, identical in every field
//      the ledger records, differing ONLY in `spender` — i.e. one pays through
//      an honest facilitator and one hands spending authority to an attacker's
//      contract. Does the evidence distinguish them?
// ===========================================================================
{
  const { guarded, ledger, intents } = rig({ limits: { perTransactionMinor: 50_000, perDayMinor: 200_000 } });
  const mk = (spender, nonce) => ({
    domain: { name: "Permit2", chainId: CHAIN_ID, verifyingContract: PERMIT2 },
    types: permitWitnessTypes,
    primaryType: "PermitWitnessTransferFrom",
    message: {
      permitted: { token: USDC, amount: 10_000n },
      spender,
      nonce,
      deadline: soon(),
      witness: { to: SELLER, facilitator: HONEST_FACILITATOR, validAfter: 0n },
    },
  });
  try {
    await guarded.signTypedData(mk(HONEST_FACILITATOR, 10n));
    await guarded.signTypedData(mk(ATTACKER, 11n));
    const scrub = (i) => {
      const c = JSON.parse(
        JSON.stringify(i, (k, v) => (typeof v === "bigint" ? String(v) : v)),
      );
      delete c.id;
      delete c.requestedAt;
      if (c.metadata) delete c.metadata.digest;
      return JSON.stringify(c);
    };
    const a = scrub(intents[0]);
    const b = scrub(intents[1]);
    report(
      "N7",
      "two materially different payments produce indistinguishable audit rows",
      a === b,
      `honest-facilitator row === attacker-spender row (id/digest/timestamp removed): ${a === b}\n` +
        `            both read: ${a}`,
    );
  } catch (err) {
    report("N7", "audit rows distinguish spender", false, `refused [${tag(err)}]`);
  }
}

// ===========================================================================
// N8 — control: does the honest path still work? A sweep that breaks the happy
//      path is measuring its own harness, not the wrapper.
// ===========================================================================
{
  const { guarded, ledger } = rig();
  const td = {
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: {
      from: realAccount.address,
      to: SELLER,
      value: 10_000n,
      validAfter: 0n,
      validBefore: soon(),
      nonce: nonce32(),
    },
  };
  const sig = await guarded.signTypedData(td);
  const ver = await ledger.verify();
  report("N8", "control: the honest path still signs and the ledger still verifies", false,
    `sig len=${sig.length}, ledger ${JSON.stringify(ver)}`);
}

console.log("\n================ FRESH SWEEP ================");
for (const f of findings) {
  console.log(`${f.bypassed ? "BYPASS" : "held  "}  [${f.id}] ${f.title}`);
}
console.log(`\n${findings.filter((f) => f.bypassed).length} bypass(es) of ${findings.length} probes`);
