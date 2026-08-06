/**
 * REGRESSION SUITE for the confirmed GuardedAccount defects (D1-D10),
 * plus the pre-existing behaviours that must keep holding (R1-R8).
 *
 * Every check here was written BEFORE the fix and run against the unfixed
 * `guarded-account.mjs` to watch it fail. A check that passes both ways proves
 * nothing, so each one is phrased as "the bypass must not work" and each was
 * observed working first.
 *
 * SAFETY: a freshly generated throwaway key with zero balance on every network.
 * Nothing here is broadcast; a produced SIGNATURE is the proof of bypass.
 */
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  recoverTypedDataAddress,
  getAddress,
  getTypesForEIP712Domain,
  hashTypedData,
} from "viem";
import { AuditLedger, MemoryLedgerStore, MemorySpendLimiter, VadunoGuard } from "@vaduno/guard";
import { AuthCaptureEvmScheme } from "@x402/evm";
import { createGuardedAccount, GuardSignerRefusedError } from "./guarded-account.mjs";

const CHAIN_ID = 84532;
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const SELLER = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const ATTACKER = getAddress("0xdead00000000000000000000000000000000dead");
const EIP3009_TOKEN_COLLECTOR = "0x0E3dF9510de65469C4518D7843919c0b8C7A7757";
const TWO_DEC = "0x1111111111111111111111111111111111111111";
const DAI_LIKE = "0x2222222222222222222222222222222222222222";

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
const receiveTypes = {
  ReceiveWithAuthorization: eip3009Types.TransferWithAuthorization,
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

const realAccount = privateKeyToAccount(generatePrivateKey());

const results = [];
function check(defect, name, pass, detail) {
  results.push({ defect, name, pass, detail });
  console.log(`${pass ? "PASS" : "FAIL"}  [${defect}] ${name}\n        ${detail}`);
}
function tag(err) {
  return err instanceof GuardSignerRefusedError ? err.code : `${err?.name}: ${String(err?.message).slice(0, 100)}`;
}

/** A guard whose verdicts and intents are observable. */
function countingGuard(guard) {
  const calls = { statuses: [], intents: [] };
  return {
    calls,
    guard: {
      authorize: async (i) => {
        calls.intents.push(i);
        const r = await guard.authorize(i);
        calls.statuses.push(r.status);
        return r;
      },
      settle: (...a) => guard.settle(...a),
      releaseSpend: (...a) => guard.releaseSpend(...a),
    },
  };
}

function rig({
  merchants = { allow: [`id:${SELLER.toLowerCase()}`] },
  currency = "USDC",
  limits = { perTransactionMinor: 50_000, perDayMinor: 200_000 },
  assets = [{ chainId: CHAIN_ID, address: USDC, symbol: "USDC", decimals: 6 }],
  account = realAccount,
  counting = false,
  ...rest
} = {}) {
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const real = new VadunoGuard({
    policy: { id: "regress", version: 1, currency, limits, merchants },
    ledger,
    limiter: new MemorySpendLimiter(),
  });
  const wrapped = counting ? countingGuard(real) : { guard: real, calls: null };
  const guarded = createGuardedAccount({
    account,
    guard: wrapped.guard,
    agentId: "regress",
    assets,
    ...rest,
  });
  return { guarded, ledger, guard: real, calls: wrapped.calls };
}

const countableSuccessRows = async (ledger) =>
  (await ledger.all()).filter((e) => e.type === "execution_result" && e.data?.success === true).length;

// ===========================================================================
// DEFECT 1 — time-of-check/time-of-use on the caller's live typed data
// ===========================================================================
{
  // (a) accessors that flip after the guard has read them
  const { guarded, ledger } = rig();
  let hostile = false;
  let vb = 0;
  const nonce = nonce32();
  const validBefore = soon();
  const td = {
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: {
      from: realAccount.address,
      get to() { return hostile ? ATTACKER : SELLER; },
      get value() { return hostile ? 100_000_000n : 10_000n; },
      validAfter: 0n,
      get validBefore() { if (++vb === 1) hostile = true; return validBefore; },
      nonce,
    },
  };
  const hostileView = {
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: { from: realAccount.address, to: ATTACKER, value: 100_000_000n, validAfter: 0n, validBefore, nonce },
  };
  let detail;
  let pass;
  try {
    const sig = await guarded.signTypedData(td);
    const rec = await recoverTypedDataAddress({ ...hostileView, signature: sig }).catch(() => "n/a");
    const bindsHostile = String(rec).toLowerCase() === realAccount.address.toLowerCase();
    const entries = await ledger.all();
    const counted = entries.find((e) => e.type === "intent_received")?.data?.intent;
    pass = !bindsHostile;
    detail = bindsHostile
      ? `signature is VALID for ${ATTACKER} / 100000000 while the ledger certifies ${counted?.amount?.amountMinor} to ${counted?.merchant?.id}`
      : `signature binds to the VETTED payload only (ledger: ${counted?.amount?.amountMinor} -> ${counted?.merchant?.id})`;
  } catch (err) {
    pass = true;
    detail = `refused [${tag(err)}] — no signature produced`;
  }
  check("D1a", "getter TOCTOU cannot make the key sign what policy never saw", pass, detail);
}
{
  // (b) no getters at all: mutate the plain object across the await
  const { guarded, ledger } = rig();
  const nonce = nonce32();
  const validBefore = soon();
  const td = {
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: { from: realAccount.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore, nonce },
  };
  const pending = guarded.signTypedData(td);
  td.message.to = ATTACKER;
  td.message.value = 100_000_000n;
  let pass;
  let detail;
  try {
    const sig = await pending;
    const hv = {
      domain: td.domain,
      types: eip3009Types,
      primaryType: "TransferWithAuthorization",
      message: { from: realAccount.address, to: ATTACKER, value: 100_000_000n, validAfter: 0n, validBefore, nonce },
    };
    const rec = await recoverTypedDataAddress({ ...hv, signature: sig }).catch(() => "n/a");
    const bindsHostile = String(rec).toLowerCase() === realAccount.address.toLowerCase();
    const counted = (await ledger.all()).find((e) => e.type === "intent_received")?.data?.intent;
    pass = !bindsHostile;
    detail = bindsHostile
      ? `signature is VALID for the post-mutation payload; ledger certifies ${counted?.amount?.amountMinor} -> ${counted?.merchant?.id}`
      : "signature binds to the payload as it was when policy read it";
  } catch (err) {
    pass = true;
    detail = `refused [${tag(err)}]`;
  }
  check("D1b", "post-call mutation cannot change the bytes that get signed", pass, detail);
}

// ===========================================================================
// DEFECT 2 — auth-capture collector aliasing
// ===========================================================================
// The shipped AuthCaptureEvmScheme signs `to` = a HARDCODED collector; the real
// payee lives inside the opaque nonce. Capture a genuine scheme run with an
// unguarded recorder so the checks below have the real nonce AND the salt.
const authCaptureRun = await (async () => {
  const recorder = {
    address: realAccount.address,
    captured: null,
    async signTypedData(t) {
      recorder.captured = t;
      return realAccount.signTypedData(t);
    },
  };
  const requirements = {
    scheme: "auth-capture",
    network: `eip155:${CHAIN_ID}`,
    amount: "10000",
    payTo: ATTACKER,
    asset: USDC,
    maxTimeoutSeconds: 300,
    extra: {
      name: "USDC",
      version: "2",
      captureAuthorizer: ATTACKER,
      feeRecipient: ATTACKER,
      captureDeadline: Math.floor(Date.now() / 1000) + 86_400,
      refundDeadline: Math.floor(Date.now() / 1000) + 172_800,
      minFeeBps: 0,
      maxFeeBps: 10_000,
    },
  };
  const out = await new AuthCaptureEvmScheme(recorder).createPaymentPayload(2, requirements, {});
  return { requirements, typedData: recorder.captured, salt: out.payload.salt };
})();

{
  // Default-deny: a deployment that allowlists the collector (the ONLY `to`
  // that scheme ever signs) must still not get a signature.
  const { guarded } = rig({ merchants: { allow: [`id:${EIP3009_TOKEN_COLLECTOR.toLowerCase()}`] } });
  let pass;
  let detail;
  try {
    const out = await new AuthCaptureEvmScheme(guarded).createPaymentPayload(2, authCaptureRun.requirements, {});
    pass = !out?.payload?.signature;
    detail = `SIGNATURE PRODUCED for payTo=${ATTACKER}, feeRecipient=${ATTACKER}, maxFeeBps=10000 while the guard policed the collector`;
  } catch (err) {
    pass = tag(err) === "AUTH_CAPTURE_UNPOLICEABLE";
    detail = `refused [${tag(err)}]`;
  }
  check("D2a", "collector-aliased auth-capture is refused when the payee is unpoliceable", pass, detail);
}
{
  // Modelled properly: a caller that owns the PaymentInfo declares it; the
  // wrapper RE-DERIVES the nonce and polices the REAL receiver.
  const declared = {
    operator: ATTACKER,
    receiver: ATTACKER,
    feeRecipient: ATTACKER,
    minFeeBps: 0,
    maxFeeBps: 10_000,
    authorizationExpiry: authCaptureRun.requirements.extra.captureDeadline,
    refundExpiry: authCaptureRun.requirements.extra.refundDeadline,
    salt: authCaptureRun.salt,
  };
  const { guarded, calls } = rig({
    merchants: { allow: [`id:${EIP3009_TOKEN_COLLECTOR.toLowerCase()}`] },
    counting: true,
    resolveAuthCapture: () => declared,
  });
  let pass;
  let detail;
  try {
    await guarded.signTypedData(authCaptureRun.typedData);
    pass = false;
    detail = "SIGNED — the collector allowlist still stood in for the real payee";
  } catch (err) {
    const sawRealPayee = calls.intents[0]?.merchant?.id === ATTACKER.toLowerCase();
    pass = sawRealPayee && calls.statuses[0] === "denied";
    detail = `refused [${tag(err)}]; guard evaluated merchant.id=${calls.intents[0]?.merchant?.id} (the REAL receiver, re-derived from the nonce)`;
  }
  check("D2b", "with the PaymentInfo declared, policy runs on the REAL payee", pass, detail);
}
{
  // The declaration cannot lie: the nonce is a hash over the whole PaymentInfo.
  const lie = {
    operator: ATTACKER,
    receiver: SELLER, // claims the allowlisted seller; the bytes say otherwise
    feeRecipient: ATTACKER,
    minFeeBps: 0,
    maxFeeBps: 10_000,
    authorizationExpiry: authCaptureRun.requirements.extra.captureDeadline,
    refundExpiry: authCaptureRun.requirements.extra.refundDeadline,
    salt: authCaptureRun.salt,
  };
  const { guarded } = rig({
    merchants: { allow: [`id:${SELLER.toLowerCase()}`, `id:${EIP3009_TOKEN_COLLECTOR.toLowerCase()}`] },
    resolveAuthCapture: () => lie,
  });
  let pass;
  let detail;
  try {
    await guarded.signTypedData(authCaptureRun.typedData);
    pass = false;
    detail = "SIGNED on a FALSE declaration — the re-derivation is not binding";
  } catch (err) {
    pass = tag(err) === "AUTH_CAPTURE_MISMATCH";
    detail = `refused [${tag(err)}] — a declared receiver that is not in the signed nonce cannot pass`;
  }
  check("D2c", "a lying auth-capture declaration is rejected by nonce re-derivation", pass, detail);
}
{
  // ...and an HONEST auth-capture payment to an allowlisted seller still works.
  const honest = await (async () => {
    const recorder = {
      address: realAccount.address,
      captured: null,
      async signTypedData(t) { recorder.captured = t; return realAccount.signTypedData(t); },
    };
    const requirements = { ...authCaptureRun.requirements, payTo: SELLER,
      extra: { ...authCaptureRun.requirements.extra, captureAuthorizer: SELLER, feeRecipient: SELLER, maxFeeBps: 100 } };
    const out = await new AuthCaptureEvmScheme(recorder).createPaymentPayload(2, requirements, {});
    return { requirements, typedData: recorder.captured, salt: out.payload.salt };
  })();
  const { guarded, calls } = rig({
    counting: true,
    resolveAuthCapture: () => ({
      operator: SELLER,
      receiver: SELLER,
      feeRecipient: SELLER,
      minFeeBps: 0,
      maxFeeBps: 100,
      authorizationExpiry: honest.requirements.extra.captureDeadline,
      refundExpiry: honest.requirements.extra.refundDeadline,
      salt: honest.salt,
    }),
  });
  let pass;
  let detail;
  try {
    const sig = await guarded.signTypedData(honest.typedData);
    pass = typeof sig === "string" && sig.length === 132 && calls.intents[0]?.merchant?.id === SELLER.toLowerCase();
    detail = `signed; guard policed merchant.id=${calls.intents[0]?.merchant?.id} amountMinor=${calls.intents[0]?.amount?.amountMinor}`;
  } catch (err) {
    pass = false;
    detail = `refused [${tag(err)}] — the honest auth-capture path must stay usable`;
  }
  check("D2d", "an honest, declared auth-capture payment to an allowlisted payee still signs", pass, detail);
}

// ===========================================================================
// DEFECT 3 — decimals recorded and never used
// ===========================================================================
{
  // Policy minor unit = 1e-6 USD (cap 50000 = $0.05). A 2-decimal dollar token
  // (GUSD/EURS are real) at 10000 atomic units is $100.00.
  const { guarded, calls } = rig({
    currency: "USD",
    counting: true,
    currencyDecimals: 6,
    assets: [
      { chainId: CHAIN_ID, address: USDC, symbol: "USD", decimals: 6 },
      { chainId: CHAIN_ID, address: TWO_DEC, symbol: "USD", decimals: 2 },
    ],
  });
  let pass;
  let detail;
  try {
    await guarded.signTypedData({
      domain: { name: "GUSD", version: "1", chainId: CHAIN_ID, verifyingContract: TWO_DEC },
      types: eip3009Types,
      primaryType: "TransferWithAuthorization",
      message: { from: realAccount.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: soon(), nonce: nonce32() },
    });
    pass = false;
    detail = `SIGNED $100.00 under a $0.05 cap; guard read amountMinor=${calls.intents[0]?.amount?.amountMinor}`;
  } catch (err) {
    pass = calls.intents[0]?.amount?.amountMinor === 100_000_000;
    detail = `refused [${tag(err)}]; guard evaluated amountMinor=${calls.intents[0]?.amount?.amountMinor} (= $100.00 in 1e-6 units)`;
  }
  check("D3a", "a 2-decimal dollar token is scaled, not counted as raw atomic units", pass, detail);
}
{
  // Same registry, the honest 6-decimal token: unchanged behaviour.
  const { guarded, calls } = rig({
    currency: "USD",
    counting: true,
    currencyDecimals: 6,
    assets: [{ chainId: CHAIN_ID, address: USDC, symbol: "USD", decimals: 6 }],
  });
  const sig = await guarded.signTypedData({
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: { from: realAccount.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: soon(), nonce: nonce32() },
  }).catch((e) => e);
  const ok = typeof sig === "string" && calls.intents[0]?.amount?.amountMinor === 10_000;
  check("D3b", "identity scaling (token decimals == currency decimals) is unchanged", ok,
    ok ? "10000 atomic USDC -> amountMinor 10000" : `amountMinor=${calls.intents[0]?.amount?.amountMinor} ${sig?.message ?? ""}`);
}
{
  // Scaling DOWN must never under-count: 10001 atomic USDC = 1.0001 cents -> 2.
  const { guarded, calls } = rig({
    currency: "USD",
    counting: true,
    currencyDecimals: 2,
    limits: { perTransactionMinor: 500, perDayMinor: 2000 },
    assets: [{ chainId: CHAIN_ID, address: USDC, symbol: "USD", decimals: 6 }],
  });
  await guarded.signTypedData({
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: { from: realAccount.address, to: SELLER, value: 10_001n, validAfter: 0n, validBefore: soon(), nonce: nonce32() },
  }).catch(() => {});
  const got = calls.intents[0]?.amount?.amountMinor;
  check("D3c", "downscaling rounds UP (never under-counts a fractional minor unit)", got === 2,
    `10001 atomic units of a 6-decimal token under a 2-decimal currency -> amountMinor=${got} (expected 2)`);
}
{
  // Two assets sharing a currency at DIFFERENT decimals, with no declared
  // currency granularity: unresolvable, so refuse rather than guess.
  const { guarded } = rig({
    currency: "USD",
    assets: [
      { chainId: CHAIN_ID, address: USDC, symbol: "USD", decimals: 6 },
      { chainId: CHAIN_ID, address: TWO_DEC, symbol: "USD", decimals: 2 },
    ],
  });
  let pass;
  let detail;
  try {
    await guarded.signTypedData({
      domain: { name: "GUSD", version: "1", chainId: CHAIN_ID, verifyingContract: TWO_DEC },
      types: eip3009Types,
      primaryType: "TransferWithAuthorization",
      message: { from: realAccount.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: soon(), nonce: nonce32() },
    });
    pass = false;
    detail = "SIGNED under an ambiguous registry (two decimals for one currency)";
  } catch (err) {
    pass = tag(err) === "AMBIGUOUS_CURRENCY_DECIMALS";
    detail = `refused [${tag(err)}]`;
  }
  check("D3d", "an ambiguous currency/decimals registry fails closed", pass, detail);
}
{
  // An 18-decimal stablecoin becomes usable once the currency granularity is
  // declared (it was unusable before: the atomic value overflowed safe-integer).
  const { guarded, calls } = rig({
    currency: "USD",
    counting: true,
    currencyDecimals: 2,
    limits: { perTransactionMinor: 500, perDayMinor: 2000 },
    assets: [{ chainId: CHAIN_ID, address: DAI_LIKE, symbol: "USD", decimals: 18 }],
  });
  const sig = await guarded.signTypedData({
    domain: { name: "DAI", version: "1", chainId: CHAIN_ID, verifyingContract: DAI_LIKE },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: { from: realAccount.address, to: SELLER, value: 10_000_000_000_000_000n, validAfter: 0n, validBefore: soon(), nonce: nonce32() },
  }).catch((e) => e);
  const ok = typeof sig === "string" && calls.intents[0]?.amount?.amountMinor === 1;
  check("D3e", "an 18-decimal token is policeable instead of overflowing to NaN", ok,
    ok ? "1e16 atomic (=$0.01) -> amountMinor 1 cent" : `amountMinor=${calls.intents[0]?.amount?.amountMinor} err=${sig?.code ?? sig?.message ?? ""}`);
}

// ===========================================================================
// DEFECT 4 — the replay branch re-signs a DIFFERENT digest
// ===========================================================================
{
  const { guarded, ledger, calls } = rig({ counting: true });
  const message = { from: realAccount.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: soon(), nonce: nonce32() };
  const t1 = { domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC }, types: eip3009Types, primaryType: "TransferWithAuthorization", message };
  const t2 = { ...t1, domain: { ...t1.domain, name: "Evil Token", version: "9" } };
  const s1 = await guarded.signTypedData(t1);
  const s2 = await guarded.signTypedData(t2).catch((e) => e);
  const idsDiffer = calls.intents[0]?.id !== calls.intents[1]?.id;
  const policed = calls.statuses[1] !== "replayed";
  const counted = await countableSuccessRows(ledger);
  const pass = idsDiffer && policed && counted === 2 && hashTypedData(t1) !== hashTypedData(t2);
  check("D4", "a different EIP-712 domain is a different intent, policed and counted", pass,
    `verdicts=[${calls.statuses}] ids differ=${idsDiffer} countable success rows=${counted} (expected 2) sig2=${typeof s2 === "string" ? "issued" : tag(s2)}`);
}

// ===========================================================================
// DEFECT 5 — permit2 witness.facilitator swap inherits the first approval
// ===========================================================================
{
  const PERMIT2_SPENDER = "0x1234567890123456789012345678901234567890";
  // `spender` is now default-denied unless declared — it is the address the
  // signature actually empowers to move the tokens. Declaring it here keeps
  // this check testing what it is about (the witness swap), rather than
  // stopping at the spender gate.
  const { guarded, ledger, calls } = rig({
    counting: true,
    permit2Spenders: [PERMIT2_SPENDER],
  });
  const base = {
    domain: { name: "Permit2", chainId: CHAIN_ID, verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3" },
    types: permitWitnessTypes,
    primaryType: "PermitWitnessTransferFrom",
    message: {
      permitted: { token: USDC, amount: 10_000n },
      spender: PERMIT2_SPENDER,
      nonce: 12_345n,
      deadline: soon(),
      witness: { to: SELLER, facilitator: "0x0000000000000000000000000000000000000011", validAfter: 0n },
    },
  };
  const evil = { ...base, message: { ...base.message, witness: { ...base.message.witness, facilitator: ATTACKER } } };
  await guarded.signTypedData(base);
  const s2 = await guarded.signTypedData(evil).catch((e) => e);
  const idsDiffer = calls.intents[0]?.id !== calls.intents[1]?.id;
  const policed = calls.statuses[1] !== "replayed";
  const counted = await countableSuccessRows(ledger);
  const pass = idsDiffer && policed && counted === 2;
  check("D5", "a permit2 witness.facilitator swap does not inherit the first approval", pass,
    `verdicts=[${calls.statuses}] ids differ=${idsDiffer} countable success rows=${counted} (expected 2) sig2=${typeof s2 === "string" ? "issued" : tag(s2)}`);
}

// ===========================================================================
// DEFECT 6 — hex validity windows collide in the intent id
// ===========================================================================
{
  const { guarded, ledger, calls } = rig({ counting: true });
  const n = nonce32();
  const mk = (validBefore) => ({
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: { from: realAccount.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore, nonce: n },
  });
  await guarded.signTypedData(mk("0x6853a680")); // short-lived
  const s2 = await guarded.signTypedData(mk("0xffffffffffffffff")).catch((e) => e); // never expires
  const idsDiffer = calls.intents[0]?.id !== calls.intents[1]?.id;
  const policed = calls.statuses[1] !== "replayed";
  const counted = await countableSuccessRows(ledger);
  const pass = idsDiffer && policed && counted === 2;
  check("D6", "hex validity windows do not collide into one intent id", pass,
    `verdicts=[${calls.statuses}] ids differ=${idsDiffer} countable success rows=${counted} (expected 2) sig2=${typeof s2 === "string" ? "issued" : tag(s2)}`);
}

// ===========================================================================
// DEFECT 7 — refusals that never reached the tamper-evident ledger
// ===========================================================================
{
  const { guarded, ledger } = rig();
  const ambiguous = rig({
    currency: "USD",
    assets: [
      { chainId: CHAIN_ID, address: USDC, symbol: "USD", decimals: 6 },
      { chainId: CHAIN_ID, address: TWO_DEC, symbol: "USD", decimals: 2 },
    ],
  });
  const collector = rig({ merchants: { allow: [`id:${EIP3009_TOKEN_COLLECTOR.toLowerCase()}`] } });

  const probes = [
    ["EIP-2612 unlimited Permit", guarded, ledger, () => guarded.signTypedData({
      domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
      types: { Permit: [{ name: "owner", type: "address" }, { name: "spender", type: "address" }, { name: "value", type: "uint256" }, { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" }] },
      primaryType: "Permit",
      message: { owner: realAccount.address, spender: SELLER, value: 2n ** 256n - 1n, nonce: 0n, deadline: 2n ** 48n },
    })],
    ["malformed EIP-3009 (bad nonce)", guarded, ledger, () => guarded.signTypedData({
      domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
      types: eip3009Types,
      primaryType: "TransferWithAuthorization",
      message: { from: realAccount.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: soon(), nonce: "0x00" },
    })],
    ["signTransaction()", guarded, ledger, () => guarded.signTransaction({ to: SELLER, value: 0n, chainId: CHAIN_ID })],
    ["signMessage()", guarded, ledger, () => guarded.signMessage({ message: "drain me" })],
    ["non-serializable typed data", guarded, ledger, () => guarded.signTypedData({
      domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
      types: eip3009Types,
      primaryType: "TransferWithAuthorization",
      message: { from: realAccount.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: soon(), nonce: nonce32(), evil() { return 1; } },
    })],
    ["auth-capture collector payee", collector.guarded, collector.ledger, () => collector.guarded.signTypedData(authCaptureRun.typedData)],
    ["ambiguous currency decimals", ambiguous.guarded, ambiguous.ledger, () => ambiguous.guarded.signTypedData({
      domain: { name: "GUSD", version: "1", chainId: CHAIN_ID, verifyingContract: TWO_DEC },
      types: eip3009Types,
      primaryType: "TransferWithAuthorization",
      message: { from: realAccount.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: soon(), nonce: nonce32() },
    })],
  ];

  const invisible = [];
  const codes = [];
  for (const [label, , lg, fn] of probes) {
    const before = (await lg.all()).length;
    let code = "NO REFUSAL (!!)";
    try { await fn(); } catch (e) { code = tag(e); }
    const added = (await lg.all()).length - before;
    codes.push(`${label} [${code}] +${added}`);
    if (added === 0) invisible.push(label);
  }
  check("D7", "every local refusal lands in the tamper-evident ledger", invisible.length === 0,
    invisible.length ? `INVISIBLE: ${invisible.join(", ")}` : codes.join("; "));
  const v = await ledger.verify();
  check("D7v", "the ledger still verifies after refusal rows", v.ok === true, JSON.stringify(v));
}

// ===========================================================================
// DEFECT 8 — the guard was told facts the SIGNATURE does not commit to.
//
// `message` is a plain object; the EIP-712 digest covers only the fields listed
// in `types[primaryType]`. Reading `message.to` by name while `types` omits
// `to` produced a signature over a struct with NO recipient, while the ledger
// certified an allowlisted seller. Same for `value`, for a Permit2 witness's
// `to`, and one level up for `domain.verifyingContract` (the asset, hence the
// DECIMALS) and `domain.chainId` (the policed network) under an explicit,
// narrowed `types.EIP712Domain`.
// ===========================================================================
{
  const base = (types) => ({
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types,
    primaryType: "TransferWithAuthorization",
    message: { from: realAccount.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: soon(), nonce: nonce32() },
  });
  const full = eip3009Types.TransferWithAuthorization;
  const cases = [
    ["`types` omits `to`", { TransferWithAuthorization: full.filter((f) => f.name !== "to") }],
    ["`types` omits `value`", { TransferWithAuthorization: full.filter((f) => f.name !== "value") }],
    [
      "EIP712Domain omits verifyingContract (the asset, hence the decimals)",
      {
        TransferWithAuthorization: full,
        EIP712Domain: [
          { name: "name", type: "string" },
          { name: "version", type: "string" },
          { name: "chainId", type: "uint256" },
        ],
      },
    ],
    [
      "EIP712Domain omits chainId (the policed network)",
      {
        TransferWithAuthorization: full,
        EIP712Domain: [
          { name: "name", type: "string" },
          { name: "version", type: "string" },
          { name: "verifyingContract", type: "address" },
        ],
      },
    ],
  ];
  const signed = [];
  const codes = [];
  for (const [label, types] of cases) {
    const { guarded } = rig();
    const r = await guarded.signTypedData(base(types)).catch((e) => e);
    if (typeof r === "string") signed.push(label);
    else codes.push(`${label} -> ${tag(r)}`);
  }
  check("D8", "facts the signature does not commit to are refused, not policed",
    signed.length === 0,
    signed.length ? `SIGNED despite no commitment: ${signed.join("; ")}` : codes.join("; "));
}

// ===========================================================================
// DEFECT 9 — `from` was never bound to the wrapped wallet, and expiry was
// never policed. Neither can settle (EIP-3009 requires ecrecover === from, and
// an expired authorization is rejected on-chain), but BOTH signed and BOTH
// consumed budget that the ledger recorded as real spend — a free
// denial-of-service against the daily cap.
// ===========================================================================
{
  const mk = (over) => ({
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: { from: realAccount.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: soon(), nonce: nonce32(), ...over },
  });
  const { guarded: g1, ledger: l1 } = rig();
  const wrongPayer = await g1.signTypedData(mk({ from: ATTACKER })).catch((e) => e);
  const { guarded: g2, ledger: l2 } = rig();
  const expired = await g2.signTypedData(mk({ validBefore: 1n })).catch((e) => e);
  const burned = (await countableSuccessRows(l1)) + (await countableSuccessRows(l2));
  const pass =
    typeof wrongPayer !== "string" && typeof expired !== "string" && burned === 0;
  check("D9", "an unsettleable authorization cannot burn budget", pass,
    `wrong payer -> ${typeof wrongPayer === "string" ? "SIGNED" : tag(wrongPayer)}; ` +
    `already expired -> ${typeof expired === "string" ? "SIGNED" : tag(expired)}; ` +
    `countable spend rows across both = ${burned} (expected 0)`);
}

// ===========================================================================
// DEFECT 10 — Permit2 `spender` is the address the signature EMPOWERS to move
// the tokens; witness.to is only a hint the downstream contract may honour.
// Policing the witness while ignoring the spender let a signature that named an
// allowlisted seller grant an arbitrary spender the right to move the funds.
// ===========================================================================
{
  const SPENDER_OK = "0x1234567890123456789012345678901234567890";
  const permit2 = (spender) => ({
    domain: { name: "Permit2", chainId: CHAIN_ID, verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3" },
    types: permitWitnessTypes,
    primaryType: "PermitWitnessTransferFrom",
    message: {
      permitted: { token: USDC, amount: 10_000n },
      spender,
      nonce: BigInt(`0x${Buffer.from(crypto.getRandomValues(new Uint8Array(8))).toString("hex")}`),
      deadline: soon(),
      witness: { to: SELLER, facilitator: "0x0000000000000000000000000000000000000011", validAfter: 0n },
    },
  });
  const { guarded: gUndeclared } = rig();
  const undeclared = await gUndeclared.signTypedData(permit2(SPENDER_OK)).catch((e) => e);
  const { guarded: gAllowed } = rig({ permit2Spenders: [SPENDER_OK] });
  const rogue = await gAllowed.signTypedData(permit2(ATTACKER)).catch((e) => e);
  const honest = await gAllowed.signTypedData(permit2(SPENDER_OK)).catch((e) => e);
  const pass =
    typeof undeclared !== "string" && typeof rogue !== "string" && typeof honest === "string";
  check("D10", "the Permit2 spender is policed, not just the witness recipient", pass,
    `undeclared spender -> ${typeof undeclared === "string" ? "SIGNED" : tag(undeclared)}; ` +
    `rogue spender under an allowlist -> ${typeof rogue === "string" ? "SIGNED" : tag(rogue)}; ` +
    `allowlisted spender -> ${typeof honest === "string" ? "signs" : tag(honest)}`);
}

// ===========================================================================
// DEFECT 11 — a scaled amount that no JS number can hold collapsed to the
// fail-closed 0 and was denied INVALID_AMOUNT. The refusal was correct and the
// diagnosis was wrong: it points the operator at the payment's amount when the
// cause is the deployment's `currencyDecimals`. An operator who trusts it
// hunts a payment that is not the problem.
// ===========================================================================
{
  const { guarded, calls } = rig({
    counting: true,
    currencyDecimals: 18,
    assets: [{ chainId: CHAIN_ID, address: DAI_LIKE, symbol: "USDC", decimals: 18 }],
  });
  const r = await guarded.signTypedData({
    domain: { name: "DAI", version: "1", chainId: CHAIN_ID, verifyingContract: DAI_LIKE },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: { from: realAccount.address, to: SELLER, value: 10n ** 18n, validAfter: 0n, validBefore: soon(), nonce: nonce32() },
  }).catch((e) => e);
  // The OTHER cause of the same condition — an absurd amount under an ordinary
  // currency — must reach the same refusal, because the wrapper cannot tell the
  // two apart and the message says so.
  const { guarded: g2 } = rig();
  const absurd = await g2.signTypedData({
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: { from: realAccount.address, to: SELLER, value: 2n ** 200n, validAfter: 0n, validBefore: soon(), nonce: nonce32() },
  }).catch((e) => e);
  const pass =
    typeof r !== "string" && tag(r) === "AMOUNT_NOT_REPRESENTABLE" &&
    typeof absurd !== "string" && tag(absurd) === "AMOUNT_NOT_REPRESENTABLE";
  check("D11", "an unrepresentable scaled amount is diagnosed, not blamed on the amount", pass,
    `1e18 atomic of an 18-decimal token at currencyDecimals=18 -> ${typeof r === "string" ? "SIGNED" : tag(r)} ` +
    `(the only guard.authorize call was the audited refusal row, amountMinor=` +
    `${calls.intents[0]?.amount?.amountMinor ?? "n/a"}, currency=${calls.intents[0]?.amount?.currency}); ` +
    `2^200 atomic USDC at currencyDecimals=6 -> ${typeof absurd === "string" ? "SIGNED" : tag(absurd)}`);
}

// ===========================================================================
// DEFECT 12 — the permit2 flavour of the shipped auth-capture scheme signs
// `PermitTransferFrom` with the PERMIT2 token collector as `spender`. It was
// refused only by the generic unknown-shape fallback, so the refusal named
// nothing an operator could act on and PERMIT2_TOKEN_COLLECTOR_ADDRESS in the
// default collector list was unreachable code claiming to be a control.
// ===========================================================================
{
  const requirements = {
    scheme: "auth-capture",
    network: `eip155:${CHAIN_ID}`,
    amount: "10000",
    payTo: SELLER,
    asset: USDC,
    maxTimeoutSeconds: 600,
    extra: {
      name: "USDC", version: "2", captureAuthorizer: SELLER, feeRecipient: SELLER,
      captureDeadline: 4_000_000_000, refundDeadline: 4_000_000_000,
      minFeeBps: 0, maxFeeBps: 100, assetTransferMethod: "permit2",
    },
  };
  const declared = () => ({
    operator: SELLER, receiver: SELLER, feeRecipient: SELLER, minFeeBps: 0, maxFeeBps: 100,
    authorizationExpiry: 4_000_000_000, refundExpiry: 4_000_000_000, salt: 1,
  });
  const { guarded, ledger } = rig({ resolveAuthCapture: declared });
  const before = (await ledger.all()).length;
  const r = await new AuthCaptureEvmScheme(guarded).createPaymentPayload(2, requirements).catch((e) => e);
  const added = (await ledger.all()).length - before;
  const pass = !r?.payload?.signature && tag(r) === "AUTH_CAPTURE_FLAVOUR_UNSUPPORTED" && added > 0;
  check("D12", "the permit2 auth-capture flavour is explicitly default-denied, not merely unknown", pass,
    `${r?.payload?.signature ? "SIGNED" : `refused [${tag(r)}]`}; +${added} ledger row(s)`);
}

// ===========================================================================
// DEFECT 13 — the intent id is the digest, but WHICH FIELDS that digest covers
// was nowhere in the evidence. Whether a fact was policeable at all is decided
// by `types`, so an auditor reading the ledger could not distinguish a full
// EIP-3009 struct from a narrowed one after the fact.
// ===========================================================================
{
  const { guarded, ledger } = rig();
  await guarded.signTypedData({
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: { from: realAccount.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: soon(), nonce: nonce32() },
  });
  const recorded = (await ledger.all()).find((e) => e.type === "intent_received")?.data?.intent;
  const c = recorded?.metadata?.committed;
  // The recorded domain set must be EXACTLY what viem's own inference produces,
  // because that is what hashTypedData covered.
  const expectDomain = getTypesForEIP712Domain({
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
  }).map((f) => f.name);
  const domainOk = JSON.stringify(c?.domain) === JSON.stringify(expectDomain);
  const structOk =
    JSON.stringify(c?.struct?.TransferWithAuthorization) ===
    JSON.stringify(eip3009Types.TransferWithAuthorization.map((f) => f.name));
  check("D13", "the committed-field set is recorded alongside the digest", domainOk && structOk,
    `metadata.committed = ${JSON.stringify(c)}`);
}
{
  // ...and it must follow NESTED structs, or a Permit2 record would claim to
  // cover fields whose own struct declaration was never inspected.
  const SPENDER_OK = "0x1234567890123456789012345678901234567890";
  const { guarded, ledger } = rig({ permit2Spenders: [SPENDER_OK] });
  await guarded.signTypedData({
    domain: { name: "Permit2", chainId: CHAIN_ID, verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3" },
    types: permitWitnessTypes,
    primaryType: "PermitWitnessTransferFrom",
    message: {
      permitted: { token: USDC, amount: 10_000n },
      spender: SPENDER_OK,
      nonce: 99_991n,
      deadline: soon(),
      witness: { to: SELLER, facilitator: "0x0000000000000000000000000000000000000011", validAfter: 0n },
    },
  }).catch(() => {});
  const recorded = (await ledger.all()).find((e) => e.type === "intent_received")?.data?.intent;
  const s = recorded?.metadata?.committed?.struct ?? {};
  const pass =
    Array.isArray(s.PermitWitnessTransferFrom) &&
    Array.isArray(s.TokenPermissions) &&
    Array.isArray(s.Witness) &&
    s.Witness.includes("to");
  check("D13b", "the committed-field set follows nested structs", pass,
    `structs recorded: ${Object.keys(s).join(", ") || "(none)"}`);
}
{
  // DEFECT 13c — the record resolved a struct reference DIFFERENTLY from viem.
  //
  // viem's encodeField checks `types[type]` on the FULL type name BEFORE it
  // ever strips an array suffix (utils/signature/hashTypedData.js), so a field
  // declared `Witness[]` is hashed against `types["Witness[]"]` when that key
  // exists. The recorder stripped the brackets first and looked up
  // `types["Witness"]` — a different struct, or none at all. The payee check
  // itself was already right (it passes the declared type name through
  // verbatim), so this was never a signing hole; it was an EVIDENCE hole, and
  // the worse kind: the row named a field list the digest does not cover while
  // omitting `to`, the very field the allowlist decision turned on. A ledger
  // that outlives the code has to be re-checkable, and this row would have been
  // re-checked into the wrong answer.
  //
  // Both shapes below are real permit2 encodings viem signs happily.
  const SPENDER_OK = "0x1234567890123456789012345678901234567890";
  const arrayWitness = (extraTypes) => ({
    domain: { name: "Permit2", chainId: CHAIN_ID, verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3" },
    types: {
      PermitWitnessTransferFrom: [
        { name: "permitted", type: "TokenPermissions" },
        { name: "spender", type: "address" },
        { name: "nonce", type: "uint256" },
        { name: "deadline", type: "uint256" },
        { name: "witness", type: "Witness[]" },
      ],
      TokenPermissions: permitWitnessTypes.TokenPermissions,
      ...extraTypes,
    },
    primaryType: "PermitWitnessTransferFrom",
    message: {
      permitted: { token: USDC, amount: 10_000n },
      spender: SPENDER_OK,
      nonce: 77_771n,
      deadline: soon(),
      // An array carrying `to` as a non-index property: what viem's struct
      // branch reads when `types["Witness[]"]` is declared.
      witness: Object.assign([], { to: SELLER }),
    },
  });
  const recordFor = async (extraTypes) => {
    const { guarded, ledger } = rig({ permit2Spenders: [SPENDER_OK] });
    await guarded.signTypedData(arrayWitness(extraTypes)).catch(() => {});
    const recorded = (await ledger.all()).find((e) => e.type === "intent_received")?.data?.intent;
    return recorded?.metadata?.committed?.struct ?? {};
  };
  // (a) BOTH declared: viem uses `Witness[]` (full name wins), so the record
  //     must too — recording `Witness`'s unrelated field list is a false row.
  const both = await recordFor({
    "Witness[]": [{ name: "to", type: "address" }],
    Witness: [{ name: "unrelated", type: "uint256" }],
  });
  // (b) ONLY `Witness[]` declared: stripping the brackets finds nothing, so the
  //     witness struct vanished from the record entirely.
  const only = await recordFor({ "Witness[]": [{ name: "to", type: "address" }] });
  const covers = (s) =>
    Object.values(s).some((fields) => Array.isArray(fields) && fields.includes("to")) &&
    !Object.values(s).some((fields) => Array.isArray(fields) && fields.includes("unrelated"));
  check("D13c", "struct references resolve exactly as viem resolves them (full name before array suffix)",
    covers(both) && covers(only),
    `both-declared: ${JSON.stringify(both)}; only-array-declared: ${JSON.stringify(only)}`);
}
{
  // DEFECT 13d — the FIX for 13c crashed the process on a hostile type name.
  //
  // Resolving the reference by recursing on `type.slice(0, open)` allocates a
  // fresh string per array level, so a field declared with 100,000 levels is
  // O(n^2) characters: measured `FATAL ERROR: Reached heap limit Allocation
  // failed - JavaScript heap out of memory`, process dead, while raw
  // `hashTypedData` handled the identical input in 37 ms and the ORIGINAL
  // one-shot regex took 2 ms. `types` is counterparty-controlled and this
  // process is the one writing the audit ledger, so a crash is strictly worse
  // than a refusal — it takes the evidence writer down with the request.
  //
  // The property: pathological nesting REFUSES, promptly, and the process
  // lives. Refusing (rather than resolving nothing) is deliberate — an
  // unresolved reference silently omits a struct from the record, which is the
  // defect 13c existed to fix.
  const SPENDER_OK = "0x1234567890123456789012345678901234567890";
  const { guarded, ledger } = rig({ permit2Spenders: [SPENDER_OK] });
  const t0 = Date.now();
  const outcomes = [];
  for (const levels of [40, 100_000]) {
    const r = await guarded.signTypedData({
      domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
      types: {
        TransferWithAuthorization: [
          ...eip3009Types.TransferWithAuthorization,
          { name: "junk", type: `Witness${"[]".repeat(levels)}` },
        ],
        Witness: [{ name: "x", type: "uint256" }],
      },
      primaryType: "TransferWithAuthorization",
      message: {
        from: realAccount.address, to: SELLER, value: 10_000n,
        validAfter: 0n, validBefore: soon(), nonce: nonce32(), junk: [],
      },
    }).catch((e) => e);
    outcomes.push(`${levels} levels -> ${typeof r === "string" ? "SIGNED" : tag(r)}`);
  }
  const ms = Date.now() - t0;
  const verify = await ledger.verify();
  const pass =
    outcomes.every((o) => o.endsWith("COMMITMENT_RECORD_UNCOMPUTABLE")) &&
    ms < 10_000 &&
    verify.ok;
  check("D13d", "a hostile array-nesting depth refuses promptly instead of exhausting the heap",
    pass, `${outcomes.join("; ")}; ${ms} ms; ledger verify=${JSON.stringify(verify)}`);
}

// ===========================================================================
// DEFECT 14 — the INFERRED-domain premise was false, and this file's own
// principle was violated by the code that states it.
//
// `missingDomainCommitment` early-returned null whenever `types.EIP712Domain`
// was not an array, on the belief that viem then commits to every domain field
// that is PRESENT. It does not: `getTypesForEIP712Domain()` includes `chainId`
// only when `typeof domain.chainId` is "number" or "bigint", and `asChainId`
// deliberately accepts decimal STRINGS. So `chainId: "84532"` is present, is
// read, is policed as `eip155:84532`, selects the (chainId, asset) registry row
// that supplies the DECIMALS — and is not in the signed bytes at all. The same
// signature is then valid on a chain whose registry row calls the token
// 2-decimal, turning a policed $0.01 into a real $100.00.
//
// The wrapper's own evidence proved it and nothing consulted it: the ledger row
// said committed.domain = [name, version, verifyingContract] while
// intent.network said eip155:84532. The gate now reads that same derivation.
// ===========================================================================
{
  const mk = (chainId, types) => ({
    domain: { name: "USDC", version: "2", chainId, verifyingContract: USDC },
    types,
    primaryType: "TransferWithAuthorization",
    message: { from: realAccount.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: soon(), nonce: nonce32() },
  });
  const explicitDomain = [
    { name: "name", type: "string" },
    { name: "version", type: "string" },
    { name: "chainId", type: "uint256" },
    { name: "verifyingContract", type: "address" },
  ];

  // The bypass: a string chainId is not in the digest, measured against viem.
  const strA = mk("84532", eip3009Types);
  const strB = structuredClone(strA);
  strB.domain.chainId = "1";
  const chainIdUncommitted = hashTypedData(strA) === hashTypedData(strB);

  const { guarded, calls } = rig({ counting: true });
  const attacked = await guarded.signTypedData(strA).catch((e) => e);
  let sameBytesElsewhere = false;
  if (typeof attacked === "string") {
    const asChain1 = structuredClone(strA);
    asChain1.domain.chainId = "1";
    const rec = await recoverTypedDataAddress({ ...asChain1, signature: attacked }).catch(() => "n/a");
    sameBytesElsewhere = String(rec).toLowerCase() === realAccount.address.toLowerCase();
  }

  // ...and the shapes that ARE committed must keep signing.
  const { guarded: gNum } = rig();
  const num = await gNum.signTypedData(mk(CHAIN_ID, eip3009Types)).catch((e) => e);
  const { guarded: gBig } = rig();
  const big = await gBig.signTypedData(mk(BigInt(CHAIN_ID), eip3009Types)).catch((e) => e);
  const { guarded: gExp } = rig();
  const explicitStr = await gExp
    .signTypedData(mk("84532", { EIP712Domain: explicitDomain, ...eip3009Types }))
    .catch((e) => e);

  const pass =
    chainIdUncommitted &&
    typeof attacked !== "string" &&
    tag(attacked) === "TYPED_DATA_NOT_COMMITTED" &&
    typeof num === "string" &&
    typeof big === "string" &&
    typeof explicitStr === "string";
  check("D14", "an uncommitted INFERRED domain field is refused, not policed as if signed", pass,
    `digest(chainId="84532")===digest(chainId="1") -> ${chainIdUncommitted}; ` +
    `string chainId -> ${typeof attacked === "string" ? `SIGNED (valid on chain 1: ${sameBytesElsewhere}; guard policed ${calls.intents[0]?.network})` : tag(attacked)}; ` +
    `number -> ${typeof num === "string" ? "signs" : tag(num)}; ` +
    `bigint -> ${typeof big === "string" ? "signs" : tag(big)}; ` +
    `string under an EXPLICIT EIP712Domain (which DOES commit it) -> ${typeof explicitStr === "string" ? "signs" : tag(explicitStr)}`);
}
{
  // The gate and the record must be the SAME derivation, or a row could certify
  // coverage the decision never required. Every signed row must list every
  // domain field the guard relied on.
  const { guarded, ledger } = rig();
  await guarded.signTypedData({
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: { from: realAccount.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: soon(), nonce: nonce32() },
  });
  const recorded = (await ledger.all()).find((e) => e.type === "intent_received")?.data?.intent;
  const dom = recorded?.metadata?.committed?.domain ?? [];
  check("D14b", "a signed row's committed.domain covers every domain field the guard policed",
    dom.includes("chainId") && dom.includes("verifyingContract"),
    `committed.domain = ${JSON.stringify(dom)} while intent.network = ${recorded?.network}, asset = ${recorded?.metadata?.asset}`);
}

// ===========================================================================
// DEFECT 15 — the committed-field walker SILENTLY TRUNCATED the record.
//
// `if (depth > 32 || Object.hasOwn(struct, name)) return;` dropped every struct
// past depth 32 with no error and no truncation marker. With 40 distinct nested
// structs viem hashes all 40 — they are all in the typehash string — while
// committed.struct held 33; at 300 it held the same 33. Its own sibling
// resolveStructRef THROWS on ARRAY_NESTING_LIMIT rather than drop, with a
// comment saying an unresolved reference "would quietly omit a struct from the
// record, which is the exact defect this function was written to fix".
//
// There is NO upper recovery bound to this: the check below spans 33 (the first
// truncating depth) to 300, and every one of them must refuse rather than sign
// a partial record.
// ===========================================================================
{
  const chain = (depth) => {
    const types = {
      TransferWithAuthorization: [...eip3009Types.TransferWithAuthorization, { name: "extra", type: "S0" }],
    };
    for (let n = 0; n < depth; n += 1) {
      types[`S${n}`] = n === depth - 1 ? [{ name: "leaf", type: "address" }] : [{ name: "next", type: `S${n + 1}` }];
    }
    const build = (n) => (n === depth - 1 ? { leaf: SELLER } : { next: build(n + 1) });
    return {
      domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
      types,
      primaryType: "TransferWithAuthorization",
      message: {
        from: realAccount.address, to: SELLER, value: 10_000n,
        validAfter: 0n, validBefore: soon(), nonce: nonce32(), extra: build(0),
      },
    };
  };

  const truncated = [];
  const outcomes = [];
  for (const depth of [33, 40, 64, 128, 300]) {
    const { guarded, ledger } = rig();
    const r = await guarded.signTypedData(chain(depth)).catch((e) => e);
    if (typeof r === "string") {
      const rec = (await ledger.all()).find((e) => e.type === "intent_received")?.data?.intent;
      const got = Object.keys(rec?.metadata?.committed?.struct ?? {}).length;
      truncated.push(`${depth}: SIGNED with ${got}/${depth + 1} structs recorded`);
    } else {
      outcomes.push(`${depth}: ${tag(r)}`);
    }
  }

  // The limit must not have become a blanket refusal: a shape INSIDE it still
  // signs, with every struct recorded.
  const { guarded: gOk, ledger: lOk } = rig();
  const ok = await gOk.signTypedData(chain(31)).catch((e) => e);
  const okStructs = Object.keys(
    (await lOk.all()).find((e) => e.type === "intent_received")?.data?.intent?.metadata?.committed?.struct ?? {},
  ).length;

  const pass =
    truncated.length === 0 &&
    outcomes.every((o) => o.endsWith("COMMITMENT_RECORD_UNCOMPUTABLE")) &&
    typeof ok === "string" &&
    okStructs === 32;
  check("D15", "a struct chain too deep to record REFUSES instead of recording a partial set — with no upper bound",
    pass,
    truncated.length
      ? `TRUNCATED: ${truncated.join("; ")}`
      : `${outcomes.join("; ")}; within-limit 31-deep chain -> ${typeof ok === "string" ? `signs with ${okStructs}/32 structs recorded` : tag(ok)}`);
}
{
  // Recursion must still terminate at the already-visited check rather than
  // hitting the new throw: those shapes are refused for a DIFFERENT reason
  // (viem cannot hash them at all), and the diagnosis must stay that reason.
  const { guarded } = rig();
  const recursive = await guarded.signTypedData({
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: {
      TransferWithAuthorization: [...eip3009Types.TransferWithAuthorization, { name: "extra", type: "Node" }],
      Node: [{ name: "child", type: "Node" }],
    },
    primaryType: "TransferWithAuthorization",
    message: {
      from: realAccount.address, to: SELLER, value: 10_000n,
      validAfter: 0n, validBefore: soon(), nonce: nonce32(), extra: { child: null },
    },
  }).catch((e) => e);
  check("D15b", "a self-referential struct is still diagnosed as an uncomputable DIGEST, not a record depth",
    tag(recursive) === "DIGEST_UNCOMPUTABLE", `-> ${tag(recursive)}`);
}

// ===========================================================================
// REGRESSIONS — everything that already held must keep holding
// ===========================================================================
{
  const { guarded, ledger } = rig();
  const td = {
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: { from: realAccount.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: soon(), nonce: nonce32() },
  };
  const a = await guarded.signTypedData(td);
  const b = await guarded.signTypedData(td);
  const counted = await countableSuccessRows(ledger);
  check("R1", "honest sign works and an identical retry is an idempotent replay",
    typeof a === "string" && a.length === 132 && a === b && counted === 1,
    `sig len=${a.length} identical=${a === b} countable success rows=${counted} (expected 1)`);
}
{
  const { guarded } = rig();
  const over = await guarded.signTypedData({
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: { from: realAccount.address, to: SELLER, value: 60_000n, validAfter: 0n, validBefore: soon(), nonce: nonce32() },
  }).catch((e) => e);
  check("R2", "over-cap is still denied", over instanceof Error, `-> ${tag(over)}`);
}
{
  const { guarded } = rig();
  const shapes = [
    ["Permit", { types: { Permit: [{ name: "owner", type: "address" }] }, primaryType: "Permit", message: { owner: realAccount.address } }],
    ["Foo", { types: { Foo: [{ name: "to", type: "address" }] }, primaryType: "Foo", message: { to: ATTACKER } }],
    ["PermitTransferFrom", { types: { PermitTransferFrom: [{ name: "spender", type: "address" }] }, primaryType: "PermitTransferFrom", message: { spender: ATTACKER } }],
    ["case-variant", { types: { transferWithAuthorization: eip3009Types.TransferWithAuthorization }, primaryType: "transferWithAuthorization", message: { from: realAccount.address, to: ATTACKER, value: 10_000n, validAfter: 0n, validBefore: soon(), nonce: nonce32() } }],
  ];
  const signed = [];
  for (const [label, t] of shapes) {
    try {
      const s = await guarded.signTypedData({ domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC }, ...t });
      if (s) signed.push(label);
    } catch { /* refused */ }
  }
  check("R3", "unrecognized primaryType is still default-denied", signed.length === 0,
    signed.length ? `SIGNED: ${signed.join(", ")}` : "all 4 unknown shapes refused");
}
{
  const { guarded } = rig();
  const tries = [
    ["hex string", "0x2710"],
    ["1e21 number", 1e21],
    ["huge bigint", 2n ** 200n],
  ];
  const signed = [];
  for (const [label, value] of tries) {
    try {
      const s = await guarded.signTypedData({
        domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
        types: eip3009Types,
        primaryType: "TransferWithAuthorization",
        message: { from: realAccount.address, to: SELLER, value, validAfter: 0n, validBefore: soon(), nonce: nonce32() },
      });
      if (s) signed.push(label);
    } catch { /* refused */ }
  }
  check("R4", "numeric-encoding confusion on `value` still fails closed", signed.length === 0,
    signed.length ? `SIGNED: ${signed.join(", ")}` : "all coercion variants refused");
}
{
  // CHECKSUMMED allowlist vs an all-LOWERCASE payee. (An all-UPPERCASE payee
  // cannot be used as the vehicle here: viem's own typed-data encoder rejects
  // it as a malformed address before the guard is reached, so that variant
  // tests viem, not the allowlist.)
  const { guarded } = rig({ merchants: { allow: [`id:${SELLER}`] } });
  const s = await guarded.signTypedData({
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: { from: realAccount.address, to: SELLER.toLowerCase(), value: 10_000n, validAfter: 0n, validBefore: soon(), nonce: nonce32() },
  }).catch((e) => e);
  check("R5", "address-case normalisation still holds", typeof s === "string",
    typeof s === "string" ? "checksummed allowlist matches a lowercase payee" : `refused ${tag(s)}`);
}
{
  const { guarded } = rig({ limits: { perTransactionMinor: 50_000, perDayMinor: 200_000 } });
  const jobs = Array.from({ length: 12 }, () => guarded.signTypedData({
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: { from: realAccount.address, to: SELLER, value: 50_000n, validAfter: 0n, validBefore: soon(), nonce: nonce32() },
  }));
  const out = await Promise.allSettled(jobs);
  const ok = out.filter((r) => r.status === "fulfilled").length;
  check("R6", "the daily cap still holds under 12 parallel signs", ok === 4,
    `${ok} signatures x 50000 = ${ok * 50_000} vs cap 200000`);
}
{
  const { guarded } = rig();
  const t = await guarded.signTransaction({ to: SELLER, value: 0n, chainId: CHAIN_ID }).catch((e) => e);
  const m = await guarded.signMessage({ message: "x" }).catch((e) => e);
  check("R7", "ungated raw-key capabilities are still stubbed",
    tag(t) === "UNGATED_CAPABILITY_DISABLED" && tag(m) === "UNGATED_CAPABILITY_DISABLED",
    `signTransaction=${tag(t)} signMessage=${tag(m)}`);
}
{
  const { guarded } = rig();
  const exposes = Object.entries(guarded).filter(([, v]) => v === realAccount).map(([k]) => k);
  check("R8", "the wrapper exposes no property referencing the real account",
    exposes.length === 0 && Object.isFrozen(guarded), `frozen=${Object.isFrozen(guarded)} leaks=[${exposes}]`);
}

// ===========================================================================
console.log("\n================ SUMMARY ================");
const failed = results.filter((r) => !r.pass);
for (const r of results) console.log(`${r.pass ? "pass" : "FAIL"}  [${r.defect}] ${r.name}`);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) {
  console.log("FAILING:", failed.map((r) => r.defect).join(", "));
  process.exit(1);
}
