/**
 * PROBE 4 — attack the wrapper fixes themselves.
 *  a) idempotency: does the widened intent id still dedupe a real retry?
 *  b) decimal scaling: overflow, precision, rounding direction (0/2/6/18)
 *  c) auth-capture: is the DECLARATION read once, or re-read after the check?
 *  d) auth-capture: does a natural bigint declaration break the happy path?
 *  e) permit2: is a collector in `witness.to` detected the way `to` is?
 *  f) network: what does the new intent.network do to existing policies?
 *  g) refusal logging: unbounded attacker-controlled text into the ledger?
 */
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { getAddress } from "viem";
import { AuditLedger, MemoryLedgerStore, MemorySpendLimiter, VadunoGuard } from "@vaduno/guard";
import { createGuardedAccount, GuardSignerRefusedError } from "./guarded-account.mjs";

const CHAIN_ID = 84532;
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const SELLER = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const ATTACKER = getAddress("0xdead00000000000000000000000000000000dead");
const COLLECTOR = "0x0E3dF9510de65469C4518D7843919c0b8C7A7757";
const T0 = "0x0000000000000000000000000000000000000010";
const T2 = "0x0000000000000000000000000000000000000012";
const T18 = "0x0000000000000000000000000000000000000018";
const real = privateKeyToAccount(generatePrivateKey());

const types3009 = {
  TransferWithAuthorization: [
    { name: "from", type: "address" }, { name: "to", type: "address" },
    { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" },
  ],
};
const permitTypes = {
  PermitWitnessTransferFrom: [
    { name: "permitted", type: "TokenPermissions" }, { name: "spender", type: "address" },
    { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" },
    { name: "witness", type: "Witness" },
  ],
  TokenPermissions: [{ name: "token", type: "address" }, { name: "amount", type: "uint256" }],
  Witness: [{ name: "to", type: "address" }, { name: "facilitator", type: "address" }],
};
const nonce32 = () => `0x${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex")}`;
const soon = () => BigInt(Math.floor(Date.now() / 1000) + 300);

function pay({ token = USDC, to = SELLER, value = 10000n, nonce = nonce32() } = {}) {
  return {
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: token },
    types: types3009, primaryType: "TransferWithAuthorization",
    message: { from: real.address, to, value, validAfter: 0n, validBefore: soon(), nonce },
  };
}

function rig({
  merchants = { allow: [`id:${SELLER.toLowerCase()}`] },
  currency = "USDC",
  limits = { perTransactionMinor: 50_000, perDayMinor: 200_000 },
  assets = [{ chainId: CHAIN_ID, address: USDC, symbol: "USDC", decimals: 6 }],
  networks,
  ...rest
} = {}) {
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const intents = [];
  const realGuard = new VadunoGuard({
    policy: { id: "probe", version: 1, currency, limits, merchants, ...(networks ? { networks } : {}) },
    ledger, limiter: new MemorySpendLimiter(),
  });
  const guard = {
    authorize: async (i) => { intents.push(i); return realGuard.authorize(i); },
    settle: (...a) => realGuard.settle(...a),
    releaseSpend: (...a) => realGuard.releaseSpend(...a),
  };
  return {
    ledger, intents,
    guarded: createGuardedAccount({ account: real, guard, agentId: "probe", assets, ...rest }),
  };
}

const say = (v, name, detail) => console.log(`${v}  ${name}\n        ${detail}`);
const tag = (e) => (e instanceof GuardSignerRefusedError ? e.code : `${e?.name}: ${String(e?.message).slice(0, 80)}`);

// ---------------------------------------------------------------- 4a idempotency
console.log("=== 4a. does the sig:<digest> id still dedupe a genuine retry? ===");
{
  const { guarded, intents, ledger } = rig();
  const req = pay();
  const s1 = await guarded.signTypedData(req);
  const s2 = await guarded.signTypedData(req);           // identical resubmission
  const s3 = await guarded.signTypedData(structuredClone(req)); // separate object, same bytes
  const counted = (await ledger.all()).filter((e) => e.type === "execution_result").length;
  say(
    s1 === s2 && s2 === s3 ? "OK" : "REGRESSION",
    "4a identical resubmission dedupes",
    `3 calls, ${new Set([s1, s2, s3]).size} distinct signature(s), ` +
      `${new Set(intents.map((i) => i.id)).size} distinct intent id(s), ${counted} execution_result row(s)`,
  );
}
{
  // The same logical payment re-encoded the way a retrying client might.
  const { guarded, intents } = rig();
  const n = nonce32();
  await guarded.signTypedData(pay({ nonce: n }));
  const variant = pay({ nonce: n });
  variant.message.value = 10000;             // number, not bigint — same on-chain value
  variant.message.validAfter = 0;
  variant.message.validBefore = Number(variant.message.validBefore);
  let second;
  try { await guarded.signTypedData(variant); second = "signed again"; }
  catch (e) { second = tag(e); }
  say(
    "INFO", "4a same payment re-encoded (bigint -> number) is a DIFFERENT id",
    `ids: ${new Set(intents.map((i) => i.id)).size} distinct for 1 logical payment; second call -> ${second}` +
      `\n        (counted twice against the cap; fails in the over-count direction)`,
  );
}

// ------------------------------------------------------------------- 4b decimals
console.log("\n=== 4b. decimal scaling: overflow / precision / rounding direction ===");
const decCases = [
  ["0-dec token, 6-dec policy", T0, 0, 6, 1n],
  ["2-dec token, 6-dec policy", T2, 2, 6, 1n],
  ["6-dec token, 6-dec policy", USDC, 6, 6, 1n],
  ["18-dec token, 6-dec policy, 1 wei (dust)", T18, 18, 6, 1n],
  ["18-dec token, 6-dec policy, 1.5 units", T18, 18, 6, 1_500_000_000_000_000_000n],
  ["6-dec token, 18-dec policy (UPSCALE)", USDC, 6, 18, 10_000n],
  ["6-dec token, 18-dec policy, 0.01 USDC", USDC, 6, 18, 10n],
];
for (const [name, token, tokDec, curDec, value] of decCases) {
  const { guarded, intents } = rig({
    assets: [{ chainId: CHAIN_ID, address: token, symbol: "USDC", decimals: tokDec }],
    currencyDecimals: curDec,
    limits: { perTransactionMinor: Number.MAX_SAFE_INTEGER - 1 },
  });
  let outcome;
  try { await guarded.signTypedData(pay({ token, value })); outcome = "SIGNED"; }
  catch (e) { outcome = `refused ${tag(e)}`; }
  const i = intents[0];
  console.log(
    `  ${name.padEnd(42)} atomic=${String(value).padStart(20)} -> amountMinor=${String(i?.amount.amountMinor).padStart(18)}  ${outcome}`,
  );
}

// ------------------------------------------------- 4c auth-capture declaration TOCTOU
console.log("\n=== 4c. is the resolveAuthCapture DECLARATION re-read after it is verified? ===");
{
  const salt = 12345n;
  const honest = {
    operator: SELLER, receiver: ATTACKER, feeRecipient: ATTACKER,
    minFeeBps: 0, maxFeeBps: 10000, authorizationExpiry: 9999999999,
    refundExpiry: 9999999999, salt,
  };
  // Derive the nonce the wrapper will demand, using the wrapper's own port.
  const mod = await import("./guarded-account.mjs");
  // The declaration is a live object: the derivation reads `receiver` once,
  // and the guard is told `receiver` on a LATER read.
  let reads = 0;
  const twoFaced = {
    ...honest,
    get receiver() {
      reads += 1;
      return reads === 1 ? ATTACKER : SELLER; // truth to the hash, lie to the guard
    },
    get feeRecipient() { return reads >= 1 ? SELLER : ATTACKER; },
  };
  // Build the request whose nonce commits to receiver=ATTACKER.
  const value = 10000n, expiry = 9999999999n;
  // Reuse the wrapper's derivation by calling it through a probe account that
  // records what the guard was told.
  const { guarded, intents } = rig({
    merchants: { allow: [`id:${SELLER.toLowerCase()}`] },
    resolveAuthCapture: () => twoFaced,
  });
  // Compute the nonce the honest declaration produces, via a throwaway rig.
  let derivedNonce = null;
  const probe = rig({
    resolveAuthCapture: (ctx) => { derivedNonce = ctx.nonce; return honest; },
  });
  try {
    await probe.guarded.signTypedData({
      domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
      types: types3009, primaryType: "TransferWithAuthorization",
      message: {
        from: real.address, to: COLLECTOR, value,
        validAfter: 0n, validBefore: expiry, nonce: nonce32(),
      },
    });
  } catch { /* mismatch expected; we only wanted the ctx */ }

  // Now derive the CORRECT nonce for `honest` by brute-forcing through the
  // wrapper: ask it what it derived, via the AUTH_CAPTURE_MISMATCH fact.
  let correctNonce = null;
  const probe2 = rig({ resolveAuthCapture: () => honest });
  try {
    await probe2.guarded.signTypedData({
      domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
      types: types3009, primaryType: "TransferWithAuthorization",
      message: {
        from: real.address, to: COLLECTOR, value,
        validAfter: 0n, validBefore: expiry, nonce: nonce32(),
      },
    });
  } catch (e) {
    // the wrapper reports the derived nonce in the ledger; pull it out
    const rows = await probe2.ledger.all();
    const row = rows.find((r) => JSON.stringify(r.data ?? {}).includes("derived"));
    correctNonce = row ? JSON.parse(JSON.stringify(row.data)).intent?.metadata?.derived ?? null : null;
  }
  const rows = await probe2.ledger.all();
  const withDerived = rows
    .map((r) => JSON.parse(JSON.stringify(r)))
    .find((r) => r?.data?.intent?.metadata?.derived);
  correctNonce = withDerived?.data?.intent?.metadata?.derived ?? null;

  if (!correctNonce) {
    say("SKIP", "4c could not recover the derived nonce from the ledger", "see 4c-direct below");
  } else {
    reads = 0;
    let outcome;
    try {
      await guarded.signTypedData({
        domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
        types: types3009, primaryType: "TransferWithAuthorization",
        message: {
          from: real.address, to: COLLECTOR, value,
          validAfter: 0n, validBefore: expiry, nonce: correctNonce,
        },
      });
      outcome = "SIGNED";
    } catch (e) { outcome = `refused ${tag(e)}`; }
    const told = intents.at(-1)?.merchant?.id;
    say(
      outcome === "SIGNED" && told === SELLER.toLowerCase() ? "BYPASS" : "held",
      "4c declaration re-read after verification (two-faced getter)",
      `nonce commits to receiver=${ATTACKER}; guard was told merchant.id=${told}; ${outcome}` +
        `\n        receiver getter invoked ${reads} time(s)`,
    );
  }
}

// -------------------------------------------- 4d bigint in an honest declaration
console.log("\n=== 4d. an honest declaration written with bigints (the natural EVM type) ===");
{
  const { guarded, intents, ledger } = rig({ resolveAuthCapture: () => null });
  // First learn the derived nonce for a bigint-flavoured declaration.
  const decl = {
    operator: SELLER, receiver: SELLER, feeRecipient: SELLER,
    minFeeBps: 0n, maxFeeBps: 100n,           // <-- bigints
    authorizationExpiry: 9999999999n, refundExpiry: 9999999999n, salt: 7n,
  };
  const r1 = rig({ resolveAuthCapture: () => decl });
  let derived = null;
  try {
    await r1.guarded.signTypedData({
      domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
      types: types3009, primaryType: "TransferWithAuthorization",
      message: {
        from: real.address, to: COLLECTOR, value: 10000n,
        validAfter: 0n, validBefore: 9999999999n, nonce: nonce32(),
      },
    });
  } catch { /* mismatch */ }
  const rows = (await r1.ledger.all()).map((r) => JSON.parse(JSON.stringify(r)));
  derived = rows.find((r) => r?.data?.intent?.metadata?.derived)?.data?.intent?.metadata?.derived;
  if (!derived) { say("SKIP", "4d no derived nonce recovered", ""); }
  else {
    const r2 = rig({ resolveAuthCapture: () => decl });
    let outcome, reasons = "";
    try {
      await r2.guarded.signTypedData({
        domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
        types: types3009, primaryType: "TransferWithAuthorization",
        message: {
          from: real.address, to: COLLECTOR, value: 10000n,
          validAfter: 0n, validBefore: 9999999999n, nonce: derived,
        },
      });
      outcome = "SIGNED";
    } catch (e) {
      outcome = `refused ${tag(e)}`;
      reasons = (e.reasons ?? []).map((x) => x.code).join(",");
    }
    say(
      outcome === "SIGNED" ? "OK" : "REGRESSION",
      "4d honest, nonce-verified auth-capture with bigint fee fields",
      `${outcome} ${reasons}\n        (derivation accepts bigint via BigInt(); metadata then carries it verbatim)`,
    );
  }
}

// --------------------------------------------------- 4e permit2 collector in witness
console.log("\n=== 4e. permit2: collector detection covers `spender` — what about `witness.to`? ===");
{
  const { guarded, intents } = rig({
    assets: [{ chainId: CHAIN_ID, address: USDC, symbol: "USDC", decimals: 6 }],
    merchants: { allow: [`id:${COLLECTOR.toLowerCase()}`] }, // operator allowlisted the collector
  });
  let outcome;
  try {
    await guarded.signTypedData({
      domain: { name: "Permit2", chainId: CHAIN_ID, verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3" },
      types: permitTypes, primaryType: "PermitWitnessTransferFrom",
      message: {
        permitted: { token: USDC, amount: 10000n },
        spender: SELLER,                 // NOT a known collector
        nonce: 1n, deadline: soon(),
        witness: { to: COLLECTOR, facilitator: ATTACKER }, // payee IS the collector
      },
    });
    outcome = "SIGNED";
  } catch (e) { outcome = `refused ${tag(e)}`; }
  say(
    outcome === "SIGNED" ? "GAP" : "held",
    "4e collector as permit2 witness.to",
    `${outcome}; guard was told merchant.id=${intents.at(-1)?.merchant?.id}` +
      `\n        (eip3009 branch tests the PAYEE; permit2 branch tests only the SPENDER)`,
  );
}

// ------------------------------------------------------------------- 4f network
console.log("\n=== 4f. the new intent.network under old and new policies ===");
for (const [name, networks, chainId] of [
  ["no networks block (pre-existing caller)", undefined, CHAIN_ID],
  ["allow the right chain", { allow: ["eip155:84532"] }, CHAIN_ID],
  ["allow the right chain, wrong chain signed", { allow: ["eip155:84532"] }, 11155111],
  ["block one chain only", { block: ["eip155:1"] }, CHAIN_ID],
  ["allow: [] (empty)", { allow: [] }, CHAIN_ID],
  ["allow: [''] (blank entry)", { allow: [""] }, CHAIN_ID],
]) {
  const { guarded, intents } = rig({
    networks,
    assets: [{ chainId, address: USDC, symbol: "USDC", decimals: 6 }],
  });
  let outcome;
  try {
    const p = pay();
    p.domain.chainId = chainId;
    await guarded.signTypedData(p);
    outcome = "SIGNED";
  } catch (e) { outcome = `refused ${tag(e)}`; }
  console.log(`  ${name.padEnd(44)} network=${intents[0]?.network} -> ${outcome}`);
}

// ------------------------------------------------- 4g refusal logging amplification
console.log("\n=== 4g. refusal logging: attacker-controlled bytes into the ledger ===");
for (const n of [10, 100_000, 2_000_000]) {
  const { ledger } = rig();
  const { guarded } = rig();
  const r = rig();
  const junk = "A".repeat(n);
  try {
    await r.guarded.signTypedData({
      domain: { chainId: CHAIN_ID, verifyingContract: USDC },
      types: types3009, primaryType: junk, message: {},
    });
  } catch { /* refused, as designed */ }
  const bytes = (await r.ledger.all()).reduce((a, e) => a + JSON.stringify(e).length, 0);
  console.log(
    `  primaryType of ${String(n).padStart(9)} chars -> ${String(bytes).padStart(10)} B of ledger ` +
      `(${(bytes / Math.max(n, 1)).toFixed(1)}x)`,
  );
}
{
  // Unbounded ROW count: every refusal gets a fresh random intent id.
  const r = rig();
  for (let i = 0; i < 200; i += 1) {
    try {
      await r.guarded.signTypedData({
        domain: { chainId: CHAIN_ID, verifyingContract: USDC },
        types: types3009, primaryType: "Nope", message: {},
      });
    } catch { /* expected */ }
  }
  const rows = (await r.ledger.all()).length;
  console.log(`  200 identical junk requests -> ${rows} ledger rows (no dedup: random id per refusal)`);
}
