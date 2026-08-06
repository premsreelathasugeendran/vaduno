/**
 * INDEPENDENT VERIFICATION — does not trust any attack script's verdict string.
 *
 * Measures the ONE invariant the wrapper exists to hold:
 *   every signature returned is over bytes that guard.authorize() was called
 *   with AND returned "authorized"/"replayed" for.
 *
 * Method: interpose on BOTH sides.
 *   - wrap guard.authorize to record (id, merchant.id, amountMinor, network)
 *   - wrap the real account's signTypedData to record the EXACT payload the key
 *     hashed, and recompute hashTypedData() over it
 * Then assert signedDigest ∈ approvedDigests for every produced signature.
 */
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { hashTypedData, recoverTypedDataAddress } from "viem";
import { VadunoGuard, AuditLedger, MemoryLedgerStore, MemorySpendLimiter } from "@vaduno/guard";
import { createGuardedAccount } from "./guarded-account.mjs";

const CHAIN = 84532;
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const SELLER = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const ATTACKER = "0xdeAD00000000000000000000000000000000dEAd";
const TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" }, { name: "to", type: "address" },
    { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" },
  ],
};
const nonce32 = () => `0x${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex")}`;

function rig(policyExtra = {}) {
  const real = privateKeyToAccount(generatePrivateKey());
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const guard = new VadunoGuard({
    policy: {
      id: "verify", version: 1, currency: "USDC",
      limits: { perTransactionMinor: 50_000, perDayMinor: 200_000 },
      merchants: { allow: [`id:${SELLER.toLowerCase()}`] },
      ...policyExtra,
    },
    ledger, limiter: new MemorySpendLimiter(),
  });

  // --- interpose on the guard: what was it ASKED, what did it ANSWER?
  const approved = new Map(); // intentId -> intent as the guard saw it
  const authorizeCalls = [];
  const origAuthorize = guard.authorize.bind(guard);
  guard.authorize = async (intent) => {
    const res = await origAuthorize(intent);
    authorizeCalls.push({ intent, status: res.status });
    if (res.status === "authorized" || res.status === "replayed") {
      approved.set(intent.id, intent);
    }
    return res;
  };

  // --- interpose on the key: what bytes did it ACTUALLY hash?
  const signedPayloads = [];
  const shadow = {
    address: real.address, publicKey: real.publicKey,
    source: real.source, type: real.type,
    signTypedData: async (td) => {
      signedPayloads.push(td);
      return real.signTypedData(td);
    },
    signMessage: real.signMessage, sign: real.sign,
    signTransaction: real.signTransaction, signAuthorization: real.signAuthorization,
  };

  const guarded = createGuardedAccount({
    account: shadow, guard, agentId: "verify",
    assets: [{ chainId: CHAIN, address: USDC, symbol: "USDC", decimals: 6 }],
  });
  return { real, guarded, ledger, approved, authorizeCalls, signedPayloads };
}

const out = [];
function check(name, pass, detail) {
  out.push({ name, pass, detail });
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}\n        ${detail}`);
}

const base = (from, over = {}) => ({
  domain: { name: "USDC", version: "2", chainId: CHAIN, verifyingContract: USDC },
  types: TYPES, primaryType: "TransferWithAuthorization",
  message: {
    from, to: SELLER, value: 10_000n, validAfter: 0n,
    validBefore: BigInt(Math.floor(Date.now() / 1e3) + 300), nonce: nonce32(), ...over,
  },
});

// ===========================================================================
// V1 — getter TOCTOU: the key must hash ONLY vetted bytes.
// ===========================================================================
{
  const { real, guarded, approved, signedPayloads } = rig();
  let hostile = false, vb = 0;
  const n = nonce32(), validBefore = BigInt(Math.floor(Date.now() / 1e3) + 300);
  const td = {
    domain: { name: "USDC", version: "2", chainId: CHAIN, verifyingContract: USDC },
    types: TYPES, primaryType: "TransferWithAuthorization",
    message: {
      from: real.address,
      get to() { return hostile ? ATTACKER : SELLER; },
      get value() { return hostile ? 100_000_000n : 10_000n; },
      validAfter: 0n,
      get validBefore() { if (++vb === 1) hostile = true; return validBefore; },
      nonce: n,
    },
  };
  let sig = null, err = null;
  try { sig = await guarded.signTypedData(td); } catch (e) { err = e; }
  if (!sig) {
    check("V1 getter TOCTOU", true, `no signature produced (refused ${err?.code})`);
  } else {
    const hashedTd = signedPayloads.at(-1);
    const signedDigest = hashTypedData(hashedTd);
    const approvedDigests = new Set([...approved.values()].map((i) => i.metadata.digest));
    const bound = approvedDigests.has(signedDigest);
    const payeeSigned = String(hashedTd.message.to).toLowerCase();
    const payeePoliced = [...approved.values()].at(-1).merchant.id;
    check("V1 getter TOCTOU — signed digest was approved",
      bound && payeeSigned === payeePoliced.toLowerCase() && payeeSigned !== ATTACKER.toLowerCase(),
      `signed digest ∈ approved: ${bound}; key hashed to=${payeeSigned} value=${hashedTd.message.value}; guard policed ${payeePoliced}`);
  }
}

// ===========================================================================
// V2 — plain-object mutation race (no getters). Verify against BOTH payloads.
// ===========================================================================
{
  const { real, guarded, approved, signedPayloads } = rig();
  const td = base(real.address);
  const originalTo = td.message.to, originalValue = td.message.value;
  const pending = guarded.signTypedData(td);
  td.message.to = ATTACKER;
  td.message.value = 100_000_000n;
  let sig = null, err = null;
  try { sig = await pending; } catch (e) { err = e; }
  if (!sig) {
    check("V2 mutation race", true, `no signature produced (refused ${err?.code})`);
  } else {
    const hashedTd = signedPayloads.at(-1);
    const benignView = {
      domain: td.domain, types: TYPES, primaryType: "TransferWithAuthorization",
      message: { ...td.message, to: originalTo, value: originalValue },
    };
    const hostileView = {
      domain: td.domain, types: TYPES, primaryType: "TransferWithAuthorization",
      message: { ...td.message, to: ATTACKER, value: 100_000_000n },
    };
    const recB = await recoverTypedDataAddress({ ...benignView, signature: sig }).catch(() => "n/a");
    const recH = await recoverTypedDataAddress({ ...hostileView, signature: sig }).catch(() => "n/a");
    const validBenign = String(recB).toLowerCase() === real.address.toLowerCase();
    const validHostile = String(recH).toLowerCase() === real.address.toLowerCase();
    const approvedDigests = new Set([...approved.values()].map((i) => i.metadata.digest));
    check("V2 mutation race — signature recovers ONLY under the vetted payload",
      validBenign && !validHostile && approvedDigests.has(hashTypedData(hashedTd)),
      `valid-for-vetted=${validBenign} valid-for-hostile=${validHostile}; key hashed to=${String(hashedTd.message.to).toLowerCase()} value=${hashedTd.message.value}`);
  }
}

// ===========================================================================
// V3 — the attack-run.mjs "replay re-issue" claim. Is policy ACTUALLY re-run?
//      attack-run infers "policy NOT re-run" purely from sig2 !== sig1.
//      Measure the real thing: authorize() call count + countable ledger rows.
// ===========================================================================
{
  const { real, guarded, authorizeCalls, ledger } = rig();
  const NONCE = "0x" + "11".repeat(32);
  const mk = (domainOver) => ({
    domain: { name: "USDC", version: "2", chainId: CHAIN, verifyingContract: USDC, ...domainOver },
    types: TYPES, primaryType: "TransferWithAuthorization",
    message: { from: real.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: 9_999_999_999n, nonce: NONCE },
  });
  const sig1 = await guarded.signTypedData(mk({}));
  const before = authorizeCalls.length;
  const sig2 = await guarded.signTypedData(mk({ version: "1" }));
  const after = authorizeCalls.length;
  const entries = await ledger.all();
  const counted = entries.filter((e) => e.type === "execution_started").length;
  const ids = authorizeCalls.map((c) => c.intent.id);
  check("V3 domain.version variant IS policed fresh (not laundered through replay)",
    after - before === 1 && ids[0] !== ids[1] && counted === 2 && sig1 !== sig2,
    `authorize() calls for the variant: ${after - before}; distinct intent ids: ${ids[0] !== ids[1]}; countable spend rows: ${counted} (2 = both counted); statuses=${authorizeCalls.map((c) => c.status).join(",")}`);
}

// ===========================================================================
// V4 — TEETH on the variant path. Under the OLD id scheme an over-cap variant
//      sharing the old idFields would ride the first approval. Make the second
//      call over-cap and confirm it is DENIED, not replayed.
// ===========================================================================
{
  const { real, guarded, authorizeCalls } = rig();
  const NONCE = "0x" + "22".repeat(32);
  const mk = (over, domainOver) => ({
    domain: { name: "USDC", version: "2", chainId: CHAIN, verifyingContract: USDC, ...domainOver },
    types: TYPES, primaryType: "TransferWithAuthorization",
    message: { from: real.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: 9_999_999_999n, nonce: NONCE, ...over },
  });
  await guarded.signTypedData(mk({}, {}));
  let sig2 = null, err = null;
  // Same nonce, same everything the OLD idFields covered except value; over cap.
  try { sig2 = await guarded.signTypedData(mk({ value: 60_000n }, { version: "1" })); } catch (e) { err = e; }
  check("V4 an over-cap variant is DENIED, not inherited from the first approval",
    sig2 === null && String(err?.code).includes("PER_TXN_LIMIT_EXCEEDED"),
    sig2 ? "*** SIGNED — policy skipped ***" : `refused ${err?.code}`);
}

// ===========================================================================
// V5 — replay of a BYTE-IDENTICAL request must re-issue the same signature and
//      must NOT double-count.
// ===========================================================================
{
  const { real, guarded, ledger } = rig();
  const td = base(real.address);
  const a = await guarded.signTypedData(td);
  const b = await guarded.signTypedData(td);
  const entries = await ledger.all();
  const counted = entries.filter((e) => e.type === "execution_started").length;
  check("V5 byte-identical replay: same signature, counted once",
    a === b && counted === 1, `identical=${a === b} countable rows=${counted}`);
}

// ===========================================================================
// V6 — ledger truth: does the audit record match what was actually signed?
// ===========================================================================
{
  const { real, guarded, ledger, signedPayloads } = rig();
  await guarded.signTypedData(base(real.address));
  const entries = await ledger.all();
  const intent = entries.find((e) => e.type === "intent_received")?.data?.intent;
  const hashedTd = signedPayloads.at(-1);
  const realDigest = hashTypedData(hashedTd);
  const ok = intent.metadata.digest === realDigest
    && intent.merchant.id === String(hashedTd.message.to).toLowerCase()
    && String(intent.amount.amountMinor) === String(hashedTd.message.value);
  check("V6 ledger records exactly what the key signed",
    ok, `ledger digest==signed digest: ${intent.metadata.digest === realDigest}; merchant=${intent.merchant.id} vs signed to=${String(hashedTd.message.to).toLowerCase()}; amountMinor=${intent.amount.amountMinor} vs signed value=${hashedTd.message.value}; verify=${JSON.stringify(await ledger.verify())}`);
}

// ===========================================================================
// V7 — chain-blindness. Confirm the OPT-IN gate genuinely bites, and confirm
//      the default really is blind (so the report is accurate either way).
// ===========================================================================
{
  const SEPOLIA = 11155111, USDC_SEP = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
  const mkRig = (policyExtra) => {
    const real = privateKeyToAccount(generatePrivateKey());
    const guard = new VadunoGuard({
      policy: {
        id: "net", version: 1, currency: "USDC",
        limits: { perTransactionMinor: 50_000, perDayMinor: 200_000 },
        merchants: { allow: [`id:${SELLER.toLowerCase()}`] }, ...policyExtra,
      },
      ledger: new AuditLedger(new MemoryLedgerStore()), limiter: new MemorySpendLimiter(),
    });
    return { real, guarded: createGuardedAccount({
      account: real, guard, agentId: "net",
      assets: [
        { chainId: CHAIN, address: USDC, symbol: "USDC", decimals: 6 },
        { chainId: SEPOLIA, address: USDC_SEP, symbol: "USDC", decimals: 6 },
      ],
    }) };
  };
  const wrongChain = (from) => ({
    domain: { name: "USDC", version: "2", chainId: SEPOLIA, verifyingContract: USDC_SEP },
    types: TYPES, primaryType: "TransferWithAuthorization",
    message: { from, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: BigInt(Math.floor(Date.now() / 1e3) + 300), nonce: nonce32() },
  });

  const noNet = mkRig({});
  let sigBlind = null, errBlind = null;
  try { sigBlind = await noNet.guarded.signTypedData(wrongChain(noNet.real.address)); } catch (e) { errBlind = e; }

  const withNet = mkRig({ networks: { allow: [`eip155:${CHAIN}`] } });
  let sigGated = null, errGated = null;
  try { sigGated = await withNet.guarded.signTypedData(wrongChain(withNet.real.address)); } catch (e) { errGated = e; }

  check("V7 network gate bites WHEN CONFIGURED",
    sigGated === null && String(errGated?.code).includes("NETWORK_NOT_ALLOWED"),
    `with networks.allow: ${sigGated ? "*** SIGNED ***" : `refused ${errGated?.code}`}`);
  check("V7b default (no networks block) is STILL chain-blind — opt-in, not closed",
    sigBlind !== null,
    sigBlind ? "signed on the wrong chain: the original attack still succeeds under a policy with no networks block" : `refused ${errBlind?.code}`);
}

// ===========================================================================
// V8 — host-pattern allowlist vs an arbitrary payee.
//
// THIS CHECK USED TO ASSERT THE DEFECT. It read
// "host-pattern allowlist still authorizes an arbitrary payee" with
// `pass = sig !== null` — i.e. it went green precisely when a transfer to an
// arbitrary address was signed under `allow: ["host:x402.org"]`. That was
// honest while the behaviour was unfixed and being catalogued, and it became a
// test that certifies a hole the moment the hole was closed. Worse, after the
// constructor diagnostic landed it did not even fail: it THREW during setup and
// took the whole file's SUMMARY with it, so V1-V7's verdicts stopped being
// printed at all.
//
// Rewritten to assert the invariant that now holds, in both of its halves.
// ===========================================================================
{
  // lowercase form: viem rejects a mixed-case address that fails EIP-55
  const EVIL = "0x00000000000000000000000000000000deadbeef";
  const mkGuard = () =>
    new VadunoGuard({
      policy: {
        id: "host", version: 1, currency: "USDC",
        limits: { perTransactionMinor: 50_000, perDayMinor: 200_000 },
        merchants: { allow: ["host:x402.org"] },
      },
      ledger: new AuditLedger(new MemoryLedgerStore()), limiter: new MemorySpendLimiter(),
    });

  // (a) LOUD: a host pattern plus a wrap-time URL is a policy that reads as
  // though it names a merchant while matching every payee. Refuse to build it.
  const real = privateKeyToAccount(generatePrivateKey());
  let built = null, ctorErr = null;
  try {
    built = createGuardedAccount({
      account: real, guard: mkGuard(), agentId: "host",
      assets: [{ chainId: CHAIN, address: USDC, symbol: "USDC", decimals: 6 }],
      merchantUrl: "https://x402.org/protected",
    });
  } catch (e) { ctorErr = e; }
  check("V8a host-form allow + merchantUrl is rejected at construction",
    built === null && /host-form pattern/.test(String(ctorErr?.message)),
    built ? "*** CONSTRUCTED *** — the misleading policy was accepted"
          : `threw: ${String(ctorErr?.message).slice(0, 80)}…`);

  // (b) STRUCTURAL: the diagnostic in (a) is best-effort (a guard wrapper that
  // does not forward getPolicy() skips it), so the control cannot be that
  // check. It is that `merchant.url` is never populated at all — so with
  // `merchantUrl` omitted, a host-form ALLOW pattern has nothing to match and
  // authorizes NOBODY, arbitrary payee included.
  const real2 = privateKeyToAccount(generatePrivateKey());
  const guarded2 = createGuardedAccount({
    account: real2, guard: mkGuard(), agentId: "host",
    assets: [{ chainId: CHAIN, address: USDC, symbol: "USDC", decimals: 6 }],
  });
  let sig = null, err = null;
  try { sig = await guarded2.signTypedData(base(real2.address, { to: EVIL })); } catch (e) { err = e; }
  check("V8b a host-form allowlist cannot authorize an arbitrary payee",
    sig === null,
    sig ? `*** SIGNED *** a transfer to ${EVIL} under allow:["host:x402.org"]`
        : `refused ${err?.code} — no merchant.url exists for the pattern to match`);
}

console.log("\n================ SUMMARY ================");
for (const r of out) console.log(`${r.pass ? "pass" : "FAIL"}  ${r.name}`);
console.log(`\n${out.filter((r) => r.pass).length}/${out.length}`);
