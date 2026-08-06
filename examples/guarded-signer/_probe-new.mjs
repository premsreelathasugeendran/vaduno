/**
 * Probing for defects the FIXES introduced or left behind.
 *
 * The fix made the intent id = the EIP-712 digest. The digest is computed over
 * `types`; the payment facts are still read from `message` BY NAME. Those two
 * are not the same set of bytes. Anywhere they diverge is a place where the
 * guard is told about a field the signature does not commit to.
 */
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { hashTypedData } from "viem";
import { VadunoGuard, AuditLedger, MemoryLedgerStore, MemorySpendLimiter } from "@vaduno/guard";
import { createGuardedAccount } from "./guarded-account.mjs";

const CHAIN = 84532;
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const SELLER = "0x209693bc6afc0c5328ba36faf03c514ef312287c";
const EVIL = "0x00000000000000000000000000000000deadbeef";
const FULL = [
  { name: "from", type: "address" }, { name: "to", type: "address" },
  { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" },
  { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" },
];
const nonce32 = () => `0x${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex")}`;

function rig(extra = {}) {
  const real = privateKeyToAccount(generatePrivateKey());
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const guard = new VadunoGuard({
    policy: {
      id: "probe", version: 1, currency: "USDC",
      limits: { perTransactionMinor: 50_000, perDayMinor: 200_000 },
      merchants: { allow: [`id:${SELLER}`] },
    },
    ledger, limiter: new MemorySpendLimiter(),
  });
  const calls = [];
  const orig = guard.authorize.bind(guard);
  guard.authorize = async (i) => { const r = await orig(i); calls.push({ i, s: r.status }); return r; };
  const guarded = createGuardedAccount({
    account: real, guard, agentId: "probe",
    assets: [{ chainId: CHAIN, address: USDC, symbol: "USDC", decimals: 6 }],
    ...extra,
  });
  return { real, guarded, ledger, calls };
}
const out = [];
function note(name, bad, detail) {
  out.push({ name, bad, detail });
  console.log(`${bad ? "!! ISSUE" : "-- ok   "}  ${name}\n          ${detail}`);
}

// ---------------------------------------------------------------------------
// P1: `types` OMITS the `to` field. extractPayment still reads message.to and
// tells the guard "payment to SELLER". The digest commits to no recipient.
// ---------------------------------------------------------------------------
{
  const { real, guarded, calls } = rig();
  const noTo = { TransferWithAuthorization: FULL.filter((f) => f.name !== "to") };
  let sig = null, err = null;
  try {
    sig = await guarded.signTypedData({
      domain: { name: "USDC", version: "2", chainId: CHAIN, verifyingContract: USDC },
      types: noTo, primaryType: "TransferWithAuthorization",
      message: { from: real.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: 9_999_999_999n, nonce: nonce32() },
    });
  } catch (e) { err = e; }
  note("P1 `types` omitting `to`: guard told a payee the signature does not commit to",
    sig !== null,
    sig ? `SIGNED; guard was told merchant.id=${calls.at(-1).i.merchant.id} but the signed struct has no recipient field` : `refused ${err?.code}`);
}

// ---------------------------------------------------------------------------
// P2: the same, weaponised. Two requests whose digests COLLIDE because the
// differing field is not in `types` -> same intent id -> second rides the
// first's approval. Approve to SELLER, then re-call with to=EVIL.
// ---------------------------------------------------------------------------
{
  const { real, guarded, calls, ledger } = rig();
  const noTo = { TransferWithAuthorization: FULL.filter((f) => f.name !== "to") };
  const n = nonce32();
  const mk = (to) => ({
    domain: { name: "USDC", version: "2", chainId: CHAIN, verifyingContract: USDC },
    types: noTo, primaryType: "TransferWithAuthorization",
    message: { from: real.address, to, value: 10_000n, validAfter: 0n, validBefore: 9_999_999_999n, nonce: n },
  });
  let s1 = null, s2 = null, err = null;
  try { s1 = await guarded.signTypedData(mk(SELLER)); } catch (e) { err = e; }
  if (s1) { try { s2 = await guarded.signTypedData(mk(EVIL)); } catch (e) { err = e; } }
  const entries = await ledger.all();
  const counted = entries.filter((e) => e.type === "execution_started").length;
  note("P2 digest collision via an out-of-`types` field launders a second payee",
    !!(s1 && s2),
    s1 && s2
      ? `both SIGNED; statuses=${calls.map((c) => c.s).join(",")} countable rows=${counted}; 2nd call declared payee ${EVIL}`
      : `2nd refused ${err?.code}`);
}

// ---------------------------------------------------------------------------
// P3: `value` omitted from `types` — guard polices an amount the signature
// does not commit to.
// ---------------------------------------------------------------------------
{
  const { real, guarded, calls } = rig();
  const noVal = { TransferWithAuthorization: FULL.filter((f) => f.name !== "value") };
  let sig = null, err = null;
  try {
    sig = await guarded.signTypedData({
      domain: { name: "USDC", version: "2", chainId: CHAIN, verifyingContract: USDC },
      types: noVal, primaryType: "TransferWithAuthorization",
      message: { from: real.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: 9_999_999_999n, nonce: nonce32() },
    });
  } catch (e) { err = e; }
  note("P3 `types` omitting `value`: guard polices an uncommitted amount",
    sig !== null,
    sig ? `SIGNED; guard counted amountMinor=${calls.at(-1).i.amount.amountMinor}` : `refused ${err?.code}`);
}

// ---------------------------------------------------------------------------
// P4: extra message fields NOT in `types` -> identical digest. Confirm the
// second call is a benign byte-identical replay, not new spending power.
// ---------------------------------------------------------------------------
{
  const { real, guarded, ledger } = rig();
  const n = nonce32();
  const mk = (extra) => ({
    domain: { name: "USDC", version: "2", chainId: CHAIN, verifyingContract: USDC },
    types: { TransferWithAuthorization: FULL }, primaryType: "TransferWithAuthorization",
    message: { from: real.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: 9_999_999_999n, nonce: n, ...extra },
  });
  const a = await guarded.signTypedData(mk({}));
  const b = await guarded.signTypedData(mk({ junk: 1 }));
  const entries = await ledger.all();
  note("P4 extra out-of-`types` message field is a byte-identical replay",
    a !== b,
    `signatures identical=${a === b} countable rows=${entries.filter((e) => e.type === "execution_started").length}`);
}

// ---------------------------------------------------------------------------
// P5: does `from` get checked against the wallet? A signature with a foreign
// `from` is useless on-chain, but does it consume budget?
// ---------------------------------------------------------------------------
{
  const { guarded, calls } = rig();
  let sig = null, err = null;
  try {
    sig = await guarded.signTypedData({
      domain: { name: "USDC", version: "2", chainId: CHAIN, verifyingContract: USDC },
      types: { TransferWithAuthorization: FULL }, primaryType: "TransferWithAuthorization",
      message: { from: EVIL, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: 9_999_999_999n, nonce: nonce32() },
    });
  } catch (e) { err = e; }
  note("P5 `from` is not bound to the wrapped wallet",
    sig !== null,
    sig ? `SIGNED with from=${EVIL} (not the signer); counted ${calls.at(-1).i.amount.amountMinor} minor` : `refused ${err?.code}`);
}

// ---------------------------------------------------------------------------
// P6: expiry is never policed — a never-expiring authorization signs.
// ---------------------------------------------------------------------------
// CORRECTED: a ceiling now EXISTS (`maxValiditySeconds`) but is opt-in, so
// "it signed with no ceiling configured" is the right answer to that config,
// not a defect. What matters is that the ceiling works when declared and does
// not refuse ordinary windows.
{
  const mk = (real, validBefore) => ({
    domain: { name: "USDC", version: "2", chainId: CHAIN, verifyingContract: USDC },
    types: { TransferWithAuthorization: FULL }, primaryType: "TransferWithAuthorization",
    message: { from: real.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore, nonce: nonce32() },
  });
  const b = rig({ maxValiditySeconds: 600 });
  let longSig = null, longErr = null;
  try { longSig = await b.guarded.signTypedData(mk(b.real, 2n ** 48n - 1n)); } catch (e) { longErr = e; }
  let shortSig = null, shortErr = null;
  try {
    shortSig = await b.guarded.signTypedData(mk(b.real, BigInt(Math.floor(Date.now() / 1e3) + 300)));
  } catch (e) { shortErr = e; }
  note("P6 validBefore = max uint256 (never expires) is signed",
    !!longSig || !shortSig,
    longSig ? "maxValiditySeconds=600 did NOT refuse a never-expiring authorization"
      : !shortSig ? `an ordinary 5-minute window was also refused (${shortErr?.code})`
      : `with maxValiditySeconds=600: never-expiring refused ${longErr?.code}, 5-minute window signs ` +
        `(the ceiling is opt-in; unset, a never-expiring authorization still signs)`);
}

console.log("\n================ SUMMARY ================");
for (const r of out) console.log(`${r.bad ? "ISSUE" : "ok   "}  ${r.name}`);
