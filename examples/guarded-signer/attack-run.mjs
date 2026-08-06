import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { recoverTypedDataAddress, hashTypedData } from "viem";
import { VadunoGuard, AuditLedger, MemoryLedgerStore, MemorySpendLimiter } from "@vaduno/guard";
import { createGuardedAccount, GuardSignerRefusedError } from "./guarded-account.mjs";

const CHAIN = 84532;
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const SELLER = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const EVIL = "0x000000000000000000000000000000000000dead";

const real = privateKeyToAccount(generatePrivateKey());

// The ledger is exposed because ATTACK 4/6 below measure whether POLICY RAN,
// which is a fact recorded in the ledger — not something that can be inferred
// from whether two signatures differ.
let lastLedger = null;
function freshGuard() {
  lastLedger = new AuditLedger(new MemoryLedgerStore());
  return new VadunoGuard({
    policy: {
      id: "attack", version: 1, currency: "USDC",
      limits: { perTransactionMinor: 50_000, perDayMinor: 200_000 },
      merchants: { allow: [`id:${SELLER.toLowerCase()}`] },
    },
    ledger: lastLedger,
    limiter: new MemorySpendLimiter(),
  });
}
/** intent ids that got a policy_decision row — i.e. that policy actually ran on. */
async function policedIds(ledger) {
  return new Set(
    (await ledger.all())
      .filter((e) => e.type === "policy_decision")
      .map((e) => String(e.intentId)),
  );
}
function mkGuarded(guard) {
  return createGuardedAccount({
    account: real, guard, agentId: "attack",
    assets: [{ chainId: CHAIN, address: USDC, symbol: "USDC", decimals: 6 }],
  });
}

const EIP3009_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};
const NONCE = "0x" + "11".repeat(32);
function baseAuth(overrides = {}) {
  return {
    domain: { name: "USDC", version: "2", chainId: CHAIN, verifyingContract: USDC, ...(overrides.domain || {}) },
    types: overrides.types || EIP3009_TYPES,
    primaryType: "TransferWithAuthorization",
    message: {
      from: real.address, to: SELLER, value: 10_000n,
      validAfter: 0n, validBefore: 9_999_999_999n, nonce: NONCE,
      ...(overrides.message || {}),
    },
  };
}

let bypass = false;
const results = [];
function note(name, worked, detail) {
  results.push({ attack: name, worked, detail });
  console.log(`${worked ? "!! BYPASS" : "-- held  "} :: ${name} :: ${detail}`);
  if (worked) bypass = true;
}

// ---------------------------------------------------------------------------
// ATTACK 1: ungated methods (sign, signMessage, signTransaction, signAuthorization)
// Can any of them sign arbitrary typed data / raw hash?
{
  const g = mkGuarded(freshGuard());
  const hash = hashTypedData(baseAuth({ message: { to: EVIL, value: 10_000_000n } }));
  for (const m of ["sign", "signMessage", "signTransaction", "signAuthorization"]) {
    try {
      let out;
      if (m === "sign") out = await g.sign({ hash });
      else if (m === "signMessage") out = await g.signMessage({ message: { raw: hash } });
      else if (m === "signTransaction") out = await g.signTransaction({ to: EVIL, value: 0n, chainId: CHAIN });
      else out = await g.signAuthorization({ contractAddress: EVIL, chainId: CHAIN, nonce: 0 });
      note(`ungated ${m}()`, true, `returned signature ${String(out).slice(0, 20)}...`);
    } catch (e) {
      note(`ungated ${m}()`, false, `threw ${e.code || e.name}`);
    }
  }
}

// ---------------------------------------------------------------------------
// ATTACK 2: reach the real account via prototype / getters / defineProperty
{
  const g = mkGuarded(freshGuard());
  let reached = false;
  // getPrototypeOf chain
  let p = Object.getPrototypeOf(g);
  while (p && p !== Object.prototype) {
    if (typeof p.signTypedData === "function" && p.signTypedData !== g.signTypedData) reached = true;
    p = Object.getPrototypeOf(p);
  }
  // any descriptor whose value/closure is the real account
  for (const k of Object.getOwnPropertyNames(g)) {
    const d = Object.getOwnPropertyDescriptor(g, k);
    if (d.value === real) reached = true;
  }
  note("prototype/property reach real account", reached, reached ? "found reference" : "no reference to real account anywhere on wrapper");
}

// ---------------------------------------------------------------------------
// ATTACK 3: mutate the frozen wrapper to swap in the real signer
{
  const g = mkGuarded(freshGuard());
  let mutated = false;
  try { g.signTypedData = real.signTypedData; if (g.signTypedData === real.signTypedData) mutated = true; } catch {}
  try { Object.defineProperty(g, "signTypedData", { value: real.signTypedData }); if (g.signTypedData === real.signTypedData) mutated = true; } catch {}
  note("overwrite gated method on frozen wrapper", mutated, mutated ? "replaced signTypedData with raw" : "frozen: assignment/defineProperty rejected");
}

// ---------------------------------------------------------------------------
// ATTACK 4: the REPLAY re-issue path.
//
// HISTORY — read this before trusting an older run of this file. The intent id
// used to be sha256 over a hand-picked field list that EXCLUDED domain.name,
// domain.version and `types`, all of which are inside the EIP-712 digest. So a
// variant differing only in those fields collided onto the approved intent's
// id, the guard reported "replayed", and the wrapper re-signed DIFFERENT bytes
// with no policy run. This check detected that with `sig2 !== sig1`.
//
// That inference is no longer valid. The id is now `sig:<EIP-712 digest>`, so a
// different domain or typehash IS a different id IS a different intent — and a
// different signature is the CORRECT and required outcome, not a bypass. Left
// as-is, this check reported a bypass against correct code.
//
// So measure the property directly instead of inferring it from the signature:
// policy must RUN on the variant (its own policy_decision row, under its own
// id), and it must have TEETH (an over-cap variant of the same shape must be
// refused). Either failure is a real bypass.
{
  const g = mkGuarded(freshGuard());
  const ledger = lastLedger;
  const benign = baseAuth(); // 10k to SELLER, ok
  const sig1 = await g.signTypedData(benign);

  const variant = baseAuth({ domain: { version: "1" } });
  let sig2, threw2 = null;
  try { sig2 = await g.signTypedData(variant); } catch (e) { threw2 = e; }

  const idBenign = `sig:${hashTypedData(benign)}`;
  const idVariant = `sig:${hashTypedData(variant)}`;
  const policed = await policedIds(ledger);
  const bothPoliced = policed.has(idBenign) && policed.has(idVariant);

  // Teeth: same domain.version trick, but over the per-txn cap. If the variant
  // were slipping through an ungated replay branch, this would sign.
  const gCap = mkGuarded(freshGuard());
  await gCap.signTypedData(baseAuth());
  let overCapSig = null, overCapErr = null;
  try {
    overCapSig = await gCap.signTypedData(
      baseAuth({ domain: { version: "1" }, message: { value: 60_000n } }),
    );
  } catch (e) { overCapErr = e; }

  const ungated = !!sig2 && !bothPoliced;
  note("replay re-issue signs DIFFERENT preimage ungated (domain.version)", ungated || !!overCapSig,
    ungated
      ? "variant signed with NO policy_decision row of its own — policy skipped"
      : overCapSig
        ? "an OVER-CAP domain.version variant was SIGNED — the replay branch has no teeth"
        : `variant is its own intent (${idBenign.slice(0,14)}… vs ${idVariant.slice(0,14)}…), both policed=${bothPoliced}; ` +
          `over-cap variant refused ${overCapErr?.code || overCapErr?.name}`);

  // Stronger variant: change `types` so the typehash changes.
  const g2 = mkGuarded(freshGuard());
  const ledger2 = lastLedger;
  const benign2 = baseAuth();
  await g2.signTypedData(benign2);
  const extraTypes = {
    TransferWithAuthorization: [
      ...EIP3009_TYPES.TransferWithAuthorization,
      { name: "extra", type: "uint256" },
    ],
  };
  const variant2 = baseAuth({ types: extraTypes, message: { extra: 42n } });
  let s2, threw = null;
  try { s2 = await g2.signTypedData(variant2); } catch (e) { threw = e; }
  const policed2 = await policedIds(ledger2);
  const variant2Policed = !s2 || policed2.has(`sig:${hashTypedData(variant2)}`);
  note("replay re-issue signs DIFFERENT typehash ungated (extra field)", !variant2Policed,
    !variant2Policed
      ? "distinct signature over a different struct type with NO policy run"
      : s2
        ? "different typehash = different intent id, policed on its own merits before signing"
        : `refused ${threw?.code || threw?.name}`);
}

// ---------------------------------------------------------------------------
// ATTACK 5: can the replay path move value to EVIL? Change ONLY fields NOT in
// idFields while keeping to=SELLER... to is IN idFields, so changing recipient
// changes the id -> policed fresh. Confirm that: try replay to EVIL.
{
  const g = mkGuarded(freshGuard());
  await g.signTypedData(baseAuth()); // approve benign to SELLER
  let sig, threw = null;
  try { sig = await g.signTypedData(baseAuth({ message: { to: EVIL } })); } catch (e) { threw = e; }
  note("replay-shift recipient to EVIL", !!sig, sig ? "SIGNED to EVIL!" : `denied fresh: ${threw?.code}`);
}

// ---------------------------------------------------------------------------
// ATTACK 6: the variant signature is cryptographically valid and submittable.
//
// Same correction as ATTACK 4. Validity alone was never the bypass — the
// wrapper is SUPPOSED to emit valid signatures for payments policy approves.
// The bypass was "a real signature policy never saw". So the verdict is
// whether a policy_decision row exists for the exact digest that recovers.
{
  const g = mkGuarded(freshGuard());
  const ledger = lastLedger;
  const benign = baseAuth();
  await g.signTypedData(benign);
  const variant = baseAuth({ domain: { version: "1" } });
  const sig2 = await g.signTypedData(variant);
  const rec = await recoverTypedDataAddress({ ...variant, signature: sig2 });
  const valid = rec.toLowerCase() === real.address.toLowerCase();
  const digest = hashTypedData(variant);
  const policed = (await policedIds(ledger)).has(`sig:${digest}`);
  note("re-issued variant signature is cryptographically valid", valid && !policed,
    !valid
      ? "does not recover"
      : policed
        ? `recovers to payer ${rec.slice(0,12)} over digest ${digest.slice(0,12)}…, and policy ran on THAT digest`
        : `recovers to payer ${rec.slice(0,12)} — a real signature policy never saw`);
}

console.log("\n==== bypassFound:", bypass, "====");
console.log(JSON.stringify(results, null, 2));
