/**
 * Does a one-line snapshot at the wrapper's entry close ATTACK A and ATTACK B,
 * without breaking the normal path? (_fixed-account.mjs = guarded-account.mjs
 * plus `structuredClone` of the request before extraction, signing the clone.)
 */
import { recoverTypedDataAddress, getAddress } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { AuditLedger, MemoryLedgerStore, MemorySpendLimiter, VadunoGuard } from "@vaduno/guard";
import { createGuardedAccount } from "./_fixed-account.mjs";
import { SELLER, USDC, CHAIN_ID, eip3009Types, randomNonce, tag } from "./attack-harness.mjs";

const ATTACKER = getAddress("0xdead00000000000000000000000000000000dead");

function fixedRig() {
  const realAccount = privateKeyToAccount(generatePrivateKey());
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const guard = new VadunoGuard({
    policy: {
      id: "fix-rig", version: 1, currency: "USDC",
      limits: { perTransactionMinor: 50_000, perDayMinor: 200_000 },
      merchants: { allow: [`id:${SELLER.toLowerCase()}`] },
    },
    ledger, limiter: new MemorySpendLimiter(),
  });
  const guarded = createGuardedAccount({
    account: realAccount, guard, agentId: "fix-rig",
    assets: [{ chainId: CHAIN_ID, address: USDC, symbol: "USDC", decimals: 6 }],
  });
  return { realAccount, guarded, ledger };
}

const base = (from, nonce, validBefore) => ({
  domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
  types: eip3009Types,
  primaryType: "TransferWithAuthorization",
  message: { from, to: SELLER, value: 10_000n, validAfter: 0n, validBefore, nonce },
});

// ---- A: getter TOCTOU against the fixed wrapper ----
{
  const { guarded, realAccount } = fixedRig();
  let hostile = false, vb = 0;
  const nonce = randomNonce();
  const validBefore = BigInt(Math.floor(Date.now() / 1000) + 300);
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
  let verdict;
  try {
    const sig = await guarded.signTypedData(td);
    const hv = { domain: td.domain, types: eip3009Types, primaryType: "TransferWithAuthorization",
      message: { from: realAccount.address, to: ATTACKER, value: 100_000_000n, validAfter: 0n, validBefore, nonce } };
    const rec = await recoverTypedDataAddress({ ...hv, signature: sig }).catch(() => "n/a");
    verdict = String(rec).toLowerCase() === realAccount.address.toLowerCase()
      ? "*** STILL BYPASSED ***"
      : "signature binds to the VETTED payload (attack neutralized)";
  } catch (e) { verdict = `refused [${tag(e)}]`; }
  console.log("ATTACK A vs fixed wrapper:", verdict);
}

// ---- B: mutation race against the fixed wrapper ----
{
  const { guarded, realAccount } = fixedRig();
  const nonce = randomNonce();
  const validBefore = BigInt(Math.floor(Date.now() / 1000) + 300);
  const td = base(realAccount.address, nonce, validBefore);
  const pending = guarded.signTypedData(td);
  td.message.to = ATTACKER;
  td.message.value = 100_000_000n;
  let verdict;
  try {
    const sig = await pending;
    const hv = { ...td, message: { from: realAccount.address, to: ATTACKER, value: 100_000_000n, validAfter: 0n, validBefore, nonce } };
    const rec = await recoverTypedDataAddress({ ...hv, signature: sig }).catch(() => "n/a");
    verdict = String(rec).toLowerCase() === realAccount.address.toLowerCase()
      ? "*** STILL BYPASSED ***"
      : "signature binds to the VETTED payload (attack neutralized)";
  } catch (e) { verdict = `refused [${tag(e)}]`; }
  console.log("ATTACK B vs fixed wrapper:", verdict);
}

// ---- regression: the honest path still works, and still enforces ----
{
  const { guarded, realAccount, ledger } = fixedRig();
  const sig = await guarded.signTypedData(base(realAccount.address, randomNonce(), BigInt(Math.floor(Date.now() / 1000) + 300)));
  console.log("honest sign still works:", typeof sig === "string" && sig.length === 132);
  const td2 = base(realAccount.address, randomNonce(), BigInt(Math.floor(Date.now() / 1000) + 300));
  td2.message.value = 60_000n;
  try { await guarded.signTypedData(td2); console.log("over-cap: *** NOT REFUSED ***"); }
  catch (e) { console.log("over-cap still refused:", tag(e)); }
  // idempotent replay still re-issues the identical signature
  const td3 = base(realAccount.address, randomNonce(), BigInt(Math.floor(Date.now() / 1000) + 300));
  const a = await guarded.signTypedData(td3);
  const b = await guarded.signTypedData(td3);
  console.log("idempotent replay preserved:", a === b);
  console.log("ledger verify:", JSON.stringify(await ledger.verify()));
}
