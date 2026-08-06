/**
 * RE-RUN of attack-semantic.mjs ATTACK 3 ("policy is chain-blind") against the
 * fixed guard, plus the two controls that decide whether the fix is real.
 *
 * The original: an ordinary two-chain asset registry (Base Sepolia USDC and
 * Ethereum Sepolia USDC, both symbol "USDC"), a deployment targeting 84532, and
 * a signature happily produced for a transfer on 11155111. Same intent shape,
 * same currency, wrong chain. No policy rule could object, because the chain
 * lived in `metadata` and nothing reads metadata.
 *
 * SAFETY: freshly generated throwaway key, zero balance on every network. No
 * signature produced here is submitted anywhere. No mainnet-domain signature.
 */
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { AuditLedger, MemoryLedgerStore, MemorySpendLimiter, VadunoGuard } from "@vaduno/guard";
import { createGuardedAccount } from "./guarded-account.mjs";

const BASE_SEPOLIA = 84532;
const SEPOLIA = 11155111;
const USDC_84532 = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const USDC_11155111 = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
const SELLER = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";

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
const nonce32 = () =>
  `0x${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex")}`;

function mkGuard(networks) {
  return new VadunoGuard({
    policy: {
      id: "attack",
      version: 1,
      currency: "USDC",
      limits: { perTransactionMinor: 50_000, perDayMinor: 200_000 },
      merchants: { allow: [`id:${SELLER.toLowerCase()}`] },
      ...(networks ? { networks } : {}),
    },
    ledger: new AuditLedger(new MemoryLedgerStore()),
    limiter: new MemorySpendLimiter(),
  });
}

function mkAccount(guard) {
  return createGuardedAccount({
    account: realAccount,
    guard,
    agentId: "a",
    assets: [
      { chainId: BASE_SEPOLIA, address: USDC_84532, symbol: "USDC", decimals: 6 },
      { chainId: SEPOLIA, address: USDC_11155111, symbol: "USDC", decimals: 6 },
    ],
  });
}

async function trySign(acct, chainId, asset) {
  try {
    const sig = await acct.signTypedData({
      domain: { name: "USDC", version: "2", chainId, verifyingContract: asset },
      types: eip3009Types,
      primaryType: "TransferWithAuthorization",
      message: {
        from: realAccount.address,
        to: SELLER,
        value: 10_000n,
        validAfter: 0n,
        validBefore: BigInt(Math.floor(Date.now() / 1e3) + 300),
        nonce: nonce32(),
      },
    });
    return { signed: true, sig };
  } catch (e) {
    return { signed: false, code: e?.code, message: e?.message?.slice(0, 160) };
  }
}

const CHAIN_POLICY = { allow: [`eip155:${BASE_SEPOLIA}`] };
const rows = [];

// 1. THE ATTACK: wrong chain, chain-constrained policy. Must refuse.
{
  const r = await trySign(mkAccount(mkGuard(CHAIN_POLICY)), SEPOLIA, USDC_11155111);
  rows.push([
    "wrong chain under networks.allow=[eip155:84532]",
    !r.signed,
    r.signed ? "SIGNED — still chain-blind" : `refused: ${r.code}`,
  ]);
}

// 2. CONTROL: right chain, same policy. Must still work, or the fix is a brick.
{
  const r = await trySign(mkAccount(mkGuard(CHAIN_POLICY)), BASE_SEPOLIA, USDC_84532);
  rows.push([
    "right chain under the same policy still signs",
    r.signed,
    r.signed ? `signed 0x${r.sig.slice(2, 14)}...` : `refused: ${r.code}`,
  ]);
}

// 3. CONTROL: no networks block = the pre-existing behaviour, unchanged.
//    This is the additive default, and it is deliberately NOT a bypass claim:
//    it is the documented cost of not breaking every deployment on upgrade.
{
  const r = await trySign(mkAccount(mkGuard(null)), SEPOLIA, USDC_11155111);
  rows.push([
    "no networks block: chain-blind, as documented (additive default)",
    r.signed,
    r.signed ? "signed — set policy.networks to gate the chain" : `refused: ${r.code}`,
  ]);
}

console.log("\n=========== chain-blindness re-test ===========");
let ok = true;
for (const [name, pass, detail] of rows) {
  if (!pass) ok = false;
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}\n      ${detail}`);
}
console.log(ok ? "\nALL EXPECTATIONS MET" : "\nEXPECTATIONS NOT MET");
process.exit(ok ? 0 : 1);
