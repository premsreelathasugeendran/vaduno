/**
 * N4/N6 claim that an unusable authorization BURNS the agent's daily budget.
 * "A ledger row was written" is not that claim. This proves the stronger one:
 * after signing authorizations that no token contract can ever accept, an
 * HONEST payment is denied for want of budget.
 */
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { getAddress } from "viem";
import { AuditLedger, MemoryLedgerStore, MemorySpendLimiter, VadunoGuard } from "@vaduno/guard";
import { createGuardedAccount } from "./guarded-account.mjs";

const CHAIN_ID = 84532;
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const SELLER = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const ATTACKER = getAddress("0xdead00000000000000000000000000000000dead");
const acct0 = privateKeyToAccount(generatePrivateKey());

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
const soon = () => BigInt(Math.floor(Date.now() / 1e3) + 300);

function rig() {
  const guard = new VadunoGuard({
    policy: {
      id: "burn",
      version: 1,
      currency: "USDC",
      // $0.10 per txn, $0.20 per day: room for exactly two payments.
      limits: { perTransactionMinor: 100_000, perDayMinor: 200_000 },
      merchants: { allow: [`id:${SELLER.toLowerCase()}`] },
    },
    ledger: new AuditLedger(new MemoryLedgerStore()),
    limiter: new MemorySpendLimiter(),
  });
  return createGuardedAccount({
    account: acct0,
    guard,
    agentId: "burn",
    assets: [{ chainId: CHAIN_ID, address: USDC, symbol: "USDC", decimals: 6 }],
  });
}

const td = ({ from = acct0.address, validBefore = soon(), value = 100_000n }) => ({
  domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
  types: eip3009Types,
  primaryType: "TransferWithAuthorization",
  message: { from, to: SELLER, value, validAfter: 0n, validBefore, nonce: nonce32() },
});

async function trial(label, mkDead) {
  const a = rig();
  // Two DISTINCT authorizations (fresh nonce each, so neither is a replay)
  // that can never settle: expired, or drawn on a payer this key is not.
  // Together they are the whole $0.20 daily cap.
  await a.signTypedData(mkDead());
  await a.signTypedData(mkDead());
  // Now an entirely honest payment, well within the per-transaction cap.
  try {
    await a.signTypedData(td({}));
    console.log(`${label}: honest payment still SIGNED (no budget burned)`);
  } catch (e) {
    console.log(`${label}: honest payment REFUSED [${e.code}] — the dead authorizations consumed the daily cap`);
  }
}

await trial("N4 expired (validBefore=1)   ", () => td({ validBefore: 1n }));
await trial("N6 wrong payer (from=attacker)", () => td({ from: ATTACKER }));
