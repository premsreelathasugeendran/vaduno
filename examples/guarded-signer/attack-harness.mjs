/**
 * ADVERSARIAL HARNESS for GuardedAccount. Read-only against the prototype:
 * imports guarded-account.mjs unmodified.
 *
 * SAFETY: uses a FRESH RANDOM throwaway key (generatePrivateKey()), never the
 * example .wallet. Nothing produced here is ever broadcast. A produced
 * SIGNATURE is the proof of bypass; settlement is neither needed nor performed.
 */
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  AuditLedger,
  MemoryLedgerStore,
  MemorySpendLimiter,
  VadunoGuard,
} from "@vaduno/guard";
import { createGuardedAccount, GuardSignerRefusedError } from "./guarded-account.mjs";

export const CHAIN_ID = 84532;
export const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
export const SELLER = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
export const ATTACKER = "0xdeAD00000000000000000000000000000000dEAd";

export const eip3009Types = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};

export function randomNonce() {
  return `0x${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex")}`;
}

/** Build a fresh rig identical in configuration to pay.mjs, but in-memory. */
export function rig({ perTransactionMinor = 50_000, perDayMinor = 200_000 } = {}) {
  const realAccount = privateKeyToAccount(generatePrivateKey());
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const guard = new VadunoGuard({
    policy: {
      id: "attack-rig",
      version: 1,
      currency: "USDC",
      limits: { perTransactionMinor, perDayMinor },
      merchants: { allow: [`id:${SELLER.toLowerCase()}`] },
    },
    ledger,
    limiter: new MemorySpendLimiter(),
  });
  const guarded = createGuardedAccount({
    account: realAccount,
    guard,
    agentId: "attack-rig",
    assets: [{ chainId: CHAIN_ID, address: USDC, symbol: "USDC", decimals: 6 }],
    merchantUrl: "https://x402.org/protected",
  });
  return { realAccount, ledger, guard, guarded };
}

export function typedData({
  to = SELLER,
  value = 10_000n,
  chainId = CHAIN_ID,
  asset = USDC,
  name = "USDC",
  version = "2",
  nonce = randomNonce(),
  validAfter = 0n,
  validBefore = BigInt(Math.floor(Date.now() / 1000) + 300),
  from,
  types = eip3009Types,
  primaryType = "TransferWithAuthorization",
} = {}) {
  return {
    domain: { name, version, chainId, verifyingContract: asset },
    types,
    primaryType,
    message: { from, to, value, validAfter, validBefore, nonce },
  };
}

export function tag(err) {
  return err instanceof GuardSignerRefusedError ? err.code : `${err.name}: ${err.message.slice(0, 90)}`;
}

export { GuardSignerRefusedError };
