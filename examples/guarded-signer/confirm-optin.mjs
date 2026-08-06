/**
 * Two of the original semantic attacks still print BYPASS. Is the fix broken,
 * or is it opt-in and the harness never opted in?
 */
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { getAddress } from "viem";
import { AuditLedger, MemoryLedgerStore, MemorySpendLimiter, VadunoGuard } from "@vaduno/guard";
import { createGuardedAccount } from "./guarded-account.mjs";

const BASE_SEPOLIA = 84532;
const SEPOLIA = 11155111;
const USDC_84532 = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const USDC_11155111 = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
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

function mk(policy, extra = {}) {
  const guard = new VadunoGuard({
    policy: { id: "p", version: 1, currency: "USDC", ...policy },
    ledger: new AuditLedger(new MemoryLedgerStore()),
    limiter: new MemorySpendLimiter(),
  });
  return createGuardedAccount({
    account: acct0,
    guard,
    agentId: "a",
    assets: [
      { chainId: BASE_SEPOLIA, address: USDC_84532, symbol: "USDC", decimals: 6 },
      { chainId: SEPOLIA, address: USDC_11155111, symbol: "USDC", decimals: 6 },
    ],
    ...extra,
  });
}

const wrongChain = {
  domain: { name: "USDC", version: "2", chainId: SEPOLIA, verifyingContract: USDC_11155111 },
  types: eip3009Types,
  primaryType: "TransferWithAuthorization",
  message: {
    from: acct0.address,
    to: SELLER,
    value: 10_000n,
    validAfter: 0n,
    validBefore: soon(),
    nonce: nonce32(),
  },
};

// A: the policy the original harness used — no networks constraint at all.
{
  const a = mk({
    limits: { perTransactionMinor: 50_000, perDayMinor: 200_000 },
    merchants: { allow: [`id:${SELLER.toLowerCase()}`] },
  });
  try {
    await a.signTypedData(wrongChain);
    console.log("A) policy WITHOUT networks{}: SIGNED on the wrong chain -> fix is OPT-IN, default is permissive");
  } catch (e) {
    console.log(`A) policy WITHOUT networks{}: refused [${e.code}]`);
  }
}

// B: the same attack with the operator opting in.
{
  const b = mk({
    limits: { perTransactionMinor: 50_000, perDayMinor: 200_000 },
    merchants: { allow: [`id:${SELLER.toLowerCase()}`] },
    networks: { allow: [`eip155:${BASE_SEPOLIA}`] },
  });
  try {
    await b.signTypedData(wrongChain);
    console.log("B) policy WITH networks.allow: SIGNED -> the network fix does NOT work");
  } catch (e) {
    console.log(`B) policy WITH networks.allow: refused [${e.code}] -> fix works when declared`);
  }
}

// C: host-pattern merchant policy + arbitrary payee (the second surviving bypass).
{
  const c = mk(
    {
      limits: { perTransactionMinor: 50_000, perDayMinor: 200_000 },
      merchants: { allow: ["host:x402.org"] },
    },
    { merchantUrl: "https://x402.org/protected" },
  );
  try {
    await c.signTypedData({
      domain: { name: "USDC", version: "2", chainId: BASE_SEPOLIA, verifyingContract: USDC_84532 },
      types: eip3009Types,
      primaryType: "TransferWithAuthorization",
      message: {
        from: acct0.address,
        to: ATTACKER,
        value: 10_000n,
        validAfter: 0n,
        validBefore: soon(),
        nonce: nonce32(),
      },
    });
    console.log(
      `C) merchants.allow=['host:x402.org'] + fixed merchantUrl: SIGNED a transfer to ${ATTACKER}\n` +
        "   -> host patterns police a CONSTANT in a signer-level deployment (documented in engine.ts)",
    );
  } catch (e) {
    console.log(`C) host-pattern policy: refused [${e.code}]`);
  }
}
