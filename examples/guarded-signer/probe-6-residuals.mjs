/**
 * PROBE 6 — the three residuals left after the digest rebuild.
 *
 *  6a. A scaled amount over Number.MAX_SAFE_INTEGER collapses to 0 and is
 *      denied INVALID_AMOUNT, which points the operator at the amount when the
 *      real cause is `currencyDecimals` configuration.
 *  6b. The permit2 flavour of the shipped auth-capture scheme is refused only by
 *      the generic UNRECOGNIZED_TYPED_DATA fallback — the collector list's
 *      PERMIT2 entry is dead code and the refusal names nothing an operator can
 *      act on.
 *  6c. The intent id is the digest, but the COMMITTED FIELD SET — the thing that
 *      decides which facts were policeable at all — is not in the evidence, so
 *      an auditor cannot tell a full EIP-3009 struct from a narrowed one.
 */
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { getAddress } from "viem";
import { AuditLedger, MemoryLedgerStore, MemorySpendLimiter, VadunoGuard } from "@vaduno/guard";
import { AuthCaptureEvmScheme } from "@x402/evm";
import { createGuardedAccount, GuardSignerRefusedError } from "./guarded-account.mjs";

const CHAIN_ID = 84532;
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const DAI_LIKE = "0x2222222222222222222222222222222222222222";
const SELLER = getAddress("0x209693Bc6afc0C5328bA36FaF03C514EF312287C");
const real = privateKeyToAccount(generatePrivateKey());

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
const soon = () => BigInt(Math.floor(Date.now() / 1000) + 300);

function rig({ assets = [{ chainId: CHAIN_ID, address: USDC, symbol: "USDC", decimals: 6 }], ...rest } = {}) {
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const intents = [];
  const g = new VadunoGuard({
    policy: {
      id: "probe6", version: 1, currency: "USDC",
      limits: { perTransactionMinor: 50_000, perDayMinor: 500_000 },
      merchants: { allow: [`id:${SELLER.toLowerCase()}`] },
    },
    ledger, limiter: new MemorySpendLimiter(),
  });
  const guard = {
    authorize: async (i) => { intents.push(i); return g.authorize(i); },
    settle: (...a) => g.settle(...a),
    releaseSpend: (...a) => g.releaseSpend(...a),
  };
  return {
    intents, ledger,
    guarded: createGuardedAccount({ account: real, guard, agentId: "probe6", assets, ...rest }),
  };
}
const tag = (e) => (e instanceof GuardSignerRefusedError ? e.code : `${e?.name}: ${String(e?.message).slice(0, 80)}`);

// ============================================================ 6a amount overflow
console.log("=== 6a. a scaled amount over MAX_SAFE_INTEGER ===");
{
  // 18-decimal token, policy currency ALSO 18 decimals -> identity scaling, so
  // 1 whole token is 1e18 minor units, which no JS number can hold exactly.
  const { guarded, intents } = rig({
    currencyDecimals: 18,
    assets: [{ chainId: CHAIN_ID, address: DAI_LIKE, symbol: "USDC", decimals: 18 }],
  });
  let outcome;
  try {
    await guarded.signTypedData({
      domain: { name: "DAI", version: "1", chainId: CHAIN_ID, verifyingContract: DAI_LIKE },
      types: eip3009Types,
      primaryType: "TransferWithAuthorization",
      message: { from: real.address, to: SELLER, value: 10n ** 18n, validAfter: 0n, validBefore: soon(), nonce: nonce32() },
    });
    outcome = "SIGNED";
  } catch (e) {
    outcome = tag(e);
  }
  console.log(`  outcome: ${outcome}`);
  console.log(`  recorded evidence: ${JSON.stringify(intents.at(-1)?.metadata)}`);
  const misleading = String(outcome).includes("INVALID_AMOUNT");
  console.log(
    misleading
      ? "  >> MISLEADING: the refusal blames the amount; the cause is currencyDecimals=18"
      : "  >> held: the refusal names the real cause",
  );
}

// =================================================== 6b permit2 auth-capture flavour
console.log("\n=== 6b. the permit2 flavour of the shipped auth-capture scheme ===");
{
  const reqs = {
    scheme: "auth-capture", network: `eip155:${CHAIN_ID}`, asset: USDC,
    payTo: SELLER, amount: "10000", maxTimeoutSeconds: 600,
    extra: {
      name: "USDC", version: "2", captureAuthorizer: SELLER, feeRecipient: SELLER,
      captureDeadline: 4_000_000_000, refundDeadline: 4_000_000_000,
      minFeeBps: 0, maxFeeBps: 100, assetTransferMethod: "permit2",
    },
  };
  const { guarded } = rig({
    resolveAuthCapture: () => ({
      operator: SELLER, receiver: SELLER, feeRecipient: SELLER, minFeeBps: 0, maxFeeBps: 100,
      authorizationExpiry: 4_000_000_000, refundExpiry: 4_000_000_000, salt: 1,
    }),
  });
  let outcome;
  try {
    await new AuthCaptureEvmScheme(guarded).createPaymentPayload(2, reqs);
    outcome = "SIGNED";
  } catch (e) {
    outcome = tag(e);
  }
  console.log(`  outcome: ${outcome}`);
  const generic = outcome === "UNRECOGNIZED_TYPED_DATA";
  console.log(
    generic
      ? "  >> UNDIAGNOSABLE: refused as an unknown shape; the PERMIT2 collector entry never fires"
      : "  >> held: refused with a reason that names the flavour",
  );
}

// ================================================ 6c committed-field set as evidence
console.log("\n=== 6c. is the COMMITTED FIELD SET recorded as evidence? ===");
{
  const { guarded, ledger } = rig();
  await guarded.signTypedData({
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types: eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: { from: real.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: soon(), nonce: nonce32() },
  });
  const recorded = (await ledger.all()).find((e) => e.type === "intent_received")?.data?.intent;
  const committed = recorded?.metadata?.committed;
  console.log(`  ledger metadata keys: ${Object.keys(recorded?.metadata ?? {}).join(", ")}`);
  console.log(`  metadata.committed = ${JSON.stringify(committed)}`);
  console.log(
    committed === undefined
      ? "  >> MISSING: the digest is bound, but WHICH FIELDS it covers is not in the record"
      : "  >> held",
  );
}
