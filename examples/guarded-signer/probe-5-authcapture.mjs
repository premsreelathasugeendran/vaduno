/**
 * PROBE 5 — the DEFECT-2 fix (collector aliasing) as new attack surface.
 *  5a. Is the caller's DECLARATION snapshotted, or re-read after verification?
 *      (the fix's own doctrine, applied to the object the fix introduced)
 *  5b. Does the real shipped permit2 auth-capture flavour have any path at all?
 *  5c. Does an honest bigint declaration break the happy path?
 */
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { getAddress, encodeAbiParameters, keccak256, zeroAddress } from "viem";
import { AuditLedger, MemoryLedgerStore, MemorySpendLimiter, VadunoGuard } from "@vaduno/guard";
import { AuthCaptureEvmScheme } from "@x402/evm";
import { createGuardedAccount, GuardSignerRefusedError } from "./guarded-account.mjs";

const CHAIN_ID = 84532;
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const SELLER = getAddress("0x209693Bc6afc0C5328bA36FaF03C514EF312287C");
const ATTACKER = getAddress("0xdead00000000000000000000000000000000dead");
const COLLECTOR = getAddress("0x0E3dF9510de65469C4518D7843919c0b8C7A7757");
const ESCROW = "0xBdEA0D1bcC5966192B070Fdf62aB4EF5b4420cff";
const real = privateKeyToAccount(generatePrivateKey());

const PAYMENT_INFO_TYPEHASH = keccak256(
  new TextEncoder().encode(
    "PaymentInfo(address operator,address payer,address receiver,address token,uint120 maxAmount," +
      "uint48 preApprovalExpiry,uint48 authorizationExpiry,uint48 refundExpiry,uint16 minFeeBps," +
      "uint16 maxFeeBps,address feeReceiver,uint256 salt)",
  ),
);

/** Independent re-implementation, so the probe does not depend on the wrapper. */
function nonceFor({ chainId, token, maxAmount, preApprovalExpiry, d }) {
  const inner = encodeAbiParameters(
    [
      { name: "typehash", type: "bytes32" }, { name: "operator", type: "address" },
      { name: "payer", type: "address" }, { name: "receiver", type: "address" },
      { name: "token", type: "address" }, { name: "maxAmount", type: "uint120" },
      { name: "preApprovalExpiry", type: "uint48" }, { name: "authorizationExpiry", type: "uint48" },
      { name: "refundExpiry", type: "uint48" }, { name: "minFeeBps", type: "uint16" },
      { name: "maxFeeBps", type: "uint16" }, { name: "feeReceiver", type: "address" },
      { name: "salt", type: "uint256" },
    ],
    [
      PAYMENT_INFO_TYPEHASH, getAddress(d.operator), zeroAddress, getAddress(d.receiver),
      getAddress(token), maxAmount, preApprovalExpiry, BigInt(d.authorizationExpiry),
      BigInt(d.refundExpiry), BigInt(d.minFeeBps), BigInt(d.maxFeeBps),
      getAddress(d.feeRecipient), BigInt(d.salt),
    ],
  );
  const outer = encodeAbiParameters(
    [{ name: "chainId", type: "uint256" }, { name: "escrow", type: "address" }, { name: "h", type: "bytes32" }],
    [BigInt(chainId), ESCROW, keccak256(inner)],
  );
  return keccak256(outer).toLowerCase();
}

const receiveTypes = {
  ReceiveWithAuthorization: [
    { name: "from", type: "address" }, { name: "to", type: "address" },
    { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" },
  ],
};

function rig({ merchants = { allow: [`id:${SELLER.toLowerCase()}`] }, ...rest } = {}) {
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const intents = [];
  const g = new VadunoGuard({
    policy: {
      id: "probe", version: 1, currency: "USDC",
      limits: { perTransactionMinor: 50_000, perDayMinor: 500_000 }, merchants,
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
    guarded: createGuardedAccount({
      account: real, guard, agentId: "probe",
      assets: [{ chainId: CHAIN_ID, address: USDC, symbol: "USDC", decimals: 6 }],
      ...rest,
    }),
  };
}

const MAX = 10_000n;
const EXPIRY = 4_000_000_000n;

// =========================================================== 5a declaration TOCTOU
console.log("=== 5a. is the DECLARATION snapshotted before use, as the request is? ===");
{
  // A declaration that names the TRUE receiver on the read the nonce check
  // uses, and an allowlisted one on every read after that.
  const truth = {
    operator: SELLER, receiver: ATTACKER, feeRecipient: ATTACKER,
    minFeeBps: 0, maxFeeBps: 10_000,
    authorizationExpiry: 4_000_000_000, refundExpiry: 4_000_000_000, salt: 42,
  };
  const nonce = nonceFor({
    chainId: CHAIN_ID, token: USDC, maxAmount: MAX, preApprovalExpiry: EXPIRY, d: truth,
  });

  let receiverReads = 0;
  let feeReads = 0;
  const twoFaced = {
    operator: SELLER,
    minFeeBps: 0, maxFeeBps: 10_000,
    authorizationExpiry: 4_000_000_000, refundExpiry: 4_000_000_000, salt: 42,
    get receiver() {
      receiverReads += 1;
      return receiverReads === 1 ? ATTACKER : SELLER; // truth to the hash, lie to the guard
    },
    get feeRecipient() {
      feeReads += 1;
      return feeReads === 1 ? ATTACKER : SELLER;      // ditto for the evidence
    },
  };

  const { guarded, intents, ledger } = rig({ resolveAuthCapture: () => twoFaced });
  let outcome;
  try {
    await guarded.signTypedData({
      domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
      types: receiveTypes, primaryType: "ReceiveWithAuthorization",
      message: {
        from: real.address, to: COLLECTOR, value: MAX,
        validAfter: 0n, validBefore: EXPIRY, nonce,
      },
    });
    outcome = "SIGNED";
  } catch (e) {
    outcome = `refused ${e instanceof GuardSignerRefusedError ? e.code : e?.name}`;
  }
  const told = intents.at(-1)?.merchant?.id;
  const meta = intents.at(-1)?.metadata?.authCapture;
  console.log(
    `  nonce cryptographically commits to receiver=${ATTACKER}, feeRecipient=${ATTACKER}`,
  );
  console.log(`  outcome: ${outcome}`);
  console.log(`  guard was told merchant.id = ${told}`);
  console.log(`  ledger records feeRecipient = ${meta?.feeRecipient}`);
  console.log(`  receiver getter invoked ${receiverReads}x, feeRecipient getter ${feeReads}x`);
  console.log(
    outcome === "SIGNED" && told === SELLER.toLowerCase()
      ? "  >> BYPASS: the verified value and the policed value are different reads"
      : "  >> held",
  );
}

// ======================================================== 5b permit2 auth-capture
console.log("\n=== 5b. the shipped permit2 auth-capture flavour, through the wrapper ===");
{
  const captured = [];
  const recorder = {
    address: real.address,
    signTypedData: async (t) => { captured.push(t); return real.signTypedData(t); },
  };
  const reqs = {
    scheme: "auth-capture", network: `eip155:${CHAIN_ID}`, asset: USDC,
    payTo: SELLER, amount: "10000", maxTimeoutSeconds: 600,
    extra: {
      name: "USDC", version: "2", captureAuthorizer: SELLER, feeRecipient: SELLER,
      captureDeadline: 4_000_000_000, refundDeadline: 4_000_000_000,
      minFeeBps: 0, maxFeeBps: 100, assetTransferMethod: "permit2",
    },
  };
  await new AuthCaptureEvmScheme(recorder).createPaymentPayload(2, reqs);
  const t = captured[0];
  console.log(`  shipped permit2 auth-capture signs primaryType=${t.primaryType}, spender=${t.message.spender}`);

  // Now the same through a guarded account WITH a resolveAuthCapture declared.
  const { guarded } = rig({ resolveAuthCapture: () => ({
    operator: SELLER, receiver: SELLER, feeRecipient: SELLER, minFeeBps: 0, maxFeeBps: 100,
    authorizationExpiry: 4_000_000_000, refundExpiry: 4_000_000_000, salt: 1,
  }) });
  let outcome;
  try {
    await new AuthCaptureEvmScheme(guarded).createPaymentPayload(2, reqs);
    outcome = "SIGNED";
  } catch (e) {
    outcome = `refused ${e instanceof GuardSignerRefusedError ? e.code : `${e?.name}: ${String(e?.message).slice(0, 60)}`}`;
  }
  console.log(`  with resolveAuthCapture supplied -> ${outcome}`);
  console.log(
    "  (PermitTransferFrom is still not a recognized PAYMENT shape — there is no payee in the",
  );
  console.log(
    "   signed struct to police. It is now matched against DEFAULT_AUTH_CAPTURE_COLLECTORS on",
  );
  console.log(
    "   `spender` and default-denied BY NAME, so the PERMIT2 entry in that list is reachable",
  );
  console.log("   rather than decorative. Still refused; now diagnosable.)");
}

// ============================================================ 5c bigint declaration
console.log("\n=== 5c. an honest declaration written with bigints ===");
for (const [label, d] of [
  ["numbers (as the README shows)", {
    operator: SELLER, receiver: SELLER, feeRecipient: SELLER, minFeeBps: 0, maxFeeBps: 100,
    authorizationExpiry: 4_000_000_000, refundExpiry: 4_000_000_000, salt: 7,
  }],
  ["bigints (the natural EVM type)", {
    operator: SELLER, receiver: SELLER, feeRecipient: SELLER, minFeeBps: 0n, maxFeeBps: 100n,
    authorizationExpiry: 4_000_000_000n, refundExpiry: 4_000_000_000n, salt: 7n,
  }],
]) {
  const nonce = nonceFor({
    chainId: CHAIN_ID, token: USDC, maxAmount: MAX, preApprovalExpiry: EXPIRY, d,
  });
  const { guarded, intents } = rig({ resolveAuthCapture: () => d });
  let outcome, codes = "";
  try {
    await guarded.signTypedData({
      domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
      types: receiveTypes, primaryType: "ReceiveWithAuthorization",
      message: {
        from: real.address, to: COLLECTOR, value: MAX,
        validAfter: 0n, validBefore: EXPIRY, nonce,
      },
    });
    outcome = "SIGNED";
  } catch (e) {
    outcome = "refused";
    codes = e instanceof GuardSignerRefusedError ? e.code : `${e?.name}`;
  }
  console.log(
    `  ${label.padEnd(32)} nonce verified OK -> ${outcome} ${codes}` +
      `   (guard saw merchant.id=${intents.at(-1)?.merchant?.id})`,
  );
}
