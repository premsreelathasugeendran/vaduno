/**
 * Shared test rig: a real VadunoGuard over an in-memory ledger and limiter,
 * wrapped around a freshly generated throwaway key. Nothing here touches a
 * network; a produced SIGNATURE is the proof of bypass.
 */
import { getAddress } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  AuditLedger,
  MemoryLedgerStore,
  MemorySpendLimiter,
  VadunoGuard,
  type PaymentIntent,
  type SpendPolicy,
} from "@vaduno/guard";
import { guardedSigner, type GuardedSignerOptions } from "../src/index.js";

export const CHAIN_ID = 84532;
export const NETWORK = `eip155:${CHAIN_ID}`;
export const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
export const SELLER = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
export const ATTACKER = getAddress("0xdead00000000000000000000000000000000dead");
export const EIP3009_TOKEN_COLLECTOR = "0x0E3dF9510de65469C4518D7843919c0b8C7A7757";
export const TWO_DEC = "0x1111111111111111111111111111111111111111";
export const EIGHT_DEC = "0x3333333333333333333333333333333333333333";

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

export const permitWitnessTypes = {
  PermitWitnessTransferFrom: [
    { name: "permitted", type: "TokenPermissions" },
    { name: "spender", type: "address" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
    { name: "witness", type: "Witness" },
  ],
  TokenPermissions: [
    { name: "token", type: "address" },
    { name: "amount", type: "uint256" },
  ],
  Witness: [
    { name: "to", type: "address" },
    { name: "facilitator", type: "address" },
    { name: "validAfter", type: "uint256" },
  ],
};

export const nonce32 = (): string => {
  const buf = new Uint8Array(32);
  globalThis.crypto.getRandomValues(buf);
  return `0x${Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("")}`;
};

export const soon = (): bigint => BigInt(Math.floor(Date.now() / 1000) + 300);

export const realAccount = privateKeyToAccount(generatePrivateKey());

/** A well-formed EIP-3009 request to the allowlisted seller for 0.01 USDC. */
export function honestTransfer(overrides: {
  to?: string;
  value?: bigint;
  from?: string;
  chainId?: number | string | bigint;
  verifyingContract?: string;
  validBefore?: bigint;
  validAfter?: bigint;
  nonce?: string;
  types?: Record<string, unknown>;
} = {}) {
  return {
    domain: {
      name: "USDC",
      version: "2",
      chainId: overrides.chainId ?? CHAIN_ID,
      verifyingContract: overrides.verifyingContract ?? USDC,
    },
    types: overrides.types ?? eip3009Types,
    primaryType: "TransferWithAuthorization",
    message: {
      from: overrides.from ?? realAccount.address,
      to: overrides.to ?? SELLER,
      value: overrides.value ?? 10_000n,
      validAfter: overrides.validAfter ?? 0n,
      validBefore: overrides.validBefore ?? soon(),
      nonce: overrides.nonce ?? nonce32(),
    },
  };
}

export interface GuardCalls {
  statuses: string[];
  intents: PaymentIntent[];
}

export interface Rig {
  guarded: ReturnType<typeof guardedSigner>;
  ledger: AuditLedger;
  guard: VadunoGuard;
  calls: GuardCalls;
}

export function rig(
  opts: {
    merchants?: SpendPolicy["merchants"];
    networks?: SpendPolicy["networks"];
    currency?: string;
    limits?: SpendPolicy["limits"];
    assets?: GuardedSignerOptions["assets"];
    account?: GuardedSignerOptions["account"];
  } & Partial<
    Pick<
      GuardedSignerOptions,
      | "agentId"
      | "merchantUrl"
      | "currencyDecimals"
      | "maxValiditySeconds"
      | "resolveAuthCapture"
      | "authCaptureCollectors"
      | "permit2Spenders"
    >
  > = {},
): Rig {
  const {
    merchants = { allow: [`id:${SELLER.toLowerCase()}`] },
    networks,
    currency = "USDC",
    limits = { perTransactionMinor: 50_000, perDayMinor: 200_000 },
    assets = [{ network: NETWORK, asset: USDC, symbol: "USDC", decimals: 6 }],
    account = realAccount,
    ...rest
  } = opts;
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const guard = new VadunoGuard({
    policy: {
      id: "cloudflare-signer-test",
      version: 1,
      currency,
      limits,
      merchants,
      ...(networks ? { networks } : {}),
    },
    ledger,
    limiter: new MemorySpendLimiter(),
  });
  const calls: GuardCalls = { statuses: [], intents: [] };
  const counting = {
    authorize: async (intent: PaymentIntent) => {
      calls.intents.push(intent);
      const result = await guard.authorize(intent);
      calls.statuses.push(result.status);
      return result;
    },
    settle: guard.settle.bind(guard),
    releaseSpend: guard.releaseSpend.bind(guard),
    getPolicy: guard.getPolicy.bind(guard),
  };
  const guarded = guardedSigner({
    account,
    guard: counting,
    agentId: "cloudflare-signer-test",
    assets,
    ...rest,
  });
  return { guarded, ledger, guard, calls };
}

export function tag(err: unknown): string {
  const e = err as { name?: string; code?: string; message?: string };
  return e?.name === "GuardSignerRefusedError"
    ? String(e.code)
    : `${e?.name}: ${String(e?.message).slice(0, 120)}`;
}

export async function executedRows(ledger: AuditLedger): Promise<number> {
  const all = await ledger.all();
  return all.filter(
    (e) =>
      e.type === "execution_result" &&
      (e.data as { success?: boolean } | undefined)?.success === true,
  ).length;
}

/** Rows whose serialized form mentions the given intent id. */
export async function rowsMentioning(ledger: AuditLedger, intentId: string): Promise<number> {
  const all = await ledger.all();
  return all.filter((e) => JSON.stringify(e).includes(intentId)).length;
}
