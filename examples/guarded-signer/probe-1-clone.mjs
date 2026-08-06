/**
 * PROBE 1 — did structuredClone() break inputs the old path accepted, and does
 * the SIGNED payload still equal what the old path would have signed?
 *
 * The fix for DEFECT 1 clones the request and signs the clone. Anything the
 * clone changes is a change to the bytes that reach the chain.
 */
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { hashTypedData, getAddress } from "viem";
import { AuditLedger, MemoryLedgerStore, MemorySpendLimiter, VadunoGuard } from "@vaduno/guard";
import { createGuardedAccount, GuardSignerRefusedError } from "./guarded-account.mjs";

const CHAIN_ID = 84532;
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const SELLER = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const real = privateKeyToAccount(generatePrivateKey());

const types = {
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

function payload(over = {}) {
  return {
    domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    types,
    primaryType: "TransferWithAuthorization",
    message: {
      from: real.address,
      to: SELLER,
      value: 10000n,
      validAfter: 0n,
      validBefore: BigInt(Math.floor(Date.now() / 1000) + 300),
      nonce: nonce32(),
      ...over,
    },
  };
}

function rig(opts = {}) {
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const guard = new VadunoGuard({
    policy: {
      id: "probe", version: 1, currency: "USDC",
      limits: { perTransactionMinor: 50_000, perDayMinor: 500_000 },
      merchants: { allow: [`id:${SELLER.toLowerCase()}`] },
    },
    ledger,
    limiter: new MemorySpendLimiter(),
  });
  return {
    ledger, guard,
    guarded: createGuardedAccount({
      account: real, guard, agentId: "probe",
      assets: [{ chainId: CHAIN_ID, address: USDC, symbol: "USDC", decimals: 6 }],
      ...opts,
    }),
  };
}

const out = [];
const rec = (name, verdict, detail) => {
  out.push({ name, verdict, detail });
  console.log(`${verdict}  ${name}\n        ${detail}`);
};

// ---------------------------------------------------------------------------
// 1a. Byte fidelity: does the clone hash to the same digest as the original?
{
  const p = payload();
  const before = hashTypedData(p);
  const after = hashTypedData(structuredClone(p));
  rec(
    "1a clone preserves the EIP-712 digest (bigint + nested)",
    before === after ? "OK" : "REGRESSION",
    `original ${before}\n        clone    ${after}`,
  );
}

// 1b. The signature the wrapper returns must verify against the ORIGINAL bytes.
{
  const { guarded } = rig();
  const p = payload();
  const expected = await real.signTypedData(p);
  const got = await guarded.signTypedData(p);
  rec(
    "1b guarded signature is byte-identical to an unguarded signature",
    expected === got ? "OK" : "REGRESSION",
    `unguarded ${expected.slice(0, 26)}...\n        guarded   ${got.slice(0, 26)}...`,
  );
}

// 1c. Inputs the OLD path accepted but structuredClone may reject.
const hostileButLegit = [
  ["plain object (control)", () => payload()],
  ["extra function-valued property on the request", () => ({ ...payload(), onSigned: () => {} })],
  ["function nested inside message", () => {
    const p = payload();
    p.message.cb = () => {};
    return p;
  }],
  ["symbol-keyed extra", () => {
    const p = payload();
    p[Symbol("x")] = 1;
    return p;
  }],
  ["class instance as domain", () => {
    class Domain {
      constructor() {
        this.name = "USDC"; this.version = "2";
        this.chainId = CHAIN_ID; this.verifyingContract = USDC;
      }
    }
    const p = payload();
    p.domain = new Domain();
    return p;
  }],
  ["Proxy over the whole request", () => new Proxy(payload(), {})],
  ["circular reference in the request", () => {
    const p = payload();
    p.self = p;
    return p;
  }],
  ["getter-bearing message (the DEFECT-1 shape)", () => {
    const p = payload();
    const to = SELLER;
    Object.defineProperty(p.message, "to", { get: () => to, enumerable: true, configurable: true });
    return p;
  }],
];

for (const [name, make] of hostileButLegit) {
  const { guarded } = rig();
  let verdict, detail;
  try {
    const sig = await guarded.signTypedData(make());
    verdict = "SIGNS";
    detail = `signature produced (${sig.slice(0, 18)}...)`;
  } catch (err) {
    verdict = "REFUSES";
    detail = err instanceof GuardSignerRefusedError
      ? `${err.code}: ${String(err.message).slice(0, 90)}`
      : `${err?.name}: ${String(err?.message).slice(0, 90)}`;
  }
  rec(`1c ${name}`, verdict, detail);
}

// 1d. Would the UNGUARDED viem account have accepted the ones we now refuse?
console.log("\n--- what the raw viem account does with the same inputs ---");
for (const [name, make] of hostileButLegit) {
  let v;
  try {
    await real.signTypedData(make());
    v = "raw account SIGNS";
  } catch (err) {
    v = `raw account throws: ${err?.name}: ${String(err?.message).split("\n")[0].slice(0, 70)}`;
  }
  console.log(`        ${name} -> ${v}`);
}

console.log("\nSUMMARY");
for (const r of out) console.log(`  ${r.verdict.padEnd(11)} ${r.name}`);
