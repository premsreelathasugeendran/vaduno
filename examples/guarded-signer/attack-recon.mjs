/**
 * ATTACK RECON — enumerate every member of the real viem account and of the
 * GuardedAccount wrapper. Looking for any signing-capable member the wrapper
 * failed to gate or stub.
 *
 * Uses a THROWAWAY key (not the funded wallet) — we only need shape here.
 */
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { VadunoGuard, AuditLedger, MemoryLedgerStore, MemorySpendLimiter } from "@vaduno/guard";
import { createGuardedAccount } from "./guarded-account.mjs";

const real = privateKeyToAccount(generatePrivateKey());

function describe(label, obj) {
  console.log(`\n=== ${label} ===`);
  console.log("Object.keys        :", Object.keys(obj).join(", "));
  console.log("getOwnPropertyNames:", Object.getOwnPropertyNames(obj).join(", "));
  console.log("ownPropertySymbols :", Object.getOwnPropertySymbols(obj).map(String).join(", ") || "(none)");
  const proto = Object.getPrototypeOf(obj);
  console.log("prototype          :", proto === Object.prototype ? "Object.prototype" : String(proto));
  if (proto && proto !== Object.prototype && proto !== null) {
    console.log("proto own names    :", Object.getOwnPropertyNames(proto).join(", "));
  }
  console.log("for..in            :", (() => { const a = []; for (const k in obj) a.push(k); return a.join(", "); })());
  const fns = [];
  for (const k of Object.getOwnPropertyNames(obj)) {
    const d = Object.getOwnPropertyDescriptor(obj, k);
    const kind = d.get ? "GETTER" : typeof d.value;
    if (kind === "function" || kind === "GETTER") fns.push(`${k}:${kind}`);
  }
  console.log("callable/getters   :", fns.join(", "));
  console.log("frozen             :", Object.isFrozen(obj));
}

describe("REAL viem account (privateKeyToAccount)", real);

const guard = new VadunoGuard({
  policy: {
    id: "recon", version: 1, currency: "USDC",
    limits: { perTransactionMinor: 50_000, perDayMinor: 200_000 },
    merchants: { allow: ["id:0x209693bc6afc0c5328ba36faf03c514ef312287c"] },
  },
  ledger: new AuditLedger(new MemoryLedgerStore()),
  limiter: new MemorySpendLimiter(),
});

const guarded = createGuardedAccount({
  account: real,
  guard,
  agentId: "recon",
  assets: [{ chainId: 84532, address: "0x036CbD53842c5426634e7929541eC2318f3dCF7e", symbol: "USDC", decimals: 6 }],
});

describe("GuardedAccount", guarded);

// Does any member of the wrapper === the real account or any of its methods?
console.log("\n--- identity leak scan ---");
for (const k of Object.getOwnPropertyNames(guarded)) {
  const v = guarded[k];
  if (v === real) console.log(`LEAK: guarded.${k} === real account`);
  for (const rk of Object.getOwnPropertyNames(real)) {
    if (typeof real[rk] === "function" && v === real[rk]) {
      console.log(`LEAK: guarded.${k} === real.${rk} (ungated raw-key method reachable)`);
    }
  }
}
console.log("scan done");

// JSON / structuredClone round trips
console.log("\n--- serialization round trips ---");
console.log("JSON.stringify(guarded):", JSON.stringify(guarded));
try {
  const c = structuredClone(guarded);
  console.log("structuredClone ok:", Object.keys(c));
} catch (e) {
  console.log("structuredClone threw:", e.message.slice(0, 120));
}
