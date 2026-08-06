/**
 * ATTACK 9 — attack the COMMITMENT ANALYSIS itself.
 *
 * The claim under test: "policy is a function of what the EIP-712 digest
 * commits to, so an uncommitted field cannot influence a decision."
 *
 * Every previous check in this family read `types` and REASONED about what the
 * digest must therefore cover. That is a second opinion about the bytes, and a
 * second opinion is exactly what this file exists to eliminate. So the oracle
 * here is not a reading of viem — it is viem:
 *
 *     a field is COMMITTED  <=>  changing its value changes hashTypedData()
 *
 * Nothing else counts. For every shape the wrapper agrees to sign, we perturb
 * every leaf of the message and measure which ones move the digest. Then:
 *
 *   HARD FAILURE  a fact the wrapper POLICED (payee, amount, asset, chain,
 *                 permit2 spender) turns out not to move the digest. That is
 *                 the whole vulnerability class returning: one signature, two
 *                 meanings, one audit row.
 *   RECORD DEFECT metadata.committed names a struct/field the digest does not
 *                 cover, or omits one it does. The ledger outlives the code, so
 *                 a row that cannot be re-checked has to be trusted instead.
 *
 * Plus: the wrapper's digest must equal the digest the SIGNATURE is over —
 * checked by ecrecover, not by inspection.
 */
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { getAddress, hashTypedData, recoverTypedDataAddress } from "viem";
import { AuditLedger, MemoryLedgerStore, MemorySpendLimiter, VadunoGuard } from "@vaduno/guard";
import { createGuardedAccount, GuardSignerRefusedError } from "./guarded-account.mjs";

const CHAIN_ID = 84532;
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const SELLER = getAddress("0x209693Bc6afc0C5328bA36FaF03C514EF312287C");
const SPENDER = getAddress("0x1111111111111111111111111111111111111111");
const real = privateKeyToAccount(generatePrivateKey());
const nonce32 = () => `0x${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex")}`;
const soon = () => BigInt(Math.floor(Date.now() / 1000) + 300);

function rig(opts = {}) {
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const intents = [];
  const g = new VadunoGuard({
    policy: {
      id: "attack9", version: 1, currency: "USDC",
      limits: { perTransactionMinor: 50_000, perDayMinor: 5_000_000 },
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
    intents,
    guarded: createGuardedAccount({
      account: real, guard, agentId: "attack9",
      assets: [{ chainId: CHAIN_ID, address: USDC, symbol: "USDC", decimals: 6 }],
      permit2Spenders: [SPENDER],
      ...opts,
    }),
  };
}
const tag = (e) => (e instanceof GuardSignerRefusedError ? e.code : `${e?.name}: ${String(e?.message).split("\n")[0].slice(0, 70)}`);

// ---------------------------------------------------------------- THE ORACLE
/** Every leaf path in a message object, as arrays of keys. */
function leafPaths(v, base = []) {
  if (v !== null && typeof v === "object") {
    const out = [];
    // own enumerable keys — INCLUDING non-index props on arrays, which
    // structuredClone preserves and which viem's struct branch will read.
    for (const k of Object.keys(v)) out.push(...leafPaths(v[k], [...base, k]));
    return out;
  }
  return [base];
}
const getPath = (o, p) => p.reduce((a, k) => (a == null ? a : a[k]), o);
function setPath(o, p, val) {
  const c = structuredClone(o);
  let cur = c;
  for (const k of p.slice(0, -1)) cur = cur[k];
  cur[p.at(-1)] = val;
  return c;
}
/** A different value of the SAME JS kind, so viem's encoder still accepts it. */
function perturbValue(v) {
  if (typeof v === "bigint") return v + 1n;
  if (typeof v === "number") return v + 1;
  if (typeof v === "boolean") return !v;
  if (typeof v === "string") {
    if (/^0x[0-9a-fA-F]{40}$/.test(v)) {
      return v.toLowerCase() === SELLER.toLowerCase()
        ? "0x00000000000000000000000000000000000000ff"
        : SELLER.toLowerCase();
    }
    if (/^0x[0-9a-fA-F]+$/.test(v)) {
      const last = v.at(-1);
      return v.slice(0, -1) + (last === "0" ? "1" : "0");
    }
    return `${v}-perturbed`;
  }
  return v;
}

/**
 * Which message leaves does the digest actually depend on?
 * Returns { moved: Set<pathString>, still: Set<pathString>, threw: Set }.
 */
function digestDependence(typed) {
  const baseline = hashTypedData(typed);
  const moved = new Set(), still = new Set(), threw = new Set();
  for (const p of leafPaths(typed.message)) {
    const before = getPath(typed.message, p);
    const after = perturbValue(before);
    if (after === before) continue;
    const mutated = { ...typed, message: setPath(typed.message, p, after) };
    let h;
    try { h = hashTypedData(mutated); } catch { threw.add(p.join(".")); continue; }
    (h === baseline ? still : moved).add(p.join("."));
  }
  return { moved, still, threw, baseline };
}

/**
 * Same oracle for the DOMAIN half. `domain.chainId` is the policed network and
 * `domain.verifyingContract` is the policed asset (hence the decimals the
 * amount is scaled by), so a domain field the digest ignores is the same
 * vulnerability as a message field it ignores.
 */
function domainDependence(typed) {
  const baseline = hashTypedData(typed);
  const moved = new Set(), still = new Set();
  for (const k of Object.keys(typed.domain ?? {})) {
    const after = perturbValue(typed.domain[k]);
    if (after === typed.domain[k]) continue;
    let h;
    try { h = hashTypedData({ ...typed, domain: { ...typed.domain, [k]: after } }); } catch { continue; }
    (h === baseline ? still : moved).add(k);
  }
  return { moved, still };
}

// ------------------------------------------------------------------ SHAPES
const eip3009Types = {
  TransferWithAuthorization: [
    { name: "from", type: "address" }, { name: "to", type: "address" },
    { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" },
  ],
};
const eip3009 = (over = {}) => ({
  domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
  types: eip3009Types, primaryType: "TransferWithAuthorization",
  message: { from: real.address, to: SELLER, value: 10_000n, validAfter: 0n, validBefore: soon(), nonce: nonce32() },
  ...over,
});
const P2_BASE = [
  { name: "permitted", type: "TokenPermissions" }, { name: "spender", type: "address" },
  { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" },
];
const TOKEN_PERMISSIONS = [{ name: "token", type: "address" }, { name: "amount", type: "uint256" }];
const permit2 = ({ witnessField, extraTypes = {}, witness }) => ({
  domain: { name: "Permit2", chainId: CHAIN_ID, verifyingContract: USDC },
  types: {
    PermitWitnessTransferFrom: [...P2_BASE, witnessField],
    TokenPermissions: TOKEN_PERMISSIONS,
    ...extraTypes,
  },
  primaryType: "PermitWitnessTransferFrom",
  message: {
    permitted: { token: USDC, amount: 10_000n }, spender: SPENDER,
    nonce: BigInt(`0x${Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("hex")}`),
    deadline: soon(), witness,
  },
});

const CASES = [
  { name: "C1  honest EIP-3009 (control)", typed: eip3009() },
  {
    name: "C2  honest Permit2 (control)",
    typed: permit2({
      witnessField: { name: "witness", type: "Witness" },
      extraTypes: { Witness: [{ name: "to", type: "address" }] },
      witness: { to: SELLER },
    }),
  },
  {
    name: "C3  witness typed `Witness[]`, BOTH `Witness[]` and `Witness` declared",
    // viem's encodeField looks up types["Witness[]"] (full name, struct branch
    // wins). committedFieldSet strips the brackets and looks up types["Witness"].
    typed: (() => {
      const w = [{ unrelated: 7n }];
      w.to = SELLER;
      return permit2({
        witnessField: { name: "witness", type: "Witness[]" },
        extraTypes: { "Witness[]": [{ name: "to", type: "address" }], Witness: [{ name: "unrelated", type: "uint256" }] },
        witness: w,
      });
    })(),
  },
  {
    name: "C4  witness typed `Witness[]`, ONLY `Witness[]` declared",
    typed: (() => {
      const w = [];
      w.to = SELLER;
      return permit2({
        witnessField: { name: "witness", type: "Witness[]" },
        extraTypes: { "Witness[]": [{ name: "to", type: "address" }] },
        witness: w,
      });
    })(),
  },
  {
    name: "C5  nested struct: Witness -> Inner",
    typed: permit2({
      witnessField: { name: "witness", type: "Witness" },
      extraTypes: {
        Witness: [{ name: "to", type: "address" }, { name: "inner", type: "Inner" }],
        Inner: [{ name: "deep", type: "uint256" }],
      },
      witness: { to: SELLER, inner: { deep: 42n } },
    }),
  },
  {
    name: "C6  array OF structs: Witness.legs is Leg[]",
    typed: permit2({
      witnessField: { name: "witness", type: "Witness" },
      extraTypes: {
        Witness: [{ name: "to", type: "address" }, { name: "legs", type: "Leg[]" }],
        Leg: [{ name: "who", type: "address" }],
      },
      witness: { to: SELLER, legs: [{ who: SELLER }, { who: SPENDER }] },
    }),
  },
  {
    name: "C7  dynamic `string` and `bytes` fields in the witness",
    typed: permit2({
      witnessField: { name: "witness", type: "Witness" },
      extraTypes: {
        Witness: [{ name: "to", type: "address" }, { name: "memo", type: "string" }, { name: "blob", type: "bytes" }],
      },
      witness: { to: SELLER, memo: "invoice-1", blob: "0xdeadbeef" },
    }),
  },
  {
    name: "C8  duplicate field name in the witness (`to` twice)",
    typed: permit2({
      witnessField: { name: "witness", type: "Witness" },
      extraTypes: { Witness: [{ name: "to", type: "address" }, { name: "to", type: "address" }] },
      witness: { to: SELLER },
    }),
  },
  {
    name: "C9  witness references an UNDEFINED type",
    typed: permit2({
      witnessField: { name: "witness", type: "Witness" },
      extraTypes: { Witness: [{ name: "to", type: "address" }, { name: "ghost", type: "Undefined" }] },
      witness: { to: SELLER, ghost: { q: 1n } },
    }),
  },
  {
    name: "C10 self-referential type reachable from the witness",
    typed: permit2({
      witnessField: { name: "witness", type: "Witness" },
      extraTypes: { Witness: [{ name: "to", type: "address" }, { name: "self", type: "Witness" }] },
      witness: { to: SELLER, self: { to: SELLER } },
    }),
  },
  {
    name: "C11 witness field name SHADOWS a domain field (`verifyingContract`)",
    typed: permit2({
      witnessField: { name: "witness", type: "Witness" },
      extraTypes: {
        Witness: [{ name: "to", type: "address" }, { name: "verifyingContract", type: "address" }, { name: "chainId", type: "uint256" }],
      },
      witness: { to: SELLER, verifyingContract: SPENDER, chainId: 1n },
    }),
  },
  {
    name: "C12 primaryType absent from `types`",
    typed: { ...eip3009(), types: {}, primaryType: "TransferWithAuthorization" },
  },
  {
    name: "C13 struct literally named `__proto__` in the witness chain",
    typed: permit2({
      witnessField: { name: "witness", type: "Witness" },
      extraTypes: { Witness: [{ name: "to", type: "address" }, { name: "p", type: "__proto__" }], __proto__: [{ name: "z", type: "uint256" }] },
      witness: { to: SELLER, p: { z: 1n } },
    }),
  },
  // ---------------------------------------------------------------- DOMAIN
  {
    name: "C14 EIP712Domain declared EXACTLY (name,version,chainId,verifyingContract)",
    typed: eip3009({
      types: {
        ...eip3009Types,
        EIP712Domain: [
          { name: "name", type: "string" }, { name: "version", type: "string" },
          { name: "chainId", type: "uint256" }, { name: "verifyingContract", type: "address" },
        ],
      },
    }),
  },
  {
    name: "C15 EIP712Domain declared but NARROWED (verifyingContract dropped)",
    typed: eip3009({
      types: {
        ...eip3009Types,
        EIP712Domain: [{ name: "name", type: "string" }, { name: "chainId", type: "uint256" }],
      },
    }),
  },
  {
    name: "C16 EIP712Domain declared but NARROWED (chainId dropped)",
    typed: eip3009({
      types: {
        ...eip3009Types,
        EIP712Domain: [{ name: "name", type: "string" }, { name: "verifyingContract", type: "address" }],
      },
    }),
  },
  {
    name: "C17 domain carries a `salt` (inferred EIP712Domain must cover it)",
    typed: eip3009({
      domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC, salt: `0x${"ab".repeat(32)}` },
    }),
  },
];

// ------------------------------------------------------------------- RUN
const POLICED = {
  // message paths whose value the wrapper turns into a policy fact
  eip3009: ["to", "value", "from", "validBefore", "validAfter", "nonce"],
  permit2: ["witness.to", "permitted.amount", "permitted.token", "spender", "deadline", "nonce"],
};
let hard = 0, record = 0;
const results = [];

for (const c of CASES) {
  const { guarded, intents } = rig();
  let outcome, signature = null;
  try {
    signature = await guarded.signTypedData(c.typed);
    outcome = "SIGNED";
  } catch (e) {
    outcome = tag(e);
  }
  console.log(`\n${c.name}\n  outcome: ${outcome}`);
  if (outcome !== "SIGNED") { results.push({ name: c.name, outcome }); continue; }

  const intent = intents.at(-1);
  const committed = intent?.metadata?.committed;
  const kind = c.typed.primaryType === "TransferWithAuthorization" ? "eip3009" : "permit2";

  // --- 1. does the wrapper's digest equal the digest the SIGNATURE is over?
  let recovered;
  try {
    recovered = await recoverTypedDataAddress({ ...c.typed, signature });
  } catch (e) { recovered = `THREW: ${e.message.split("\n")[0]}`; }
  const digestOk =
    intent.metadata.digest === hashTypedData(c.typed) &&
    String(recovered).toLowerCase() === real.address.toLowerCase();
  console.log(`  digest binds to the signature: ${digestOk} (recovered ${recovered})`);
  if (!digestOk) { hard++; console.log("  >> HARD FAILURE: policy policed a digest the signature is not over"); }

  // --- 2. which message leaves does the digest ACTUALLY depend on?
  const dep = digestDependence(c.typed);
  console.log(`  digest MOVES with: ${[...dep.moved].join(", ") || "(nothing)"}`);
  if (dep.still.size) console.log(`  digest IGNORES:    ${[...dep.still].join(", ")}`);

  // --- 3. HARD: did the wrapper police a fact the digest ignores?
  const dom = domainDependence(c.typed);
  console.log(`  domain MOVES with: ${[...dom.moved].join(", ") || "(nothing)"}${dom.still.size ? ` | IGNORES: ${[...dom.still].join(", ")}` : ""}`);
  const policedButFree = [
    ...POLICED[kind].filter((f) => dep.still.has(f)),
    // chainId and verifyingContract are the policed network and asset
    ...["chainId", "verifyingContract"].filter((f) => dom.still.has(f)).map((f) => `domain.${f}`),
  ];
  if (policedButFree.length) {
    hard++;
    console.log(`  >> HARD FAILURE: policed but NOT committed -> ${policedButFree.join(", ")}`);
  }
  // the recorded domain list must match what the digest actually depends on
  const domClaimed = new Set(committed?.domain ?? []);
  const domUnbacked = [...dom.moved].filter((f) => !domClaimed.has(f));
  const domOverclaimed = [...dom.still].filter((f) => domClaimed.has(f));
  if (domUnbacked.length || domOverclaimed.length) {
    record++;
    console.log(`  >> RECORD DEFECT (domain): claimed=${JSON.stringify([...domClaimed])} unbacked=${domUnbacked} overclaimed=${domOverclaimed}`);
  }

  // --- 4. RECORD: does metadata.committed match what the digest covers?
  const claimedFields = new Set();
  for (const [s, fs] of Object.entries(committed?.struct ?? {})) for (const f of fs) claimedFields.add(`${s}.${f}`);
  const claimedStructs = Object.keys(committed?.struct ?? {});
  const movedLeafNames = new Set([...dep.moved].map((p) => p.split(".").at(-1)));
  const claimedLeafNames = new Set([...claimedFields].map((p) => p.split(".").at(-1)));
  const unbackedStructFields = [...dep.moved].filter((p) => !claimedLeafNames.has(p.split(".").at(-1)));
  console.log(`  metadata.committed.struct = ${JSON.stringify(committed?.struct)}`);
  if (unbackedStructFields.length) {
    record++;
    console.log(`  >> RECORD DEFECT: digest covers ${unbackedStructFields.join(", ")}, absent from the record`);
  }
  results.push({ name: c.name, outcome, digestOk, policedButFree, claimedStructs, unbackedStructFields });
}

console.log(`\n================ SUMMARY ================`);
for (const r of results) console.log(`  ${r.outcome === "SIGNED" ? "signed " : "refused"} ${r.name}  ${r.outcome !== "SIGNED" ? `[${r.outcome}]` : ""}`);
console.log(`\nHARD FAILURES (policed fact not committed / digest not the signed one): ${hard}`);
console.log(`RECORD DEFECTS (metadata.committed disagrees with the digest):          ${record}`);
