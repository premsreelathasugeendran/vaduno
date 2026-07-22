/**
 * Paygent transparency demo: the guard records every decision in its
 * hash-chained ledger, the transparency log mirrors those entries into an
 * RFC 9162 Merkle tree, and a signed tree head is published. Then we play
 * both sides:
 *   1. a third party VERIFIES that a specific payment decision is committed
 *      under the published head (inclusion proof — proof of non-omission);
 *   2. a witness ACCEPTS honest growth (consistency proof) and CATCHES a
 *      rewritten history.
 *
 * Run: npm run demo:transparency
 */
import {
  AuditLedger,
  MemoryLedgerStore,
  PaygentGuard,
  canonicalJson,
} from "@paygent/guard";
import {
  LedgerMirror,
  MemoryTreeStore,
  TransparencyLog,
  detectSplitView,
  generateLogKeyPair,
  leafHash,
  ledgerEntryLeaf,
  signTreeHead,
  verifyInclusion,
  witnessObserve,
  type WitnessState,
} from "@paygent/transparency";
import { randomUUID } from "node:crypto";

const usd = (amountMinor: number) => ({ amountMinor, currency: "USD" });

// ── Guard + ledger, as in every Paygent setup ────────────────────────────
const ledger = new AuditLedger(new MemoryLedgerStore());
const guard = new PaygentGuard({
  policy: {
    id: "transparency-demo",
    version: 1,
    currency: "USD",
    limits: { perTransactionMinor: 2_000, perDayMinor: 5_000 },
    merchants: { allow: ["openai.com", "anthropic.com"] },
  },
  ledger,
});

// ── The transparency layer ───────────────────────────────────────────────
const keys = generateLogKeyPair();
const signing = { logId: "paygent-demo-log", privateKeyPem: keys.privateKeyPem };
const tree = new TransparencyLog(new MemoryTreeStore());
const mirror = new LedgerMirror(ledger, tree, { signing });

// A witness only needs the log's PUBLIC key and the last head it accepted.
let witness: WitnessState = {
  logId: "paygent-demo-log",
  publicKeyPem: keys.publicKeyPem,
  lastHead: null,
};

async function pay(merchantHost: string, amountMinor: number) {
  const id = randomUUID();
  const result = await guard.execute(
    {
      id,
      agentId: "agent-1",
      amount: usd(amountMinor),
      merchant: { id: merchantHost, url: `https://${merchantHost}/api` },
      rail: "demo",
      description: `demo purchase at ${merchantHost}`,
      requestedAt: new Date().toISOString(),
    },
    async () => ({ ok: true }),
  );
  console.log(`  ${result.status === "executed" ? "✅" : "⛔"} $${(amountMinor / 100).toFixed(2)} at ${merchantHost} → ${result.status}`);
  return id;
}

console.log("― payments through the guard ―");
const paidIntent = await pay("openai.com", 1_200);
await pay("evil-merchant.example", 500); // denied: off allowlist
await pay("anthropic.com", 900);

// ── Publish: mirror ledger → tree, sign the head ─────────────────────────
const { head, signedHead } = await mirror.sync();
console.log(`\n― published signed tree head ―`);
console.log(`  size ${head.treeSize}, root ${head.rootHash.slice(0, 16)}…`);

const w1 = witnessObserve(witness, signedHead!);
if (w1.ok) witness = w1.state;
console.log(`  witness baseline accepted: ${w1.ok}`);

// ── Third-party check: is that DENIED decision really in the history? ────
// The verifier needs only: the entry, its proof, and the published head.
const entries = await ledger.all();
const denialSeq = entries.findIndex(
  (e) => e.type === "policy_decision" && canonicalJson(e.data).includes("deny"),
);
const denialEntry = entries[denialSeq]!;
const proof = await mirror.proveEntry(denialSeq);
const included = verifyInclusion(
  leafHash(ledgerEntryLeaf(denialEntry)), proof, signedHead!.rootHash,
);
console.log(`\n― non-omission proof ―`);
console.log(`  the DENY at seq ${denialSeq} is provably in the published history: ${included}`);

// ── The log grows; the witness verifies append-only-ness ─────────────────
await pay("openai.com", 700);
const sync2 = await mirror.sync();
const growthProof = await tree.proveConsistency(head.treeSize, sync2.head.treeSize);
const w2 = witnessObserve(witness, sync2.signedHead!, growthProof);
if (w2.ok) witness = w2.state;
console.log(`\n― honest growth ―`);
console.log(`  witness accepted ${head.treeSize} → ${sync2.head.treeSize} with consistency proof: ${w2.ok}`);

// ── Now the operator turns evil and rewrites history ─────────────────────
const forgedTree = new TransparencyLog(new MemoryTreeStore());
for (let i = 0; i < sync2.head.treeSize; i++) {
  await forgedTree.appendLeaf(`forged-entry-${i}`); // the deny is "gone"
}
const forgedHead = signTreeHead(await forgedTree.head(), signing);
const caught = witnessObserve(witness, forgedHead);
console.log(`\n― rewrite attempt ―`);
console.log(`  witness verdict: ${caught.ok ? "ACCEPTED (bad!)" : `REJECTED — ${!caught.ok && caught.code}`}`);

// And with two signed heads of the same size, equivocation is attributable:
const split = detectSplitView([sync2.signedHead!, forgedHead], keys.publicKeyPem);
console.log(`  split-view detector: consistent=${split.consistent} (two signed heads, same size, different roots = signed proof of equivocation)`);
