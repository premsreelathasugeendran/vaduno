/**
 * Vaduno transparency demo: the guard records every decision in its
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
  VadunoGuard,
  canonicalJson,
} from "@vaduno/guard";
import {
  LedgerMirror,
  MemoryTreeStore,
  TransparencyLog,
  attachCosignatures,
  checkCosignatureQuorum,
  detectSplitView,
  generateLogKeyPair,
  leafHash,
  ledgerEntryLeaf,
  signCheckpoint,
  signTreeHead,
  verifyInclusion,
  verifyNoteSignature,
  witnessCosign,
  witnessObserve,
  type WitnessState,
} from "@vaduno/transparency";
import { randomUUID } from "node:crypto";

const usd = (amountMinor: number) => ({ amountMinor, currency: "USD" });

// ── Guard + ledger, as in every Vaduno setup ────────────────────────────
const ledger = new AuditLedger(new MemoryLedgerStore());
const guard = new VadunoGuard({
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
const signing = { logId: "vaduno-demo-log", privateKeyPem: keys.privateKeyPem };
const tree = new TransparencyLog(new MemoryTreeStore());
const mirror = new LedgerMirror(ledger, tree, { signing });

// A witness only needs the log's PUBLIC key and the last head it accepted.
let witness: WitnessState = {
  logId: "vaduno-demo-log",
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

// ── Witness cosigning: the defence against a SPLIT VIEW ──────────────────
// Everything above catches an operator who rewrites history for ONE viewer.
// It does NOT catch an operator who signs two histories and shows a different
// one to each party — every signature verifies, every proof passes. That is
// what independent witness cosignatures fix.
console.log(`\n― witness cosigning (C2SP tlog-cosignature v1) ―`);

const ORIGIN = "vaduno.example/ledger";
const finalHead = await tree.head();
const checkpoint = signCheckpoint(
  { origin: ORIGIN, treeSize: finalHead.treeSize, rootHash: finalHead.rootHash },
  { name: ORIGIN, privateKeyPem: keys.privateKeyPem, publicKeyPem: keys.publicKeyPem },
);
console.log("  interop checkpoint (the format Sigsum/Go-sumdb witnesses speak):");
for (const line of checkpoint.trimEnd().split("\n")) console.log(`    ${line || "(blank)"}`);

// Three INDEPENDENT witnesses (in production these are other people's servers;
// witnesses you run yourself add exactly zero assurance).
const witnessKeys = [generateLogKeyPair(), generateLogKeyPair(), generateLogKeyPair()];
const witnessNames = ["witness.a.example", "witness.b.example", "witness.c.example"];
let witnessStates = witnessNames.map(() => ({
  origin: ORIGIN,
  logPublicKeyPem: keys.publicKeyPem,
  logKeyName: ORIGIN,
  lastCosigned: null as { treeSize: number; rootHash: string; bodyHash: string } | null,
}));

const cosignatures = [];
for (let i = 0; i < witnessNames.length; i++) {
  const r = witnessCosign(witnessStates[i]!, checkpoint, {
    name: witnessNames[i]!,
    privateKeyPem: witnessKeys[i]!.privateKeyPem,
    publicKeyPem: witnessKeys[i]!.publicKeyPem,
  });
  if (r.ok) {
    cosignatures.push(r.cosignature);
    witnessStates[i] = r.state;
  }
}
const witnessed = attachCosignatures(checkpoint, cosignatures);
const knownWitnesses = witnessNames.map((name, i) => ({
  name,
  publicKeyPem: witnessKeys[i]!.publicKeyPem,
}));
const binding = { origin: ORIGIN, logPublicKeyPem: keys.publicKeyPem };
const quorum = checkCosignatureQuorum(witnessed, knownWitnesses, 2, binding);
console.log(`  ${cosignatures.length} witnesses cosigned → 2-of-3 quorum: ${quorum.ok ? "✅" : "❌"} (${quorum.message})`);

// ── The split-view attack, defeated ──────────────────────────────────────
// The operator builds a SECOND history at the same size and signs it validly,
// intending to show it to a different counterparty.
const forkTree = new TransparencyLog(new MemoryTreeStore());
for (let i = 0; i < finalHead.treeSize; i++) await forkTree.appendLeaf(`fork-${i}`);
const forkHead = await forkTree.head();
const forkCheckpoint = signCheckpoint(
  { origin: ORIGIN, treeSize: forkHead.treeSize, rootHash: forkHead.rootHash },
  { name: ORIGIN, privateKeyPem: keys.privateKeyPem, publicKeyPem: keys.publicKeyPem },
);
console.log(`\n  operator forks: a second, validly-signed history at the same size`);
console.log(`    log signature on the fork verifies: ${verifyNoteSignature(forkCheckpoint, { name: ORIGIN, publicKeyPem: keys.publicKeyPem })}  ← the log's own crypto cannot catch this`);

const forkCosignatures = witnessStates
  .map((s, i) =>
    witnessCosign(s, forkCheckpoint, {
      name: witnessNames[i]!,
      privateKeyPem: witnessKeys[i]!.privateKeyPem,
      publicKeyPem: witnessKeys[i]!.publicKeyPem,
    }),
  )
  .filter((r) => r.ok);
console.log(`    witnesses willing to cosign the fork: ${forkCosignatures.length}/3`);

const forkQuorum = checkCosignatureQuorum(forkCheckpoint, knownWitnesses, 2, binding);
console.log(`    fork reaches 2-of-3 quorum: ${forkQuorum.ok ? "❌ BAD" : "✅ no"} — ${forkQuorum.message}`);
console.log(
  `\n  A relying party that requires a 2-of-3 witness quorum accepts the real`,
);
console.log(`  history and rejects the fork — non-equivocation, not just tamper-evidence.`);
console.log(
  `\n  Honest limit: this proves everyone sees the SAME log. It does NOT prove the`,
);
console.log(`  log is COMPLETE, and witnesses you run yourself count for nothing.`);
