/**
 * Swale revocation demo — the kill switch, honestly scoped.
 *
 *   npm run demo:revocation
 *
 * Shows: instant local revocation, an agent-wide kill, the race that matters
 * (revoking while a human approval is pending), fail-closed behaviour when the
 * registry is unreachable, a publishable W3C status list a third party can
 * verify, and a rail fan-out failure that is recorded rather than hidden.
 */
import {
  AuditLedger,
  MandateManager,
  MemoryLedgerStore,
  SwaleGuard,
  generateMandateKeyPair,
  type PaymentIntent,
  type SpendPolicy,
} from "@swale/guard";
import {
  Bitstring,
  MemoryRevocationStore,
  RevocationRegistry,
  checkStatus,
  createRegistryCheck,
  type FanOutTarget,
} from "@swale/revocation";
import { randomUUID } from "node:crypto";

const keys = generateMandateKeyPair();
const ledger = new AuditLedger(new MemoryLedgerStore());
const store = new MemoryRevocationStore();
const mandates = new MandateManager(keys, ledger);

// Two rails: one healthy, one down — to show honest fan-out reporting.
const fanOut: FanOutTarget[] = [
  { rail: "stripe-issuing", revoke: async () => {} },
  {
    rail: "x402-wallet",
    revoke: async () => {
      throw new Error("wallet service returned 503");
    },
  },
];

const registry = new RevocationRegistry({
  issuer: "prem@swale.dev",
  listId: "https://swale.example/status/1",
  privateKeyPem: keys.privateKeyPem,
  store,
  ledger,
  fanOut,
});

const policy: SpendPolicy = {
  id: "demo-policy",
  version: 1,
  currency: "USD",
  limits: { perTransactionMinor: 5_000, perDayMinor: 100_000 },
};

const guard = new SwaleGuard({
  policy,
  ledger,
  mandates,
  revocationCheck: createRegistryCheck(registry),
});

function usd(minor: number): string {
  return `$${(minor / 100).toFixed(2)}`;
}

function intent(over: Partial<PaymentIntent> = {}): PaymentIntent {
  return {
    id: randomUUID(),
    agentId: "shopper-agent-1",
    merchant: { id: "openai", url: "https://api.openai.com" },
    amount: { amountMinor: 900, currency: "USD" },
    rail: "mock",
    requestedAt: new Date().toISOString(),
    ...over,
  };
}

async function issueMandate(agentId = "shopper-agent-1") {
  const mandate = await mandates.issue({
    issuer: "prem@swale.dev",
    agentId,
    constraints: {
      maxAmountMinor: 5_000,
      currency: "USD",
      validFrom: new Date(Date.now() - 1000).toISOString(),
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      maxUses: 20,
    },
  });
  // Assign the status-list bit AND link the mandate to its agent, so an
  // agent-wide kill can find it later.
  await registry.assignIndex(mandate.id, agentId);
  return mandate;
}

async function attempt(label: string, i: PaymentIntent): Promise<void> {
  const result = await guard.execute(i, async () => ({ receipt: "ok" }));
  const icon = result.status === "executed" ? "✅" : "⛔";
  const reason =
    result.status === "denied"
      ? ` — ${result.policyResult.reasons.map((r) => r.code).join(", ")}`
      : "";
  console.log(`${icon} ${label}: ${usd(i.amount.amountMinor)} → ${result.status}${reason}`);
}

console.log("— Swale revocation registry demo —\n");

// ── 1. Normal operation, then revoke ─────────────────────────────────────
console.log("— Revoking one mandate —\n");
const m1 = await issueMandate();
await attempt("Purchase before revocation", intent({ mandateId: m1.id }));

const revoked = await registry.revokeMandate(m1.id, {
  reason: "agent showed anomalous behaviour",
  by: "prem",
});
console.log(`  revoked locally: ${revoked.effectiveLocally} (effective immediately)`);
// Rail fan-out runs OFF the kill path under a deadline — awaiting it is
// optional, the revocation is already in force.
for (const f of await revoked.fanOut) {
  console.log(`  fan-out → ${f.rail}: ${f.ok ? "✅ acknowledged" : `❌ ${f.error} (recorded, NOT hidden)`}`);
}
await attempt("Purchase after revocation", intent({ mandateId: m1.id }));

// ── 2. The race: revoke while a human approval is pending ────────────────
console.log("\n— The race: kill switch pulled while a human approval is pending —\n");
const raceLedger = new AuditLedger(new MemoryLedgerStore());
const raceMandates = new MandateManager(keys, raceLedger);
const m2 = await (async () => {
  const mandate = await raceMandates.issue({
    issuer: "prem@swale.dev",
    agentId: "shopper-agent-1",
    constraints: {
      maxAmountMinor: 5_000,
      currency: "USD",
      validFrom: new Date(Date.now() - 1000).toISOString(),
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      maxUses: 5,
    },
  });
  await registry.assignIndex(mandate.id, "shopper-agent-1");
  return mandate;
})();

let release: (() => void) | undefined;
const humanThinking = new Promise<void>((r) => {
  release = r;
});
const raceGuard = new SwaleGuard({
  policy: { ...policy, approval: { always: true } },
  ledger: raceLedger,
  mandates: raceMandates,
  revocationCheck: createRegistryCheck(registry),
  approvalHandler: async () => {
    await humanThinking;
    return { approved: true, approver: "prem" };
  },
});

let railRan = false;
const pending = raceGuard.execute(intent({ mandateId: m2.id }), async () => {
  railRan = true;
  return { receipt: "should never happen" };
});
console.log("  human is deciding…  operator pulls the kill switch…");
await registry.revokeMandate(m2.id, { reason: "kill switch mid-approval" });
release!();
const raceResult = await pending;
console.log(
  `  human APPROVED, but result = ${raceResult.status}; rail ran: ${railRan} → kill switch wins: ${!railRan ? "✅" : "❌"}`,
);

// ── 3. Agent-wide kill ───────────────────────────────────────────────────
console.log("\n— Agent-wide kill (every mandate + future ones) —\n");
const m3 = await issueMandate("rogue-agent");
await attempt("rogue-agent buys something", intent({ agentId: "rogue-agent", mandateId: m3.id }));
const killed = await registry.revokeAgent("rogue-agent", { reason: "credentials leaked", by: "prem" });
console.log(`  revoked ${killed.length} mandate(s) + blocked the agent id`);
await attempt("rogue-agent tries again", intent({ agentId: "rogue-agent", mandateId: m3.id }));
const m4 = await issueMandate("rogue-agent");
await attempt("rogue-agent with a BRAND NEW mandate", intent({ agentId: "rogue-agent", mandateId: m4.id }));

// ── 4. Fail closed when the registry is unreachable ──────────────────────
console.log("\n— Registry outage must NOT read as 'not revoked' —\n");
const outageLedger = new AuditLedger(new MemoryLedgerStore());
const outageGuard = new SwaleGuard({
  policy,
  ledger: outageLedger,
  revocationCheck: async () => {
    throw new Error("registry unreachable");
  },
});
const outage = await outageGuard.execute(intent(), async () => ({ receipt: "ok" }));
console.log(
  `  result: ${outage.status}${outage.status === "denied" ? ` — ${outage.policyResult.reasons.map((r) => r.code).join(", ")}` : ""} → fail closed: ${outage.status === "denied" ? "✅" : "❌"}`,
);

// ── 4b. A HANGING rail must not wedge the kill path ──────────────────────
console.log("\n— A rail that hangs (not just fails) must not delay the kill —\n");
const hungLedger = new AuditLedger(new MemoryLedgerStore());
const hungRegistry = new RevocationRegistry({
  issuer: "prem@swale.dev",
  listId: "https://swale.example/status/2",
  privateKeyPem: keys.privateKeyPem,
  store: new MemoryRevocationStore(),
  ledger: hungLedger,
  // This rail accepts the call and NEVER answers — the ordinary failure mode
  // of an HTTP client with no timeout.
  fanOut: [{ rail: "blackhole-rail", revoke: () => new Promise<void>(() => {}) }],
  fanOutTimeoutMs: 500,
});
await hungRegistry.assignIndex("mandate-A", "agent-z");
await hungRegistry.assignIndex("mandate-B", "agent-z");
const t0 = Date.now();
await hungRegistry.revokeMandate("mandate-A");
const killAll = await hungRegistry.revokeAgent("agent-z", { reason: "compromised" });
const elapsed = Date.now() - t0;
console.log(`  two kills completed in ${elapsed}ms despite an unresponsive rail`);
console.log(
  `  agent blocked: ${await hungRegistry.isAgentBlocked("agent-z")}, mandate-B revoked: ${(await hungRegistry.isRevoked("mandate-B")) !== null} → kill path never wedged: ${elapsed < 400 ? "✅" : "❌"}`,
);
const hungResults = await killAll.find((r) => r.record.mandateId === "mandate-B")!.fanOut;
console.log(`  the hung rail is reported honestly: ${hungResults[0]!.error}`);

// ── 5. Publishable status list a third party can verify ──────────────────
console.log("\n— Published W3C Bitstring Status List (third-party verifiable) —\n");
const credential = await registry.publish(1);
const snap = await registry.snapshot();
console.log(`  list ${credential.id} v${credential.version}`);
console.log(`  ${credential.entries.toLocaleString()} entries, encoded size ${credential.encodedList.length} chars`);
console.log(`  revoked: ${snap.records.length}, valid until ${credential.validUntil}`);

const idxRevoked = (await store.indexOf(m1.id))!;
const active = await issueMandate();
const idxActive = (await store.indexOf(active.id))!;
const verifiedRevoked = checkStatus(credential, idxRevoked, { publicKeyPem: keys.publicKeyPem });
const verifiedActive = checkStatus(credential, idxActive, { publicKeyPem: keys.publicKeyPem });
console.log(
  `  verifier reads index ${idxRevoked} (revoked mandate): revoked=${verifiedRevoked.revoked} valid=${verifiedRevoked.valid}`,
);
console.log(
  `  verifier reads index ${idxActive} (active mandate):  revoked=${verifiedActive.revoked} valid=${verifiedActive.valid}`,
);

// Real tampering: an attacker clears every bit (un-revoking everyone) but
// cannot re-sign, because the issuer's private key is not theirs.
const cleanList = new Bitstring(credential.entries).encode();
const forged = { ...credential, encodedList: cleanList };
const tampered = checkStatus(forged, idxRevoked, { publicKeyPem: keys.publicKeyPem });
console.log(
  `  …attacker swaps in an all-clear bitstring to un-revoke everyone…\n  verifier says: ${tampered.code} (valid=${tampered.valid}) → forgery rejected: ${tampered.code === "SIGNATURE_INVALID" ? "✅" : "❌"}`,
);

// A stale list is "unknown", never "clean".
const expired = checkStatus(credential, idxActive, {
  publicKeyPem: keys.publicKeyPem,
  now: () => new Date(Date.parse(credential.validUntil) + 1000),
});
console.log(
  `  …list goes stale…  verifier says: ${expired.code} (valid=${expired.valid}) → treated as unavailable, not "not revoked": ${!expired.valid ? "✅" : "❌"}`,
);

// ── 6. Audit trail ───────────────────────────────────────────────────────
console.log("\n— Audit trail —\n");
const entries = await ledger.all();
const counts = new Map<string, number>();
for (const e of entries) counts.set(e.type, (counts.get(e.type) ?? 0) + 1);
for (const type of ["mandate_revoked", "agent_revoked", "revocation_fanout", "status_list_published"]) {
  console.log(`  ${type}: ${counts.get(type) ?? 0}`);
}
const verdict = await ledger.verify();
console.log(`  chain verification: ${verdict.ok ? "✅ intact" : `❌ ${verdict.problem}`} (${verdict.entries} entries)`);

console.log(
  "\nScope note: revocation is INSTANT and GUARANTEED for mandates Swale mediates.",
);
console.log(
  "For authority it does not mediate (a raw wallet key), fan-out is BEST-EFFORT — and",
);
console.log("every failure is recorded, never assumed away.");
