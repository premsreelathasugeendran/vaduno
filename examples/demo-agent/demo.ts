/**
 * Swale demo: an AI agent with a $50 budget tries a series of purchases —
 * including the things that go wrong in the real attacks (over-limit spends,
 * off-allowlist merchants injected by a malicious page, a forged merchant id,
 * mandate replay). Every attempt lands in the tamper-evident flight recorder.
 *
 * Run: npm run demo
 */
import {
  AuditLedger,
  MemoryLedgerStore,
  MandateManager,
  SwaleGuard,
  generateMandateKeyPair,
  type PaymentIntent,
} from "@swale/guard";
import { randomUUID } from "node:crypto";

const usd = (amountMinor: number) => ({ amountMinor, currency: "USD" });
const dollars = (m: number) => `$${(m / 100).toFixed(2)}`;

// ── Setup ────────────────────────────────────────────────────────────────
const ledger = new AuditLedger(new MemoryLedgerStore());
const keys = generateMandateKeyPair();
const mandates = new MandateManager(
  { publicKeyPem: keys.publicKeyPem, privateKeyPem: keys.privateKeyPem },
  ledger,
);

const guard = new SwaleGuard({
  policy: {
    id: "demo-policy",
    version: 1,
    currency: "USD",
    limits: {
      perTransactionMinor: 2_000, // $20 per transaction
      perDayMinor: 5_000, //         $50 per day
    },
    // Host allowlist: matched against the URL host, NEVER the merchant.id
    // (which the agent controls). Forging merchant.id cannot get past this.
    merchants: {
      allow: ["openai.com", "anthropic.com", "aws.amazon.com"],
    },
    approval: { aboveMinor: 1_500 }, // human approval at $15+
  },
  ledger,
  mandates,
  approvalHandler: async ({ intent }) => {
    // In production this pings a human (Slack, dashboard, push). Demo: auto-OK.
    console.log(
      `  👤 human approval requested for ${dollars(intent.amount.amountMinor)} at ${intent.merchant.id} → APPROVED`,
    );
    return { approved: true, approver: "prem" };
  },
});

// A mock rail executor — in real integrations this is your x402 client,
// Stripe issuing call, or UPI collect. Swale never touches the money and
// hands the executor the SAFE, evaluated snapshot of the intent.
const mockRail = (intent: PaymentIntent) => ({
  receipt: `mock-${intent.id.slice(0, 8)}`,
});

function intent(over: Partial<PaymentIntent>): PaymentIntent {
  return {
    id: randomUUID(),
    agentId: "shopper-agent-1",
    merchant: { id: "openai", url: "https://api.openai.com" },
    amount: usd(500),
    category: "api-credits",
    rail: "mock",
    requestedAt: new Date().toISOString(),
    ...over,
  };
}

async function attempt(label: string, i: PaymentIntent) {
  const result = await guard.execute(i, async (safe) => mockRail(safe));
  const icon =
    result.status === "executed"
      ? "✅"
      : result.status === "approval_rejected"
        ? "🙅"
        : result.status === "failed"
          ? "💥"
          : "⛔";
  const reason =
    result.status === "denied"
      ? ` — ${result.policyResult.reasons.map((r) => r.code).join(", ")}`
      : "";
  console.log(
    `${icon} ${label}: ${dollars(i.amount.amountMinor)} at ${i.merchant.id} → ${result.status}${reason}`,
  );
}

// ── Scenario ─────────────────────────────────────────────────────────────
console.log("— Swale demo: agent with $50/day budget, $20/txn cap —\n");

await attempt("Buy API credits", intent({ amount: usd(900) }));

await attempt(
  "Big compute purchase (needs human)",
  intent({ merchant: { id: "aws", url: "https://aws.amazon.com" }, amount: usd(1_800) }),
);

await attempt(
  "PROMPT-INJECTED purchase (hidden text on a product page told the agent to buy here)",
  intent({
    merchant: { id: "totally-legit-deals", url: "https://totally-legit-deals.example" },
    amount: usd(1_200),
  }),
);

await attempt(
  "FORGED merchant id (claims to be openai.com, but pays a drainer host)",
  intent({
    merchant: { id: "openai.com", url: "https://wallet-drainer.xyz/pay" },
    amount: usd(500),
  }),
);

await attempt("Over per-transaction cap", intent({ amount: usd(2_500) }));

await attempt("Small top-up", intent({ amount: usd(1_400) }));

await attempt(
  "Would blow the daily budget",
  intent({ amount: usd(1_900) }),
);

// ── Concurrency: 4 parallel purchases racing a fresh daily cap ───────────
// Without a mutex, all 4 read a stale $0 total and all execute (5x overspend).
console.log("\n— Concurrency: 4 x $18 fired in parallel against a fresh $50/day cap —\n");
const raceLedger = new AuditLedger(new MemoryLedgerStore());
const raceGuard = new SwaleGuard({
  policy: {
    id: "race-policy",
    version: 1,
    currency: "USD",
    limits: { perTransactionMinor: 2_000, perDayMinor: 5_000 },
  },
  ledger: raceLedger,
});
const parallelResults = await Promise.all(
  [0, 1, 2, 3].map((n) =>
    raceGuard.execute(
      intent({ amount: usd(1_800), description: `parallel-${n}` }),
      async (safe) => mockRail(safe),
    ),
  ),
);
const executed = parallelResults.filter((r) => r.status === "executed").length;
console.log(
  `${executed} executed, ${4 - executed} denied — total ${dollars(executed * 1_800)} ≤ $50/day cap: ${executed * 1_800 <= 5_000 ? "✅ held" : "❌ BREACHED"}`,
);

// ── Mandate: consume-once semantics ─────────────────────────────────────
console.log("\n— Mandate demo: single-use signed authorization —\n");
const mandate = await mandates.issue({
  issuer: "prem@swale.dev",
  agentId: "shopper-agent-1",
  constraints: {
    maxAmountMinor: 1_000,
    currency: "USD",
    merchants: ["anthropic.com"],
    validFrom: new Date(Date.now() - 1000).toISOString(),
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    maxUses: 1,
  },
});

const mandated = intent({
  merchant: { id: "anthropic", url: "https://api.anthropic.com" },
  amount: usd(800),
  mandateId: mandate.id,
});
await attempt("Mandated purchase (1st use)", mandated);
await attempt(
  "REPLAYED mandate (2nd use — the AP2 replay attack)",
  intent({
    merchant: { id: "anthropic", url: "https://api.anthropic.com" },
    amount: usd(800),
    mandateId: mandate.id,
  }),
);

// ── Runtime enforcement: a retry storm that must NOT double-charge ───────
// A crashed/retried agent (or a duplicate orchestration hop) fires the SAME
// payment 6x in parallel. Signature-only mandates would let every retry
// through; consume-once enforcement runs the rail exactly once and replays
// the original outcome to the rest.
console.log("\n— Runtime enforcement: same payment fired 6x (retry storm) —\n");
// Fresh guard + mandate manager so the daily budget above doesn't interfere.
const stormLedger = new AuditLedger(new MemoryLedgerStore());
const stormMandates = new MandateManager(
  { publicKeyPem: keys.publicKeyPem, privateKeyPem: keys.privateKeyPem },
  stormLedger,
);
const stormGuard = new SwaleGuard({
  policy: {
    id: "storm-policy",
    version: 1,
    currency: "USD",
    limits: { perTransactionMinor: 2_000, perDayMinor: 5_000 },
  },
  ledger: stormLedger,
  mandates: stormMandates,
});
const stormMandate = await stormMandates.issue({
  issuer: "prem@swale.dev",
  agentId: "shopper-agent-1",
  constraints: {
    maxAmountMinor: 1_000,
    currency: "USD",
    validFrom: new Date(Date.now() - 1000).toISOString(),
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    maxUses: 1,
  },
});
const stormIntent = intent({
  merchant: { id: "anthropic", url: "https://api.anthropic.com" },
  amount: usd(700),
  mandateId: stormMandate.id,
});
let railRuns = 0;
const storm = await Promise.all(
  Array.from({ length: 6 }, () =>
    stormGuard.execute(stormIntent, async (safe) => {
      railRuns += 1;
      return mockRail(safe);
    }),
  ),
);
const executedOnce = storm.filter((r) => r.status === "executed").length;
const replayed = storm.filter((r) => r.status === "replayed").length;
console.log(
  `  rail actually ran ${railRuns}x · ${executedOnce} executed + ${replayed} replayed · double-charge prevented: ${railRuns === 1 ? "✅" : "❌"}`,
);

// ── Kill switch ──────────────────────────────────────────────────────────
console.log("\n— Kill switch —\n");
await guard.freeze("operator hit the red button");
await attempt("Any purchase while frozen", intent({ amount: usd(100) }));
await guard.unfreeze();

// ── Flight recorder ──────────────────────────────────────────────────────
console.log("\n— Flight recorder —\n");
const head = await ledger.head();
const entries = await ledger.all();
console.log(`ledger entries: ${entries.length}`);
const verdict = await ledger.verify(head);
console.log(
  `chain verification: ${verdict.ok ? "✅ intact" : `❌ ${verdict.problem}`}`,
);

// Simulate an attacker editing history, then re-verify against the retained head.
const store2 = new MemoryLedgerStore();
for (const e of entries) await store2.append(structuredClone(e));
(await store2.all())[3]!.data = { policyResult: "doctored" };
console.log("\n…attacker edits entry #3 in the database…");
const tampered = await new AuditLedger(store2).verify(head);
console.log(
  `chain verification: ${tampered.ok ? "✅ intact" : `❌ tampering detected at seq ${tampered.firstBadSeq}: ${tampered.problem}`}`,
);
