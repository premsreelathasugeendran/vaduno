/**
 * Seed a realistic, hash-chained ledger + a couple of pending approvals so the
 * dashboard shows authentic, verifiable data. Everything here is produced by
 * the real PaygentGuard, so the audit chain verifies.
 *
 * Run: npm run dashboard:seed
 */
import { rm } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import {
  AuditLedger,
  FileApprovalStore,
  JsonlLedgerStore,
  PaygentGuard,
  type PaymentIntent,
} from "@paygent/guard";
import { APPROVALS_PATH, LEDGER_PATH } from "../lib/paths.js";

const MERCHANTS = ["openai", "anthropic", "aws", "github", "vercel"];
const RAILS = ["x402", "stripe-issuing", "mock"];

let clock = Date.parse("2026-07-19T09:00:00.000Z");
const now = () => new Date(clock);
const advance = (ms: number) => (clock += ms);

async function main() {
  await rm(LEDGER_PATH, { force: true });
  await rm(APPROVALS_PATH, { force: true });

  const ledger = new AuditLedger(new JsonlLedgerStore(LEDGER_PATH), now);
  const policy = {
    id: "team-policy",
    version: 3,
    currency: "USD",
    limits: { perTransactionMinor: 5_000, perDayMinor: 30_000 },
    merchants: { allow: MERCHANTS.map((m) => `id:${m}`) },
    approval: { aboveMinor: 3_000 },
  };
  const guard = new PaygentGuard({
    policy,
    ledger,
    approvalHandler: async () => ({ approved: true, approver: "prem" }),
    now,
  });
  // Log the policy so the dashboard can render the real firewall threshold.
  await guard.setPolicy(policy);

  function intent(over: Partial<PaymentIntent>): PaymentIntent {
    return {
      id: randomUUID(),
      agentId: "shopper-agent-1",
      merchant: { id: "openai" },
      amount: { amountMinor: 900, currency: "USD" },
      category: "api-credits",
      rail: "x402",
      requestedAt: now().toISOString(),
      ...over,
    };
  }

  const script: Array<{ merchant: string; amount: number; rail: string; agent?: string; gapMin: number }> = [
    { merchant: "openai", amount: 900, rail: "x402", gapMin: 40 },
    { merchant: "anthropic", amount: 1500, rail: "x402", gapMin: 90 },
    { merchant: "aws", amount: 4200, rail: "stripe-issuing", gapMin: 180 },
    { merchant: "sketchy-store", amount: 800, rail: "mock", gapMin: 30 }, // off-allowlist -> denied
    { merchant: "github", amount: 2500, rail: "stripe-issuing", gapMin: 700 },
    { merchant: "vercel", amount: 2000, rail: "stripe-issuing", agent: "ops-agent", gapMin: 300 },
    { merchant: "openai", amount: 6500, rail: "x402", gapMin: 60 }, // over per-txn -> denied
    { merchant: "openai", amount: 1200, rail: "x402", gapMin: 120 },
    { merchant: "anthropic", amount: 3400, rail: "x402", gapMin: 800 },
    { merchant: "aws", amount: 3900, rail: "stripe-issuing", agent: "ops-agent", gapMin: 240 },
    { merchant: "github", amount: 1100, rail: "stripe-issuing", gapMin: 90 },
    { merchant: "vercel", amount: 800, rail: "mock", gapMin: 300 },
    { merchant: "openai", amount: 2100, rail: "x402", gapMin: 150 },
  ];

  let executed = 0;
  let denied = 0;
  for (const step of script) {
    advance(step.gapMin * 60_000);
    const result = await guard.execute(
      intent({
        merchant: { id: step.merchant },
        amount: { amountMinor: step.amount, currency: "USD" },
        rail: step.rail,
        ...(step.agent ? { agentId: step.agent } : {}),
      }),
      async () => ({ receipt: randomUUID().slice(0, 8) }),
    );
    if (result.status === "executed") executed++;
    else denied++;
  }

  // Two agents currently waiting on a human decision (> $30 approval threshold).
  const approvals = new FileApprovalStore(APPROVALS_PATH, now);
  advance(30 * 60_000);
  await approvals.enqueue({
    intentId: randomUUID(),
    agentId: "ops-agent",
    amount: { amountMinor: 4200, currency: "USD" },
    merchant: { id: "aws", url: "https://aws.amazon.com" },
    policyReasons: [{ code: "APPROVAL_THRESHOLD", message: "amount 4200 >= approval threshold 3000" }],
    requestedAt: now().toISOString(),
  });
  advance(5 * 60_000);
  await approvals.enqueue({
    intentId: randomUUID(),
    agentId: "shopper-agent-1",
    amount: { amountMinor: 3800, currency: "USD" },
    merchant: { id: "anthropic", url: "https://api.anthropic.com" },
    policyReasons: [{ code: "APPROVAL_THRESHOLD", message: "amount 3800 >= approval threshold 3000" }],
    requestedAt: now().toISOString(),
  });

  const verdict = await ledger.verify();
  console.log(`Seeded ${LEDGER_PATH}`);
  console.log(`  executed: ${executed}, denied: ${denied}, ledger entries: ${verdict.entries}`);
  console.log(`  chain verification: ${verdict.ok ? "OK" : "BROKEN"}`);
  console.log(`Seeded ${APPROVALS_PATH} with 2 pending approvals`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
