/**
 * Paygent Stripe Issuing demo: Paygent's guard is the REAL-TIME AUTHORIZATION
 * BRAIN behind a card. Stripe delivers issuing_authorization.request webhooks;
 * the guard approves/declines each by policy within the 2s window, and every
 * decision is hash-chained. No real Stripe, no keys — the webhook + signature
 * are mocked in-process.
 *
 * Run: npm run demo:stripe
 */
import { AuditLedger, MemoryLedgerStore, PaygentGuard } from "@paygent/guard";
import { createStripeAuthorizationHandler, type StripeEvent } from "@paygent/stripe";

const money = (atomic: number) => `$${(atomic / 100).toFixed(2)}`;

// ── Guard: $20/txn, $50/day, no gambling, only these card categories ────────
const ledger = new AuditLedger(new MemoryLedgerStore());
const guard = new PaygentGuard({
  policy: {
    id: "issuing-demo",
    version: 1,
    currency: "USD",
    limits: { perTransactionMinor: 2_000, perDayMinor: 5_000 },
    categories: { block: ["gambling"] },
  },
  ledger,
});

// ── Mock Stripe: signature "good" verifies; else throw. No crypto. ──────────
const stripe = {
  webhooks: {
    constructEvent(payload: string | Buffer, signature: string): StripeEvent {
      if (signature !== "good") throw new Error("bad signature");
      return JSON.parse(typeof payload === "string" ? payload : payload.toString()) as StripeEvent;
    },
  },
};

const handle = createStripeAuthorizationHandler({
  guard,
  stripe,
  webhookSecret: "whsec_demo",
  apiVersion: "2026-06-24.dahlia",
});

let seq = 0;
function authEvent(o: { amount: number; category?: string; merchant?: string }): StripeEvent {
  seq += 1;
  return {
    id: `evt_${seq}`,
    type: "issuing_authorization.request",
    data: {
      object: {
        id: `iauth_${seq}`,
        amount: 0, // 0 on the request — real amount is in pending_request
        currency: "usd",
        approved: false,
        created: 1_700_000_000 + seq,
        merchant_data: {
          name: o.merchant ?? "Example Merchant",
          category: o.category ?? "computer_software_stores",
          network_id: `net_${o.merchant ?? "x"}`,
          country: "US",
        },
        pending_request: { amount: o.amount, currency: "usd" },
        card: { id: "ic_agent", metadata: { agent_id: "ops-agent-1" } },
      },
    },
  };
}

async function swipe(label: string, o: { amount: number; category?: string; merchant?: string }) {
  const res = await handle(JSON.stringify(authEvent(o)), "good");
  const parsed = JSON.parse(res.body) as { approved: boolean; metadata?: { paygent_reasons?: string } };
  const icon = parsed.approved ? "✅" : "⛔";
  const why = parsed.approved ? "" : ` — ${parsed.metadata?.paygent_reasons}`;
  console.log(`${icon} ${label}: ${money(o.amount)} at ${o.merchant ?? "merchant"} → ${parsed.approved ? "approved" : "declined"}${why}`);
}

console.log("— Paygent × Stripe Issuing: the guard decides each card authorization —\n");

await swipe("SaaS subscription", { amount: 900, merchant: "vercel" });
await swipe("API credits", { amount: 1_500, merchant: "openai" });
await swipe("Over per-txn cap", { amount: 2_500, merchant: "aws" });
await swipe("Casino (blocked category)", { amount: 500, category: "gambling", merchant: "casino" });
await swipe("Small top-up", { amount: 1_400, merchant: "github" });
await swipe("Would blow the daily cap", { amount: 1_900, merchant: "openai" });

// Idempotency: Stripe retries the same authorization — decided once.
console.log("\n— Stripe retries a delivery (idempotent) —\n");
const retry = authEvent({ amount: 800, merchant: "anthropic" });
const a = JSON.parse((await handle(JSON.stringify(retry), "good")).body) as { approved: boolean };
const b = JSON.parse((await handle(JSON.stringify(retry), "good")).body) as { approved: boolean };
console.log(`first: ${a.approved ? "approved" : "declined"} · retry: ${b.approved ? "approved" : "declined"} (same decision, counted once)`);

// Kill switch.
console.log("\n— Kill switch —\n");
await guard.freeze("operator hit the red button");
await swipe("Any charge while frozen", { amount: 100, merchant: "openai" });
await guard.unfreeze();

console.log("\n— Flight recorder —\n");
const head = await ledger.head();
console.log(`ledger entries: ${head.entries}`);
console.log(`chain verification: ${(await ledger.verify(head)).ok ? "✅ intact" : "❌ broken"}`);
