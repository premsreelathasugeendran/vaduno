# Paygent

**A spend firewall and flight recorder for AI agents.**

Your agent has an API key that can spend real money. Research says the agent *will* eventually be tricked — prompt-injection attacks against commerce agents succeed in [86% of attempts](https://arxiv.org/abs/2504.18575), and agents have bought from fake storefronts without hesitation. The model cannot be the last line of defense.

Paygent puts a deterministic guard between your agent and the money:

- **Policy engine** — per-transaction / daily / weekly / monthly caps, merchant & category allowlists, rail restrictions, velocity limits, human-approval thresholds. Pure code; no model in the loop.
- **Signed mandates** — Ed25519 "permission slips" binding what the human authorized (amount, merchant, time window) to what executes. Time-bound and **consume-once atomic**, closing the [mandate-replay attacks](https://arxiv.org/abs/2602.06345) published against agent-payment protocols.
- **Flight recorder** — every attempt, decision, approval, and execution lands in a hash-chained, append-only audit ledger. Any edit, deletion, or reordering of history is detectable by `verify()`.
- **Kill switch** — `guard.freeze()` denies everything instantly, and the freeze itself is audited.

**Paygent never holds funds, keys, or the ability to move money.** It decides whether *your* executor function may run, and records everything. Rail-agnostic by design: wrap an x402 client, a Stripe issuing call, a UPI collect — anything.

## Install

```bash
npm install @paygent/guard
```

Zero runtime dependencies. Node ≥ 18.

## 60-second example

```ts
import {
  PaygentGuard, AuditLedger, MemoryLedgerStore,
} from "@paygent/guard";

const ledger = new AuditLedger(new MemoryLedgerStore());

const guard = new PaygentGuard({
  policy: {
    id: "shopper-policy", version: 1, currency: "USD",
    limits: { perTransactionMinor: 2_000, perDayMinor: 5_000 }, // $20/txn, $50/day
    merchants: { allow: ["openai", "anthropic", "aws"] },
    approval: { aboveMinor: 1_500 },                            // human sign-off at $15+
  },
  ledger,
  approvalHandler: async ({ intent }) => askHumanSomehow(intent),
});

const result = await guard.execute(
  {
    id: crypto.randomUUID(),
    agentId: "shopper-agent-1",
    merchant: { id: "openai", url: "https://api.openai.com" },
    amount: { amountMinor: 900, currency: "USD" },              // $9.00 (always integer minor units)
    category: "api-credits",
    rail: "x402",
    requestedAt: new Date().toISOString(),
  },
  () => myX402Client.pay(...),   // your executor — Paygent never touches the money
);

// result.status: "executed" | "denied" | "approval_rejected" | "failed"

const audit = await ledger.verify();  // { ok: true, entries: n } — or exactly where history was tampered
```

What the guard blocks, from the demo (`npm run demo`):

```
✅ Buy API credits: $9.00 at openai → executed
✅ Big compute purchase (needs human): $18.00 at aws → executed (approved)
⛔ PROMPT-INJECTED purchase: $12.00 at totally-legit-deals → denied — MERCHANT_NOT_ALLOWED
⛔ Over per-transaction cap: $25.00 → denied — PER_TXN_LIMIT_EXCEEDED
⛔ Would blow the daily budget: $19.00 → denied — PER_DAY_LIMIT_EXCEEDED
⛔ REPLAYED single-use mandate → denied — MANDATE_USES_EXHAUSTED
❌ tampering detected at seq 3 (ledger verification)
```

## Mandates: provable authorization

```ts
import { MandateManager, generateMandateKeyPair } from "@paygent/guard";

const keys = generateMandateKeyPair();          // issuer keeps the private key
const mandates = new MandateManager(
  { publicKeyPem: keys.publicKeyPem, privateKeyPem: keys.privateKeyPem },
  ledger,
);

const mandate = await mandates.issue({
  issuer: "you@company.com",
  agentId: "shopper-agent-1",
  constraints: {
    maxAmountMinor: 1_000, currency: "USD",
    merchants: ["anthropic"],
    validFrom: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    maxUses: 1,                                  // consume-once
  },
});
```

Attach `mandateId` to an intent (set `requireMandate: true` to demand it for every payment). Validation is checked pre-flight and **consumed atomically right before execution** — two concurrent uses of a single-use mandate cannot both succeed. The signed mandate + the hash-chained trail together answer the dispute question no current agent-payment spec answers: *prove what the human authorized and what actually happened.*

A validating agent process needs only the **public** key. Never put the private key in an LLM's context.

## Ledger stores

| Store | Use |
|---|---|
| `MemoryLedgerStore` | tests, ephemeral agents |
| `JsonlLedgerStore("ledger.jsonl")` | local flight-recorder file |
| `SupabaseLedgerStore(client)` | shared/team ledger — schema in [supabase/schema.sql](supabase/schema.sql), RLS keeps it append-only server-side |

The chain is computed client-side; `verify()` re-derives every hash, so even a compromised database cannot silently rewrite history.

## Design principles

1. **Fail closed.** No approval handler? Approval-needing intents are denied. Internal error? Denied and audited. Unknown mandate? Denied.
2. **Deterministic last line.** An attacker is assumed to fully control the agent and every field of the intent. Policy checks are pure code over integer minor units.
3. **Amounts are integers.** Minor units (cents, paise) everywhere. Floats are denied, not rounded.
4. **Everything is evidence.** Denials and failures are recorded as thoroughly as successes — the audit trail is the product.
5. **Not in the money path.** No custody, no keys, no transmission. Your executor moves money; Paygent governs and records.

## Roadmap

- **x402 adapter** — wrap Coinbase x402 payments with policy + audit (next)
- **Dashboard** — live spend view, approval inbox, ledger explorer
- **Stripe issuing adapter** + consent-evidence dossiers (exportable dispute packets)
- **UPI adapter** — ready for NPCI delegated-payment APIs the day they open

## License

MIT
