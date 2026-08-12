# @vaduno/stripe

**Make Vaduno's guard the real-time authorization brain for a Stripe Issuing card.**

Stripe Issuing can ask *your* server to approve or decline every card
authorization in real time (the `issuing_authorization.request` webhook, ~2s to
answer). This adapter routes that decision through `@vaduno/guard`: the same
deterministic policy engine that governs your agents' spend now decides each
physical/virtual card charge — and every decision is written to the
hash-chained audit ledger.

**Vaduno never holds funds, keys to funds, or card PANs.** You pass in your own
Stripe client; the adapter only calls `stripe.webhooks.constructEvent`. Stripe
moves the money the instant the handler answers `approved: true`.

> **This adapter has never run against Stripe — not even in test mode.** It is
> verified against an in-process mock of the `issuing_authorization.request`
> webhook: the decision path, the signature check and the fail-closed deadline
> are exercised, the network path is not. Live Issuing needs a business entity
> and Stripe approval the author doesn't have. Treat this as a reference
> implementation, not a tested integration.

## Install

```bash
npm install @vaduno/stripe stripe
```

`stripe` is a peer dependency. Zero other runtime dependencies.

## The real-time authorization handler

```ts
import Stripe from "stripe";
import { VadunoGuard } from "@vaduno/guard";
import { createStripeAuthorizationHandler } from "@vaduno/stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
const guard = new VadunoGuard({ policy, ledger });

const handle = createStripeAuthorizationHandler({
  guard,
  stripe,
  webhookSecret: process.env.STRIPE_ISSUING_WEBHOOK_SECRET!,
  apiVersion: "2026-06-24.dahlia", // MUST match your account/SDK — echoed as Stripe-Version
});

// Framework-agnostic: hand it the RAW body + signature, write back its response.
// Next.js route handler:
export async function POST(req: Request) {
  const raw = await req.text();               // RAW body — required for signature verification
  const sig = req.headers.get("stripe-signature")!;
  const { status, body, headers } = await handle(raw, sig);
  return new Response(body, { status, headers });
}
```

**The body must be the RAW bytes** — a JSON body parser breaks signature
verification. In Express, use `express.raw` for the webhook route (do **not**
let `express.json()` touch it):

```ts
app.post("/webhooks/issuing", express.raw({ type: "application/json" }), async (req, res) => {
  const { status, body, headers } = await handle(req.body, req.header("stripe-signature")!);
  res.set(headers).status(status).send(body);
});
```

On `issuing_authorization.request`, the handler maps the Stripe `Authorization`
to a `PaymentIntent` (reading the amount from **`pending_request.amount`** — the
top-level `auth.amount` is `0` on the request), runs it through the guard with a
**no-op executor**, and answers Stripe:

- guard `executed` → `{ approved: true }` (the spend is counted)
- guard `denied` / `approval_rejected` / `failed` → `{ approved: false }`
- any internal error → **fail closed** to `{ approved: false }` (never throws on the request path)

```
✅ SaaS subscription: $9.00 → approved
⛔ Over per-txn cap: $25.00 → declined — PER_TXN_LIMIT_EXCEEDED
⛔ Casino (blocked category): $5.00 → declined — CATEGORY_BLOCKED
⛔ Would blow the daily cap: $19.00 → declined — PER_DAY_LIMIT_EXCEEDED
⛔ Any charge while frozen → declined — GUARD_FROZEN
```

Run `npm run demo:stripe` for the full loop against a mocked Stripe.

## Provisioning a card

```ts
import { createAgentCardholder, createAgentCard } from "@vaduno/stripe";

const cardholder = await createAgentCardholder(stripe, {
  name: "Acme AI",
  type: "company",
  billing: { address: { line1: "1 Main St", city: "SF", state: "CA", country: "US", postal_code: "94103" } },
});

const card = await createAgentCard(stripe, {
  cardholder: cardholder.id,
  agentId: "ops-agent-1",   // stamped into card.metadata so the handler resolves the agent
  policy,                    // mirrored into Stripe-native spending_controls (defense in depth)
});
```

`policyToSpendingControls(policy)` mirrors your caps into Stripe's own
`spending_controls`, so Stripe enforces the deterministic limits *before* the
webhook even fires. Native aggregation lags ~30s, so the **real-time guard stays
the tight gate**; the card controls are a backstop.

Card number / CVC retrieval (`expand: ["number","cvc"]` + an ephemeral key) is
intentionally left out of this package to keep it clear of PCI scope.

## Merchant & category matching (important)

- **There is no reliable merchant URL in Issuing**, so host-pattern merchant
  rules (`"openai.com"`) — **both allow *and* block** — **never match** on this
  rail. A `merchants.block: ["evil.com"]` is silently inert here. Constrain
  merchants with `id:<network_id>` patterns instead.
- `merchant.id` is the acquirer `network_id`. When absent it falls back to
  `unverified:<name-slug>` — the merchant name is attacker-controlled, so it's
  namespaced to keep it out of your trusted `id:` allowlist. Only trust `id:`
  matches that come from a real `network_id`.
- Categories are Stripe **MCC enums** (e.g. `"gambling"`). Free-form policy
  categories (`"api-credits"`) won't match a card authorization's category and
  are reported by `policyToSpendingControls` as `unmapped`.
- **Prefer an allow-list over a block-list for card categories.** A
  `categories.allow` fails *closed* (an authorization with a missing/unknown
  category is denied); a `categories.block` fails *open* on that same case
  (nothing to match → allowed). On a card, where category is the primary
  control, use `categories.allow` with exact Stripe MCC strings.
- **Approval-gated policies DECLINE on this rail.** A `require_approval` verdict
  cannot pend for a human inside Stripe's 2-second window — configure the guard
  used for Issuing without a blocking `approvalHandler` (so it denies), or rely
  on the adapter's decision deadline, which declines a blocked approval.

## Honest limitations

- **This has never been run against Stripe, in either mode.** Test mode should
  be demoable (`stripe trigger issuing_authorization.request` / test-helpers),
  but that is an expectation, not a result — nothing here has touched
  `api.stripe.com`. Going live additionally needs a real US business entity and
  Stripe's eligibility review, which the author does not have.
- **The deadline is hard, and the adapter's is 1300ms.** Stripe's own
  authorization window is ~2 seconds; `decisionTimeoutMs` defaults to **1300ms**
  ([`handler.ts`](src/handler.ts)) so the fail-closed DECLINE is emitted *inside*
  that window rather than racing it. One budget bounds the whole request path —
  the idempotency store's `get()`, `guard.execute`, and the store's `set()` —
  so even a hung external `DecisionStore` cannot stall the answer into the
  account default. Size your handler against 1300ms, not 2s.
  Keep it warm and deterministic and do the heavy reasoning at provisioning
  time; a cold serverless start or a slow ledger store can blow it.
- **Fail-closed-on-timeout is a Dashboard setting the adapter can't control.**
  Stripe has no safe default if your endpoint times out or returns a
  `webhook_error` (a wrong `Stripe-Version` triggers this). Set your account's
  authorization timeout posture to **decline**.
- **Native `spending_controls` fire before the webhook**, so charges they block
  never reach the guard and aren't in the ledger. Capture them via `onReconcile`
  (`issuing_authorization.created` declines) if you want them audited.
- **Approval-time accounting ≠ settlement.** Counted spend is the approved
  authorization; tips / partial captures / fuel finalization can diverge.
  Reconcile via `issuing_transaction.created`.

## License

MIT
