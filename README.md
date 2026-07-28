# Vaduno

**A spend firewall and flight recorder for AI agents.**

[![CI](https://github.com/premsreelathasugeendran/vaduno/actions/workflows/ci.yml/badge.svg)](https://github.com/premsreelathasugeendran/vaduno/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@vaduno/guard.svg)](https://www.npmjs.com/package/@vaduno/guard)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![deps](https://img.shields.io/badge/runtime%20deps-0-brightgreen.svg)](packages/guard/package.json)

Your agent has an API key that can spend real money. Research says the agent *will* eventually be tricked — prompt-injection attacks against commerce agents succeed in [86% of attempts](https://arxiv.org/abs/2504.18575), and agents have bought from fake storefronts without hesitation. The model cannot be the last line of defense.

Vaduno puts a deterministic guard between your agent and the money:

- **Policy engine** — per-transaction / daily / weekly / monthly caps, merchant & category allowlists, rail restrictions, velocity limits, human-approval thresholds. Pure code; no model in the loop.
- **Signed mandates** — Ed25519 "permission slips" binding what the human authorized (amount, merchant, time window) to what executes. Time-bound and **consume-once atomic**, closing the [mandate-replay attacks](https://arxiv.org/abs/2602.06345) published against agent-payment protocols.
- **Runtime enforcement** — a mandate's "consume-once, context-bound" isn't just signed, it's *enforced on the execution path*: a retry storm or duplicate orchestration hop firing the same payment N times runs the rail **exactly once** and replays the original outcome to the rest; a used intent id reused for a different payment is denied; an optional context hash binds a mandate to one approved task run.
- **Flight recorder** — every attempt, decision, approval, and execution lands in a hash-chained, append-only audit ledger. Any edit, deletion, or reordering of history is detectable by `verify()`. Upgrade it to an [RFC 9162 Merkle transparency log](packages/transparency) for third-party inclusion (non-omission) and append-only consistency proofs.
- **Kill switch & revocation** — `guard.freeze()` denies everything instantly. For targeted kills, [`@vaduno/revocation`](packages/revocation) revokes a single mandate or an agent's entire authority, checked *after* human approval so a switch pulled mid-approval still wins — plus signed [W3C Bitstring Status Lists](https://www.w3.org/TR/vc-bitstring-status-list/) so third parties can verify status themselves.

**Vaduno never holds funds, keys, or the ability to move money.** It decides whether *your* executor function may run, and records everything. Rail-agnostic by design: wrap an x402 client, a Stripe issuing call, a UPI collect — anything.

## Status: v0.1.0, new, and honest about it

Read this before you put it anywhere near real money.

- **Published today. Zero users. Never run in production.** The tests are thorough (275 across five packages, including concurrency and adversarial cases) but tests are not production.
- **Stripe Issuing is test-mode only.** Production Issuing needs a business entity and Stripe approval the author doesn't have.
- **The API will break.** It's 0.x; breaking changes land in minor versions. Two API changes in the last week came from security review, and more review is planned.
- **In-process, it can be routed around.** A library the agent's own process imports is a guardrail against a *confused* agent, not a *compromised runtime* — an injected agent holding a raw wallet key can simply not call it. The one configuration where it is genuinely non-bypassable today is **Stripe Issuing**, where the guard answers the card authorization itself and the network enforces the answer. Out-of-process and rail-side enforcement is what would make the rest of it as strong.
- **Caps don't prevent prompt injection. They bound the loss.** No policy engine stops an agent being tricked; it stops the tricked agent from spending more than you allowed, at a merchant you didn't allow, twice.
- **"Fully secure" is never claimed.** Bybit lost $1.5B and Ronin ~$600M with sound cryptography underneath; both broke at the human and supply-chain layer. [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) states the precise guarantees **and** the precise non-guarantees. If a claim anywhere contradicts that file, that file is right.

Built ahead of demand on purpose: real agent-payment volume today is tiny. The bet is that the controls need to exist before the money shows up, not after.

## Install

```bash
npm install @vaduno/guard
```

Zero runtime dependencies. Node ≥ 18.

## 60-second example

```ts
import {
  VadunoGuard, AuditLedger, MemoryLedgerStore,
} from "@vaduno/guard";

const ledger = new AuditLedger(new MemoryLedgerStore());

const guard = new VadunoGuard({
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
  () => myX402Client.pay(...),   // your executor — Vaduno never touches the money
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
import { MandateManager, generateMandateKeyPair } from "@vaduno/guard";

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

**Where the signing key lives is the whole design.** A human signs a scope ahead of time — merchants, ceiling, time window — with an Ed25519 key held offline or somewhere the agent process cannot reach. The agent then spends unattended *inside* that scope. A validating process needs only the **public** key.

If you automate signing on the agent's own machine, the mandate stops being an authorization and becomes merely an audit format. That's a legitimate use, but be clear with yourself about which one you're deploying.

### Runtime enforcement: survive retries, races, and misapplication

Signing a mandate proves it was *issued*; it does nothing to stop that valid mandate from being executed twice by a retry loop or raced by two workers. Vaduno enforces it at execution time through a **consume-once registry** keyed on `(mandateId, intentId)`:

```ts
// The SAME payment fired 6x in parallel (a crashed/retried agent):
const results = await Promise.all(
  Array.from({ length: 6 }, () => guard.execute(sameIntent, payOnce)),
);
// rail ran AT MOST once → 1 "executed" + 5 "replayed" (original outcome), never a double charge.
```

**Scope of that guarantee:** at-most-once holds within one process by default, and across processes when you supply a shared store with an atomic uniqueness constraint. `FileConsumeStore` provides that on a single box. A Postgres-backed store is an *interface you implement*, not an adapter that ships today — if you run multiple instances, that's the piece you need to write.

- **`status: "replayed"`** carries the original attempt's outcome (`executed` / `failed` / `unresolved`); the executor does **not** run again.
- A used intent id presented with **different money fields** is denied `MANDATE_REPLAY_MISMATCH` — an id-reuse attack, not a retry.
- **Context binding** (`mandateContextHash`): set `constraints.contextHash` at issue time and the intent must present the exact context blob — with `agentId`/`merchantId` matching — or it's denied `CONTEXT_MISMATCH`. This binds a mandate to one approved task run so a valid mandate can't be redirected by a different orchestration hop.
- **Cross-process:** the default `MemoryConsumeStore` covers one process; pass a `FileConsumeStore` (one box) or a DB store with a unique constraint (multi-instance) so a race between processes still yields exactly one execution. `hydrateFromLedger()` rebuilds the registry after a restart.

Based on the runtime-verification results in [ZTRV](https://arxiv.org/abs/2602.06345) and APEX: signature-only checks intercept 0% of replays; an atomic consume registry intercepts 100%.

## Ledger stores

| Store | Use |
|---|---|
| `MemoryLedgerStore` | tests, ephemeral agents |
| `JsonlLedgerStore("ledger.jsonl")` | local flight-recorder file |
| `SupabaseLedgerStore(client)` | shared/team ledger — schema in [supabase/schema.sql](supabase/schema.sql), RLS keeps it append-only server-side |

The chain is computed client-side; `verify()` re-derives every hash, so even a compromised database cannot silently rewrite history.

## x402 rail adapter (`@vaduno/x402`)

Turn the guard into a real payment path. `@vaduno/x402` wraps the HTTP 402
"pay-per-request" flow: on a 402 it builds a `PaymentIntent` from the server's
requirement, runs the guard, and only if allowed calls **your** signer. Vaduno
never sees keys.

```ts
import { createX402Fetch, usdc } from "@vaduno/x402";

const fetchWithPay = createX402Fetch({
  guard,                                   // your VadunoGuard
  agentId: "researcher-agent-1",
  pay: (req) => myWallet.signX402(req),    // your signer — Vaduno never holds keys
  assets: [                                // bind spend to the REAL token, not a label
    { network: "base", asset: "0x833589...2913", symbol: "USDC", decimals: 6 },
  ],
});

// Use it like fetch(). 402s are paid under policy; everything else passes through.
const res = await fetchWithPay("https://api.example.com/premium");
```

Rail-specific security notes (see [SECURITY.md](SECURITY.md)):

- **`merchant.url` is the real endpoint you contact**, not the server's `resource`
  claim — host allowlists bind where you actually connect. A server that claims a
  different origin than the one reached is refused.
- **In x402 the money goes to `payTo` (an address), decoupled from the request
  host.** A host allowlist does *not* constrain the recipient — pin it with an
  `id:<payTo>` pattern if that matters.
- **Pass the `assets` registry.** Without it, `currency` comes from the server's
  spoofable `extra.symbol`. With it, a token that isn't on your list is refused.
- **Spend is counted once the `X-PAYMENT` is transmitted** — because it's a bearer
  authorization the server can still settle even while returning an error. Bind a
  consume-once mandate (`maxUses`) to bound retries.

## Revocation & kill switch (`@vaduno/revocation`)

An agent's credentials leak at 2am. Revoke one mandate, or the agent's entire authority, and have it take effect before the next payment:

```ts
import { RevocationRegistry, createRegistryCheck } from "@vaduno/revocation";

const guard = new VadunoGuard({
  policy, ledger, mandates,
  revocationCheck: createRegistryCheck(registry),   // makes revocation ENFORCED
});

await registry.revokeAgent("shopper-agent-1", { reason: "credentials leaked" });
```

The check runs **inside the guard's critical section, after human approval** — so a kill switch pulled while someone is still approving still wins. Everything fails closed: a registry outage denies (`REVOCATION_CHECK_FAILED`) rather than reading as "not revoked". For counterparties who don't own your registry, `registry.publish(version)` emits a signed [W3C Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/) (131,072 entries in ~70 bytes) that rejects forged, stale, and rolled-back snapshots.

**Honest scope:** revocation is instant and guaranteed for mandates the guard mediates. For authority it doesn't mediate (a raw wallet key), fan-out to the rail's own API is best-effort — and every failure is recorded, never assumed away. Settled on-chain spend cannot be clawed back by anyone. See [packages/revocation](packages/revocation/README.md).

## Transparency log (`@vaduno/transparency`)

Upgrade the hash chain to an [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162) Merkle transparency log — the Certificate Transparency machinery, applied to payment decisions. It adds what a bare chain cannot: **inclusion proofs** (a specific decision *is* in the published history — proof of non-omission) and **consistency proofs** (a later root only ever extended the earlier one), both verifiable by a third party from Ed25519-signed tree heads.

On top of that, **witness cosigning** ([C2SP](https://github.com/C2SP/C2SP) `tlog-checkpoint` / `tlog-cosignature`) closes the one hole the log's own math cannot: an operator who signs *two* histories and shows a different one to each party. Independent witnesses refuse to cosign a checkpoint that contradicts one they already cosigned, so a fork can never reach a k-of-n quorum. Honest limit: this proves everyone sees the *same* log, not that the log is *complete* — and witnesses you run yourself count for nothing. See [packages/transparency](packages/transparency/README.md) and [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).

## Design principles

1. **Fail closed.** No approval handler? Approval-needing intents are denied. Internal error? Denied and audited. Unknown mandate? Denied.
2. **Deterministic last line.** An attacker is assumed to fully control the agent and every field of the intent. Policy checks are pure code over integer minor units.
3. **Amounts are integers.** Minor units (cents, paise) everywhere. Floats are denied, not rounded.
4. **Everything is evidence.** Denials and failures are recorded as thoroughly as successes — the audit trail is the product.
5. **Not in the money path.** No custody, no keys, no transmission. Your executor moves money; Vaduno governs and records.

## Roadmap

- ✅ **x402 adapter** (`@vaduno/x402`) — wrap Coinbase x402 payments with policy + audit
- ✅ **Stripe issuing adapter** (`@vaduno/stripe`) — the guard as the real-time card-authorization brain
- ✅ **Dashboard** — live spend view, approval inbox, ledger explorer ("Vault Terminal")
- ✅ **Runtime mandate enforcement** — consume-once + idempotent replay + context binding
- ✅ **Transparency log** (`@vaduno/transparency`) — RFC 9162 inclusion / consistency proofs
- ✅ **Revocation registry** (`@vaduno/revocation`) — targeted kill switch + W3C Bitstring Status Lists
- ✅ **Witness cosigning** — C2SP checkpoints + cosignatures; independent witnesses attest the log never forked
- **Consent-evidence dossiers** — exportable dispute/representment packets built on the audit trail
- **UPI adapter** — ready for NPCI delegated-payment APIs the day they open

## Prior art, and where this doesn't compete

**Stripe's `spending_controls`, Lithic and Privacy.com already enforce caps at the network** — the strongest possible place, because an agent cannot route around them. If you're on one rail, use those. They're better at that job than this is.

What Vaduno adds is one policy and one portable signed authority that survive *across* rails, plus an audit log a counterparty can verify without trusting you. On Stripe Issuing it sits behind their controls, not instead of them.

## How this was built

Every package went through adversarial review before release: 20–35 reviewers per round, each finding independently verified before being accepted. That caught a cross-process double-spend (the `maxUses` check was check-then-act across separate locks), a hanging payment rail that could freeze the kill switch for every later revocation, a witness-quorum bypass that needed *zero* witness misbehaviour, and a C2SP wire-format error that would have broken interoperability with real Go/Sigsum witnesses while every local test still passed.

**To be precise about what that was:** multi-agent LLM review with findings verified by hand — not a professional audit, and you shouldn't take my word for the verification. The bugs are concrete enough to check against the commit history, which is the point of describing them here rather than burying them. A security tool that hides its near-misses is asking you to trust the wrong thing.

## Contributing

Bug reports and criticism are wanted, particularly on the concurrency and the cryptography. See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues go to [GitHub Security Advisories](https://github.com/premsreelathasugeendran/vaduno/security/advisories/new), never a public issue.

## License

MIT
