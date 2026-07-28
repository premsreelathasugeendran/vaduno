# Vaduno Security Model

This document states exactly what Vaduno guarantees, under what assumptions,
and what it does **not** guarantee. If a marketing claim ever contradicts this
document, this document is right.

## What Vaduno is

A **non-custodial control plane** for AI-agent payments. It decides whether a
payment may happen (policy, mandates, approvals, kill-switch) and records what
happened (tamper-evident audit). Licensed rails move the money.

## The structural invariant (the most important control)

**Vaduno never holds funds, private keys for funds, or card PANs.**

- x402: the agent's own signer produces the payment; Vaduno polices the
  *requirement* and never sees the wallet key.
- Stripe Issuing: Stripe holds the card and moves the money; Vaduno only
  answers approve/decline for each authorization.
- Consequence: a **full compromise of Vaduno cannot directly move money**. It
  could at worst approve payments the policy should have blocked — bounded by
  the rails' own caps — or deny service (fail-closed).

Everything else in this document is defense in depth behind that invariant.
One custodial adapter would collapse it (and pull in money-transmitter
licensing); no such adapter will be accepted.

## Guarantees, precisely

| Property | Mechanism | Assumption it rests on |
|---|---|---|
| A payment above policy is not executed *through Vaduno* | Deterministic policy engine, fail-closed on any error | The agent actually routes spend through the guard (see limits) |
| Human approval cannot be replayed onto a different payment | Approval bound to a fingerprint of amount+currency+merchant+rail | — |
| A mandate cannot be over-used, reused after expiry, or forged | Ed25519 signature, time bounds, atomic consume-once use counting | Issuer's signing key stays private |
| A retried/raced payment executes the rail exactly once | Runtime enforcement: atomic `claim(mandateId, intentId)` in a ConsumeStore; every duplicate returns `replayed` with the original outcome | All spend for that mandate routes through one guard/ConsumeStore |
| A used intent id cannot be replayed as a *different* payment | The claim commits an `intentDigest` of amount+currency+merchant+rail; a mismatch is denied (`MANDATE_REPLAY_MISMATCH`), never replayed or executed | — |
| A mandate is bound to one approved task run | Optional `contextHash`: the intent must present the exact context blob, and its `agentId`/`merchantId` fields must match the intent (`CONTEXT_MISMATCH`) | Issuer sets a contextHash at issue time |
| A revoked mandate or agent can never spend again | The guard consults the revocation registry inside its critical section (after approval, before mandate consumption) and fails closed | Spend flows through a guard wired with `revocationCheck` |
| A revocation beats work already in flight | The check runs after any human approval, so a kill switch pulled mid-approval still denies | — |
| A tampered, stale, or rolled-back status list cannot un-revoke | Ed25519-signed status lists with `validUntil` freshness and a monotonic version floor; every failure mode denies | Issuer's signing key stays private |
| The log cannot show two different histories to two parties | C2SP witness cosigning: k independent witnesses each refuse to cosign a checkpoint contradicting one they already cosigned, so a fork cannot reach quorum | The k witnesses are genuinely independent parties, and each persists its state |
| Recorded history cannot be *silently* edited or reordered | Hash-chained ledger; `verify()` re-derives every link | Verifier runs; a retained head is compared |
| A specific decision **is** in the published history (non-omission) | RFC 9162 Merkle inclusion proofs (`@vaduno/transparency`) | The relying party checks proofs against a published head |
| Published history only ever grows (append-only) | RFC 9162 consistency proofs between signed tree heads | At least one party retains a previous head |
| Rewriting history is *cryptographically attributable* | Ed25519-signed tree heads; two signed heads of equal size with different roots are proof of equivocation | The log's signing key identifies the operator |

## Explicit non-guarantees (read these)

1. **"Fully secure" does not exist.** Bybit ($1.5B) and Ronin (~$600M) were
   breached at the human/UI/supply-chain layer with provably-sound
   cryptography underneath. Vaduno claims *specific properties under stated
   assumptions*, never "unhackable."
2. **A single operator can equivocate.** The transparency log makes rewriting
   history *detectable and attributable*, not impossible. Detection requires
   heads to be witnessed (published, or retained by clients —
   `witnessObserve`). A log whose only witness is its own operator proves
   nothing to outsiders. We provide the mechanism and name this limit rather
   than claiming distributed trust we don't have.
3. **Vaduno cannot stop spend that bypasses it.** An agent holding a raw
   funded wallet key can pay without asking. The deployment pattern is to
   give agents *only* guarded paths (x402 fetch wrapper, issued cards) — the
   guard governs what flows through it.
4. **Tamper-evidence is not tamper-proofness.** An attacker with full control
   of the store can destroy history; they cannot *fabricate* a history that
   passes verification against an externally retained head or signed root.
5. **Runtime enforcement stops replay and misapplication, not a compromised
   task.** Consume-once + context binding guarantee a mandate authorizes at
   most its `maxUses` executions, each for the exact payment approved. It does
   **not** stop a prompt-injected agent from getting a *fresh, correctly
   formed* mandate for an attacker's goal — that is an intent-integrity
   problem upstream of the firewall. A claim that is won but never settled
   (crash mid-execution) replays as `unresolved`: money *may* have moved, so
   the caller must reconcile, never blindly re-run.
6. **The one-execution guarantee is per shared ConsumeStore.** Two guards over
   two *separate* in-memory stores do not coordinate. Cross-process safety
   requires a shared store with an atomic uniqueness constraint
   (`FileConsumeStore` on one box; a DB unique index for multi-instance).
7. **Witnessing gives non-equivocation, not completeness — and only from
   genuinely independent witnesses.** A k-of-n cosignature quorum proves every
   relying party sees the *same* log; it does **not** prove the log recorded
   every event that happened. And witnesses run by the log operator provide
   exactly zero assurance — independence is a social property no code can
   check. A witness that does not persist its last-cosigned state also
   provides nothing, because it has no baseline to contradict. Cosignature
   freshness is judged against the verifier's own clock, not trusted time.
8. **Revocation binds only where Vaduno mediates.** Killing a mandate is
   instant and guaranteed for spend that flows through the guard. For
   authority Vaduno does not mediate — a raw wallet key the agent holds, a
   card issued outside Vaduno — revocation is a **best-effort fan-out** to
   that rail's own API; the registry has no authority over it. Fan-out
   failures are recorded, never assumed away. Money already settled on-chain
   cannot be clawed back by anyone. Do not call this a "universal kill
   switch."
9. **Settlement risk lives on the rails.** Peg/FX/finality risk of a
   stablecoin, chargeback outcomes on cards — Vaduno records evidence and
   surfaces data; it does not (cannot) alter rail-level outcomes.
10. **Timestamps are informational.** Signed tree heads assert tree state, not
    trusted time.

## Threat model summary

- **In scope:** compromised/prompt-injected agent, hostile merchant/server
  (x402 402 bodies, redirects, spoofed assets), replayed or tampered
  approvals/mandates/webhooks, post-hoc modification of audit history,
  malicious dashboard input, DoS-shaped inputs (nesting, oversized bodies).
- **Out of scope (delegated):** custody of funds/keys (rails/user signer),
  KYC/AML/Travel-Rule (licensed providers), physical/host compromise of the
  machine running the guard (an attacker who owns the process owns its
  in-memory policy — run the guard in the *user's* trust domain, never the
  merchant's), and availability of the rails themselves.

## Operational requirements for the guarantees to hold

- Retain ledger heads / signed tree heads **outside** the store they attest
  (print them, mirror them, publish them). Verification without an external
  head only proves internal consistency.
- Keep the mandate and log signing keys out of the repo and out of agent
  reach; prefer a cloud KMS. These keys sign *evidence*, not money — but a
  stolen log key lets an attacker sign a forged history.
- Run `verify()` / `audit()` on a schedule and on every dispute export.
- Fail-closed configuration is mandatory in production: the dashboard refuses
  to start without a real session secret; the guard denies on any policy
  evaluation error; approval and mandate checks reject on any parse/crypto
  error.
