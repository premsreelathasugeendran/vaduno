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
| A used intent id cannot be replayed as a *different* payment | Within one mandate: the claim commits an `intentDigest` of amount+currency+merchant+rail; a mismatch is denied (`MANDATE_REPLAY_MISMATCH`), never replayed or executed. Across mandates the digest check cannot fire — `(M2, id)` is a new claim key — so the guard also refuses a mandated payment riding on a spend reservation it did not take (`INTENT_ID_NOT_BUDGETED`), which is what kept an id-reuse cap bypass open until 0.6.1 | — |
| A mandate is bound to one approved task run | Optional `contextHash`: the intent must present the exact context blob, and its `agentId`/`merchantId` fields must match the intent (`CONTEXT_MISMATCH`) | Issuer sets a contextHash at issue time |
| A revoked mandate or agent can never spend again | The guard consults the revocation registry inside its critical section (after approval, before mandate consumption) and fails closed | Spend flows through a guard wired with `revocationCheck` |
| A revocation beats work already in flight | The check runs after any human approval, so a kill switch pulled mid-approval still denies | — |
| An emergency freeze issued in ONE process stops every process's next authorization | A shared `FreezeStore` (one global row, monotonic epoch) consulted at authorization time via `createFreezeCheck` — inside the critical section, after approval, before the budget reservation. Unfreeze is epoch-fenced compare-and-set (a stale fence is refused, unchanged). An unreachable store denies every payment — a deliberate total stop, never fail-open | Every guard is wired with `createFreezeCheck` over the SAME store (`guard.freeze()` alone remains per-process), and spend flows through the guard |
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
   give agents *only* guarded paths — the x402 fetch wrapper, issued cards,
   or `@vaduno/cloudflare`'s out-of-process signer host, where the key lives
   in a separate process/Durable Object whose only exposed capability is the
   policy-gated `signTypedData` and the agent process is keyless — the guard
   governs what flows through it, and the custody arrangement decides whether
   anything can flow around it.
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
11. **Concurrent ledger writers are safe since 0.3.0 — within each store's
    stated residual.** Before 0.3.0 `AuditLedger.append` derived
    `seq = last.seq + 1` inside a promise queue scoped to a single *instance*,
    so two `AuditLedger` objects over one store both read seq N and both wrote
    N+1 (measured: 30 concurrent appends across three instances produced 10
    distinct sequence numbers, each written three times) — Memory/Jsonl forked
    and an honest system self-reported as tampered; Supabase quietly
    **dropped** the losing row while `verify()` stayed green. `LedgerStore` is
    now compare-and-append: a store admits an entry only if it still extends
    the current tip, a losing writer is handed the real tip and retries
    (bounded, then fails CLOSED as `AUDIT_WRITE_FAILED` / `auditDegraded` —
    a hot rival can starve a writer into denial, never into a forked or
    silently gappy chain). Hashing stays client-side, so a hostile store still
    cannot fabricate history (item 4).

    What "atomic" rests on, per store — trust the mechanism, not the label:
    - `MemoryLedgerStore`: JS single-threading; the compare and the write are
      one synchronous body.
    - `JsonlLedgerStore`: a `FileMutex` lockfile (shared with
      `FileSpendLimiter` / `FileConsumeStore`), tip re-read under the lock.
      Residual, inherited and documented in file-mutex.ts: a holder stalled
      past `staleMs` (default 30s) is reclaimed, briefly permitting two
      holders. Verified by an in-repo test with two real OS processes
      appending overlapping bursts to one file.
    - `SupabaseLedgerStore`: the schema is the mechanism — `seq bigint
      primary key` (one row per position) plus `unique (prev_hash)` (one
      child per parent) make a fork unrepresentable at the database even to a
      buggy or hostile client; the loser's SQLSTATE 23505 is classified as
      contention and retried, not dropped. Requires the 0.3.0
      `supabase/schema.sql` (the `prev_hash` unique index is new).
    - `PostgresLedgerStore` (`@vaduno/postgres`, new): same two constraints,
      plus `pg_advisory_xact_lock` to make retries rare rather than to be
      correct.

    A third-party `LedgerStore` written against the pre-0.3.0 interface is
    REFUSED at runtime (its bare append is exactly the fork bug), and
    `guard.isAuditDegraded()` remains the alarm for a durable record that
    never landed.

    **What has actually been exercised, exactly.** Memory and Jsonl run
    against the real stores, Jsonl by two real OS processes. The two
    database-backed stores are weaker evidence: `SupabaseLedgerStore` is
    exercised only against a schema-faithful in-repo fake, and
    `PostgresLedgerStore`'s conformance suite — while wired into the same CI
    job that runs the limiter and consume-store suites against a real
    Postgres 16 — is env-gated and skips on any machine without
    `VADUNO_TEST_POSTGRES_URL`, which was every machine it was written on.
    For both, correctness is Postgres's constraint guarantee rather than a
    property this project has watched hold. Believe it exactly as much as you
    believe the schema in `supabase/schema.sql`, and no more.

## Post-quantum posture (read the wording carefully — it is deliberate)

Audit evidence is LONG-LIVED. A dispute bundle or transparency proof verified
years from now must resist the adversary of THAT year forging "2026"
signatures — the archival variant of harvest-now-decrypt-later. FIPS 204
(ML-DSA) is final; NIST IR 8547 deprecates ECC/RSA signatures for new use in
2030 and disallows them in 2035, so any Ed25519 signature emitted today is
inside that window if it is verified after 2030.

**What is already adequate and was NOT rebuilt:** the hash chain and the
RFC 9162 Merkle tree are SHA-256. Grover's algorithm halves the security
bits; 128-bit preimage resistance remains, which is adequate. The SIGNATURES
are the quantum-exposed surface. (This is also the direction the CT/WebPKI
world is taking: the answer to PQ signature sizes there is to replace
signatures with Merkle hash paths — which is the architecture this project's
evidence layer already has.)

**What hybrid adds, precisely:** a v2 mandate carries an ML-DSA-44 signature
ALONGSIDE Ed25519 over the same `vaduno-mandate/v2` payload, and the
transparency log accepts ML-DSA-44 (0x06) witness cosignatures per C2SP
tlog-cosignature, where the runtime supports them. The classical signatures
remain exposed post-CRQC unless the verifier's policy requires the PQ
algorithm (`requireAlgs`). Nothing here is "quantum-safe" and this project
does not use that phrase; the release gate rejects it.

1. **THE DOWNGRADE RESIDUAL, stated as an attack.** "There are no downgrade
   rules to exploit" would be FALSE at the system level, so it is not
   claimed. A post-CRQC attacker does not strip a v2 mandate's PQ signature —
   they MINT A FRESH v1 mandate under any Ed25519 kid the verifier still
   registers, because `requireAlgs` defaults to `[]` and v1 remains a
   supported format. Issuing v2 mandates therefore protects NOTHING by
   itself. The ONLY defenses are `requireAlgs: ["ML-DSA-44"]` (refuses every
   v1 and every v2 whose ML-DSA half cannot be verified — fail closed) or
   de-registering classical-only trust. Both the exposure and the remedy are
   pinned by an attack test (`packages/guard/test/mandate-v2.test.ts`).
   - **Migration guidance:** run hybrid issuance now; enforce per issuer as
     each issuer's mandates go hybrid (a verifier that trusts several
     issuers can hold separate managers per issuer, flipping `requireAlgs`
     issuer by issuer); or pick and document a cutover date after which
     verifiers set `requireAlgs` and v1 acceptance ends. The frozen v1
     format itself never changes — what changes is whether your policy
     still accepts it.
   - **Why the AUDIT layer is less exposed than fresh authorizations:**
     evidence ANCHORING. A mandate forged in 2035 claiming to be "v1 from
     2026" has no 2026 inclusion in the transparency log and no pre-CRQC
     witness cosignatures; `assessCheckpointAnchor` reports `witnessedAt`
     from cosignatures at least as strong as the reported anchor strength.
     Anchoring mitigates the audit layer; it does not authorize spend, and
     it is not a substitute for `requireAlgs` on the authorization path.

2. **Archival verification is temporal-precedence-based, not freshness-
   based.** A cosignature attests "this witness saw this checkpoint no later
   than T", and that statement does not decay. `verifyCosignatures` /
   `checkCosignatureQuorum` therefore apply NO staleness bound by default —
   an EvidenceBundle verified years later verifies. The future-skew
   rejection stays on (a timestamp ahead of the verifier's clock is
   implausible at any age). Freshness (`maxAgeSeconds`) is an opt-in
   LIVENESS check for "is this log still publishing", not an evidence check;
   `Infinity` is the explicit spelling of "unbounded".

3. **witnessedAt is scoped to the reported strength.** For a
   `witnessed-pq` checkpoint, `witnessedAt` is computed from VERIFIED 0x06
   cosignatures ONLY — never "earliest across all algorithms". Otherwise a
   post-CRQC attacker could append a validly-forged, BACKDATED Ed25519
   cosignature and move the claimed witness time arbitrarily early. Pinned
   by the label-upgrade attack test (`packages/transparency/test/anchor.test.ts`).

4. **The 0x06 witnessing asymmetry, not hidden:** the C2SP ML-DSA-44
   cosignature signs a binary struct covering (origin, tree size, root hash)
   only, while the 0x04 text cosignature signs the FULL note body including
   extension lines. `witnessed-pq` therefore attests TREE STATE; extension-
   line equivocation is witnessed only classically. Vaduno's own checkpoints
   carry no extension lines (and they are documented as NOT RECOMMENDED),
   but third-party notes may differ.

5. **Key ids are truncated hashes — collisions are a residual, not
   impossible.** `mandateKeyId` / `mlDsa44KeyId` are 64-bit truncations of
   SHA-256. Distinct keys can share an id: ~2^32 work birthday-collides two
   attacker-chosen keys, ~2^64 grinds a targeted second preimage —
   borderline feasible for a resourced attacker. What is enforced: verifiers
   look keys up by **(algorithm, kid)**, so a collision can never cross
   algorithm families (an id registered only under ML-DSA-44 does not
   resolve for a v1 mandate, and vice versa — tested). The WITHIN-family
   residual remains and is stated here instead of being papered over with
   "cannot collide by construction", which was never true of a truncated
   hash.

6. **Unverifiable-here PQ signatures: the decided behavior.** On a runtime
   without native ML-DSA (or for a kid the verifier holds no ML-DSA key
   for), a v2 mandate is accepted RESTING ON ITS CLASSICAL SIGNATURE — the
   same standing as a v1 mandate, so no new exposure — unless `requireAlgs`
   demands ML-DSA-44, in which case it is refused. On the transparency
   verify path, unverifiable 0x06 lines are IGNORED (per the signed-note
   spec's treatment of unusable signatures; making them fatal would let one
   byzantine witness's garbage line veto everyone's quorum) and the note
   rests on its classical cosignatures. Neither treatment can be turned
   into a downgrade: where an algorithm can be verified it MUST verify (a
   present-but-invalid half is refused as tamper evidence), labels and
   witness times only ever count what VERIFIED, and every "required but
   unverifiable" case is a refusal.

7. **Runtime capability is decided by a PROBE, never a version string.**
   ML-DSA in `node:crypto` requires Node >= 24.7 **built against OpenSSL >=
   3.5**; a Node binary linked to an older OpenSSL lacks it at ANY Node
   version. `mlDsa44Available()` asks the crypto layer directly and is the
   only authority. Absent support, SIGNING paths throw a typed
   `PqUnavailableError` naming that requirement — they never silently fall
   back to classical-only output.

8. **Hybrid-vs-pure is a genuinely unsettled policy split.** NSA CNSA 2.0
   says hybrid is not required; BSI and ANSSI mandate hybrid; the IETF is
   standardizing composite signatures where BOTH must verify. This project
   implements the hybrid/composite pattern (both halves must verify where
   verifiable) and presents neither position as settled consensus.

## Threat model summary

- **In scope:** compromised/prompt-injected agent, hostile merchant/server
  (x402 402 bodies AND the v2 `PAYMENT-REQUIRED` header carrier, the v2
  extensions echo channel, role-constant `payTo`, redirects, spoofed
  assets), replayed or tampered
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
  stolen log key lets an attacker sign a forged history. The `Ed25519Signer`
  interface (see `docs/signers.md`) lets these keys live in a KMS/HSM so only
  signatures ever enter the process; every signer output is verified against
  the signer's declared public key before it is emitted — `MandateManager`,
  `RevocationRegistry`, and `LedgerMirror` freeze that key at construction —
  and every signer failure denies.
- **NORMATIVE key separation: a key used behind `Ed25519Signer` MUST be
  dedicated to Vaduno — minted for it, holding no other signing authority.
  Pointing Vaduno at an Ed25519 blockchain wallet key (Solana, NEAR,
  Stellar, any chain) or at any key shared with another system is PROHIBITED
  and unsupported.** A shared wallet key would make the Vaduno process a
  signing oracle adjacent to a key to funds — the deployment would cross the
  structural invariant above even though the code does not. Domain
  separation narrows what such a misdeployed key could be steered into, but
  it is PARTIAL (tested at the signer boundary): mandate, tree-head, and
  status-list payloads begin with fixed `vaduno-*` tags and witness
  cosignatures with the fixed C2SP `cosignature/v1` header — none of those
  tagged payloads can be a rail transaction. Checkpoint payloads carry NO
  fixed tag: they are C2SP signed-note bodies whose leading line is the
  operator-chosen `origin`. On the signer path Vaduno refuses a checkpoint
  body containing control or non-ASCII bytes, so it cannot reproduce a
  binary transaction framing (a Solana message header, for instance), but
  its leading bytes remain operator-chosen. Domain separation is
  defense-in-depth, NOT a licence to share keys — for checkpoints
  especially, key separation is the only wall.
- Run `verify()` / `audit()` on a schedule and on every dispute export.
- **Concurrent ledger writers need every writer on the 0.3.0
  compare-and-append store** (item 11) — one pre-0.3.0 writer on the same
  store reintroduces the fork. Also alarm on
  `guard.isAuditDegraded()`: it is the only signal that a charge executed and
  its durable record did not land, and nothing surfaces it for you. It is a
  live-process signal — a restart resets it — which is exactly where the
  second alarm takes over: `hydrateFromLedger()` returns a `HydrateReport`,
  and a nonzero `skippedUnparseableSpendRows` means the ledger holds rows
  that claim a successful charge (or cannot be read at all) which the
  restored caps do NOT include — for example rows written by a pre-0.3.0
  `settle()`, which recorded no amount. Reconcile against the rail before
  trusting restored totals. The two alarms cover different failures, and
  together they still do not close everything: a record that never landed at
  all (the write failed) leaves both the chain and the report clean — only
  the original process's `isAuditDegraded()` ever knew. If that flag fired
  and the process is gone, reconciliation against the rail is the remaining
  recourse.
- On restart over a persistent ledger, hydrate before serving — and pass
  `requireHydration: true` so the guard denies (`HYDRATION_REQUIRED`) until
  `hydrateFromLedger()` succeeds. A hydrate that is attempted and FAILS
  already denies by default until a retry succeeds; the option closes the
  remaining gap — a restart that never attempts hydrate and so serves with
  fresh, empty state: no restored freeze, zero counted spend, the maximally
  permissive configuration. Alarm on `guard.isFreezeDegraded()` as well: it
  means a freeze/unfreeze is enforced live but has no durable record, so a
  restart would not honour it.
- `guard.freeze()` takes no lock: its deny flag flips before the first await,
  and it is safe to call — and await — from anywhere, including inside an
  executor or `revocationCheck` (a freeze issued from inside the rail call
  cannot deadlock the guard). Its stopping power ends at the last freeze
  re-check: a freeze landing after that final check — inside the
  `execution_started` write that precedes the rail, or once `authorize()` has
  handed an authorization back to the caller — cannot stop that payment.
  Vaduno never recalls in-flight money; doing so would require the control
  over funds it must never hold.
- `guard.freeze()` is PER-PROCESS. For a freeze that binds every process,
  wire a shared `FreezeStore` into every guard
  (`revocationCheck: createFreezeCheck(store)`, `@vaduno/revocation`) — the
  store freeze then denies each wired process's next authorization, and
  `unfreeze(expectedEpoch)` is compare-and-set so a stale operator cannot
  lift a re-freeze they never saw. The two halves are independent: a local
  freeze does not write the store, and a store unfreeze does not clear a
  peer's local flag. Know the availability cost before wiring it: the check
  fails closed, so an unreachable freeze store denies EVERY payment on every
  wired guard — a total stop, by design, with no cache and no fail-open
  mode. The freeze store is a hard availability dependency for all payments;
  deploy it like one. A freeze gates authorizations only — it deliberately
  does not gate `settle()`, because a settle records money that already
  moved, and refusing to record it would corrupt the caps and the evidence,
  not protect anything.
- Fail-closed configuration is mandatory in production: the dashboard refuses
  to start without a real session secret; the guard denies on any policy
  evaluation error; approval and mandate checks reject on any parse/crypto
  error.
