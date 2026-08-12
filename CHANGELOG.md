# Changelog

All packages are versioned together and released as a matched set.

## Unreleased

### Fixed — `@vaduno/revocation`: hydrate now reserves the bit of an agentless inline-revoked mandate

`hydrateFromLedger` only re-allocated a status-list index for a replayed
`mandate_revoked` event when the event carried an agent id. A mandate revoked
inline with no agent (and no prior `assignIndex`) still consumed a bit in the
original run, so skipping the allocation left the store's `next` counter
under-advanced: the first post-restart assignment reused the orphan's bit —
two mandates on one index — and once the reused-bit mandate was revoked and
the list published, a third-party `checkStatus` at the *other* mandate's
stamped index read a **revoked mandate as ACTIVE**. Local `isRevoked()` was
never wrong (it is keyed by mandate id, fail-closed); the damage was confined
to the published list — exactly the artifact third parties consume. Hydrate
now allocates unconditionally (a `null` agent just skips the agent link),
pinned by a restart-collision regression test.

### Fixed — `@vaduno/stripe`: `decisionTimeoutMs` now bounds the whole request path, not just `guard.execute`

A hung idempotency-store `get()` or `set()` (dead Redis, network partition)
could block `handle()` indefinitely — past Stripe's ~2s window — despite the
handler's documented "never blocks past the deadline" guarantee, leaving the
decision to the account default (which may APPROVE). Store *errors* already
failed closed; store *hangs* did not. One deadline budget now covers the
idempotency read, the guard decision, and the idempotency write: a hung
`get()` degrades to a cache miss, and a hung `set()` stops being awaited
(bounded, not fire-and-forget — the write keeps running and a merely slow
store is still waited for in-budget) so an already-computed decision always
reaches Stripe. Pinned by hung-get, hung-set, and slow-set regression tests.

### Fixed — `@vaduno/cloudflare`: the wire codec refuses `-0` and sparse arrays instead of letting JSON mangle them

`encodeWire` accepted negative zero and array holes — both survive
`structuredClone`, so they reached the wire — where `JSON.stringify` silently
rewrites them (`-0` → `0`, hole → `null`), breaking the codec's documented
"anything JSON would silently mangle is REFUSED" / `decode(encode(x))`-is-`x`
contract (the sparse-array case round-tripped to a real signature over
rewritten bytes). No police-X-sign-Y split existed — the host polices and
signs the same decoded value — and neither class is reachable through a
recognized payment shape; this closes a latent trap and makes the doc claim
true. Both classes now refuse client-side with `TYPED_DATA_NOT_SERIALIZABLE`,
and `decodeWire` symmetrically rejects `-0` arriving from a tampering
transport.

## 0.7.0 — 2026-08-10

### Added — `@vaduno/cloudflare`: out-of-process key custody (`createSignerHost` / `remoteSigner`)

The README has said from the first release that the in-process wrapper "can be
routed around — an injected agent holding a raw wallet key can simply not call
it", and that closing it needs the raw key kept "where only the wrapper reaches
it (separate process, Durable Object, or KMS)". That was a documented
aspiration. It now ships:

- `createSignerHost(options)` — same options as `guardedSigner` — keeps the
  raw account in the key-holder process and exposes exactly one capability:
  the policy-gated `signTypedData`, as `handle(string) -> string` and as a
  `fetch(Request) -> Response` for a Durable Object / Worker route. Every
  other method (`signTransaction`, `signMessage`, `exportKey`, anything) is an
  audited `HOST_METHOD_DISABLED` refusal; malformed or unparseable wire input
  is an audited refusal that never kills the host.
- `remoteSigner({ address, send })` / `connectRemoteSigner(send)` — the agent
  side: structurally a `ClientEvmSigner` for `withX402Client`, constructed
  from a public address and a transport. There is no key in the agent process
  to steal and no raw account to reach around; a full compromise there can
  only *ask*, and every ask is policed and ledgered on the host's side.
- The boundary is textual by construction (strings both ways), with a
  bigint-preserving, injective wire codec that REFUSES anything JSON would
  silently mangle (`TYPED_DATA_NOT_SERIALIZABLE`) — pinned by a test that the
  remote signature is byte-identical to a local `guardedSigner` signature
  over the same request.
- Honest residuals, in the README: host-process compromise still owns the
  key; the transport authenticates nobody by itself; client-side codec
  refusals cannot reach the host's ledger.
- `examples/keyless-agent` (`npm run demo:keyless`) spawns both OS processes
  and hard-checks the properties above; with `--live` it made a real Base
  Sepolia settlement (tx `0x7711f2…fb92`, 0.01 testnet USDC) in which the
  payment signature was produced in the key-holder process.

### Fixed — doc claims brought back to measured reality (2026-08-09 audit)

Every factual claim in the docs was re-measured against the registry, the
chain, and the test suite. Corrected where reality had moved or the original
measurement was wrong:

- README status header said v0.6.0 while npm's latest was 0.6.1 for all eight
  packages.
- The npm download curve was described as "a single spike on publish day and
  flat afterwards". The conclusion (automated traffic, no human users) stands;
  the shape was wrong — there is one spike per publish, collapsing to near
  zero between releases. Docs now describe the shape and quote no weekly
  total, because the total is a moving number (~1,187 on 2026-08-06, 824 two
  days later) and any hardcoded figure becomes false within days.
- `docs/DISTRIBUTION-EXPERIMENT.md` said "seven payments settled". An
  exhaustive on-chain scan (genesis to tip, retrying failed RPC chunks, zero
  dropped) counts twenty-one USDC transfers out of the experiment wallet —
  the earlier count came from a scan that silently swallowed failed chunks
  and under-reported, which is the exact defect class this project documents
  elsewhere.
- "1,189 tests" was ambiguous against a suite reporting 1,186 passed +
  3 skipped; the README now states passed and skipped separately (1,201
  passing + 3 capability-gated skips after this round's signer-host tests).
- The spend-limiter conformance figures ("23 cases, naive passes 19
  sequential / fails 4 concurrent") predated the suite's growth; re-measured
  against the current suite it is 38 cases, naive passes all 33 sequential
  and fails exactly the 5 concurrent ones — the claim's point is unchanged.
- `CONTRIBUTING.md` still said v0.2.2 / "981 tests across seven packages";
  `docs/LAUNCH.md` still said 364 tests and "one spike on publish day, zero
  every other day". Both corrected (LAUNCH keeps its 0.2.x bug history as
  history).

### Added — `@vaduno/cloudflare`: the guarded signer as a publishable package

(Chronology, for anyone diffing against the registry: this entry was first
published to npm as `@vaduno/cloudflare@0.6.1` on 2026-08-07, after the rest
of the 0.6.1 set — so the npm 0.6.1 artifact contains the in-process guarded
signer described here and NOT the signer host above, which first ships in
0.7.0.)

The `examples/guarded-signer/` prototype — five adversarial rounds, 20
confirmed defects fixed, real Base Sepolia settlements verified on-chain — is
now a workspace package, `@vaduno/cloudflare`, so a Cloudflare Agents SDK user
can put the guard in the mandatory signing path with a one-line swap:

```ts
const client = withX402Client(mcpClient, {
  account: guardedSigner({ account, guard, assets }),   // was: account
});
```

- The port is faithful: snapshot-then-sign, commitment gating (explicit and
  inferred domain), default-deny on shape, decimals scaling with round-up,
  payer/expiry/spender/collector policing, audited local refusals, throwing
  stubs for every raw-key capability, frozen wrapper with the real account
  closure-held. Each property's test was first observed failing against a
  deliberately broken build (two planted-defect batches, 11 + 8 targeted
  failures) before being trusted.
- Typechecked against the REAL upstream types: `ClientEvmSigner` from
  `@x402/evm` and `withX402Client`'s option type from `agents` are
  devDependencies, so upstream drift breaks this package's build instead of a
  consumer's runtime. The auth-capture tests run the genuine
  `AuthCaptureEvmScheme`, never an imitation.
- `viem` is a peerDependency (the consumer's copy is used; no version skew
  between what they sign with and what this package hashes with).
  `@vaduno/guard` stays the only runtime dependency, itself
  zero-runtime-dependency. No `node:` imports — refusal ids use Web Crypto —
  so the module loads on Workers without `nodejs_compat`.
- The asset registry takes the same `{ network, asset, symbol, decimals }`
  shape as `@vaduno/x402`'s `AssetInfo` (CAIP-2 networks); non-`eip155`
  entries are refused at construction rather than sitting in the registry as
  no-ops.

This project is pre-1.0. Under semver, 0.x minor bumps may break the API. Two
have, and each was breaking because the fix for a real security bug required it.
See [`SECURITY.md`](SECURITY.md) for what is and isn't guaranteed.

## 0.6.1 — 2026-08-06

### Fixed — two ways a refusal (or a valid payment) could still write ZERO ledger rows

The 0.5.0 notes claimed a malformed intent leaves the "same two ledger rows any
other deny leaves." That claim was overstated: two paths still ended in
`AUDIT_WRITE_FAILED` with an empty ledger, and this round closes both. This is
the third round of fixes for this class; what is different now is that the
depth limit is *derived from the serializer's own constant* rather than
mirrored by hand, and depth finally has test coverage.

- **A hostile `intent.id` / `intent.agentId` erased the refusal's evidence.**
  `inspectIntentShape` sanitizes what lands in the entry's `data` — but the
  guard passed RAW `safe.id` / `safe.agentId` as append refs, which
  `AuditLedger` writes as top-level entry fields, and `entryHash()`
  canonicalizes the whole entry. So an intent whose *id* was a bigint, `NaN`,
  or a `Date` made the very first append throw: `AUDIT_WRITE_FAILED`, zero
  rows — the exact zero-evidence failure `intent-shape.ts` was written to
  kill, resurrected one line below its fix (the non-cloneable path five lines
  earlier already type-guarded correctly). Measured before the fix: repeated
  refused attempts, 0 rows, every time. Refs are now sanitized before the
  append; the hostile value itself is still recorded, sanitized, inside
  `data.intent`, and the deny is `INTENT_NOT_SERIALIZABLE` with the usual two
  rows. (The first cut of this fix indexed every non-string id as a constant
  `"(unknown)"`, which a reattack showed merges DISTINCT hostile ids into one
  trail — see the injective type-tagged index under "reattack findings"
  below.)
- **The intent-depth limit was measured from the wrong root — with NO upper
  recovery bound.** The walker's private `MAX_DEPTH = 256` "mirrored"
  `canonicalJson`'s, but canonicalJson serializes the LEDGER ENTRY, where the
  intent sits at `entry.data.intent`, two levels deeper. A well-formed, fully
  valid, about-to-execute payment nested 255–256 deep passed inspection with
  zero problems and then threw inside `entryHash()`: `AUDIT_WRITE_FAILED`,
  zero rows, no execution. Past 256 it got *worse*, not better: the
  sanitization marker replaces an over-deep value at that value's own depth,
  so the sanitized copy was itself unappendable — depth 263, 300, 1000 all
  wrote zero rows too. The limit is now derived where it cannot drift:
  `MAX_INTENT_DEPTH = CANONICAL_MAX_DEPTH − 2 (entry envelope) − 1 (marker
  slot) = 253`, so the walker validates what the serializer will actually
  see. Proven by test at depths 253 (executes, full trail on the ledger),
  254, 255, 258, 263, 266, 300, 500 and 1000 (denied `INTENT_TOO_LARGE`, two
  rows, chain verifies) — no upper bound. The honest trade: an intent at
  exactly depth 254 used to execute and is now refused with evidence.
- **Third file store, same prototype-key hole — and the reference store
  diverged from its own documented semantics.** `FileApprovalStore` kept
  `pending`/`decisions` on plain objects where both sibling file stores had
  already moved to null-prototype records and documented why. The record is
  keyed on caller-controlled `intentId`: `enqueue("__proto__")` was silently
  dropped (`decisions["__proto__"]` reads `Object.prototype` — truthy — so
  the item was "already decided" and no human was ever shown it), and
  `getDecision("toString")` returned a *function* with no `.approved`, which
  the queued handler records as "approval does not match this payment" — a
  false audit row about a human decision that never existed. Fixed with the
  same null-prototype pattern. The absence that let it hide is also fixed:
  `ApprovalStore` now has the Memory-vs-File conformance suite the limiter
  and consume store already had — and its first run caught a second bug:
  `MemoryApprovalStore.resolve()` allowed planting a decision for a
  never-enqueued id and allowed overwriting an existing decision, both of
  which `FileApprovalStore`'s documented semantics forbid. Memory now
  enforces the same preconditions (no plant, first decision wins). A sweep
  for a fourth plain-object record keyed on caller strings found none: every
  other keyed record in the workspace is a `Map`, null-prototype, or
  fixed-key-validated.

### Fixed — the chain gate accepted a blocklist as proof of constraint, and the blocklist itself could be spelled around

Both reproduced against the current code before the fix. No money was at risk
in either — but the chain constraint they were supposed to supply was not real.

- **x402: a `networks.block` list alone no longer satisfies the chain gate.**
  `assertChainGated` accepted the mere presence of a `networks` key — allow OR
  block — as proof the deployment was chain-constrained. A blocklist is a
  subtraction from an unbounded set: every chain it does not name passes, so it
  supplies no positive constraint at all. Measured before the fix: with no
  `policy.networks` the gate correctly refused `NETWORK_UNGATED`, but with
  `networks: { block: [] }` — and with `block: ["solana:x"]` — the identical
  request **paid on base-sepolia, 200 OK**, precisely the chain-blind hole the
  gate's own docblock claimed to close. The gate now requires a positive
  constraint: a trusted `assets` registry, a `policy.networks.allow` list, or
  the explicit `allowChainBlind: true`. A block list still applies on top of an
  allow list, where a match can only tighten.
- **guard: network ids are canonicalized structurally, so a hostile seller
  cannot respell a blocked chain.** Comparison was trim + lowercase text, and
  the network id arrives in a 402 from an untrusted counterparty — so
  `eip155:084532` (leading zero) evaded a `block: ["eip155:84532"]` entry, as
  did hex, whitespace, and extra-colon spellings; the allow side was already
  fail-closed for the same variants, which made the block list the weak one.
  A block entry a counterparty can spell around is not a control. CAIP-2-shaped
  ids (anything with a `:`) are now parsed structurally — namespace plus
  reference, the `eip155` reference canonicalized numerically — a colon-bearing
  id that does not parse is denied with the new `NETWORK_UNPARSEABLE` code
  rather than passed through, and a policy entry that cannot itself be
  canonicalized poisons the whole constraint (`NETWORK_POLICY_INVALID`, now
  triggered by ANY unusable entry, not only when every entry is unusable),
  because a block entry that silently never matches is a hole the operator
  cannot see. Bare colon-free names (`"base-sepolia"`, `"stripe-live"`) keep
  their trim+lowercase semantics.

### Fixed — a mandated payment could execute on a spend reservation it never took

Found by a fresh sweep of the areas prior rounds had not looked at, reproduced
against the current code before the fix.

- **Cap bypass: one intent id, two mandates.** The spend limiter keys
  reservations on `intent.id`. The consume registry keys uses on
  `(mandateId, intent.id)`. Those key spaces are different, and the difference
  was live. Reuse one intent id under a **second** mandate — or under a mandate
  after a first payment that carried none — and `reserve()` answers `replayed`
  and records **nothing**, while `consumeOnce()` answers "fresh", because that
  pair is new to it. The guard took the mandate's word and ran the rail, so the
  payment moved funds no spend window ever counted. Measured before the fix
  against a 1,000-minor daily cap with payments of 600: two mandates executed
  1,200 of real spend against 600 counted; eight mandates executed nine payments
  (5,400) against the same counted 600; `authorize()` handed out two
  authorizations under one cap. `MANDATE_REPLAY_MISMATCH` could not catch it —
  the digest it compares lives on a claim key the registry had never held.
  The guard now refuses any mandated payment whose reservation came back
  `replayed`, with a new `INTENT_ID_NOT_BUDGETED` code, upholding the invariant
  the caps rest on: **nothing executes on a reservation it did not take.** A
  genuine retry (same mandate, same id) is untouched — `consumeOnce()` answers
  "duplicate" and the replay branch returns the original outcome, which is the
  property id reuse exists for. The check costs one burned mandate use on a
  payment that never ran, settled `failed`, the same trade the late-freeze exit
  already makes.
- **`FileSpendLimiter` treated prototype-named reservation ids as lookup hits.**
  `reservationId` is `intent.id`, a field the threat model assumes the caller
  controls, and the reservation record was a plain object — so
  `reservations["__proto__"]` read back `Object.prototype` (truthy) and
  `reserve()` answered "already reserved" on an **empty** limiter while
  recording nothing. Measured: the file limiter returned
  `{"ok":true,"reservationId":"__proto__","replayed":true}` where
  `MemorySpendLimiter` (Map-backed, the reference semantics every store must
  reproduce) returned `replayed: false`; the same read hits `constructor`,
  `toString` and every other prototype member. Both file-backed stores now hold
  their records on null-prototype objects, and the SpendLimiter conformance
  suite covers the case, so any future store is held to it too.
- **Docs corrected.** `SECURITY.md`, `docs/SECURITY-MODEL.md` and both READMEs
  claimed a used intent id could not be replayed as a different payment, full
  stop. That held only *within one mandate*. The rows now say which check covers
  which case, and name the gap that was open.

### Fixed — three semantic defects found by adversarial review of the signer binding

Putting `@vaduno/guard` in the mandatory signing path of a shipped x402 client
held against every escape, freeze-bypass and concurrency probe thrown at it. Not
one attack got past the wrapper. What broke was **semantics** — what the guard
is *told* about the payment it is approving — and all three are in shipped
library code, not in the prototype.

- **Policy was chain-blind: `PaymentIntent` had no network dimension.** Currency
  is not a chain. With an entirely ordinary multi-chain asset registry (Base
  Sepolia USDC and Ethereum Sepolia USDC, both symbol `USDC`) a transfer on
  chainId 11155111 was authorized by a deployment targeting 84532 — same intent
  shape, same currency, wrong chain. The chain lived in `metadata`, which no
  policy rule reads, so the only chain gate was the caller's asset registry:
  caller config, not a policy control. Added `intent.network` (opaque id,
  CAIP-2 recommended) and `policy.networks.allow` / `.block`.
  - **Exact match only**, case-insensitive after trimming. `"eip155"` does not
    stand for every EVM chain; implicit breadth is what caused this.
  - Once a `networks` block exists, an intent stating no network is denied
    `NETWORK_MISSING`, and a `networks` block with no usable entry denies
    `NETWORK_POLICY_INVALID` rather than enforcing nothing.
  - **The default is layered, not merely additive.** At the *guard* layer a
    policy with no `networks` block imposes no network constraint: the guard is
    rail-agnostic and cannot know whether a "network" is even meaningful for the
    rail in use, and denying unstated networks would deny every payment of every
    deployment that predates the field. But **where the network is always known,
    the safe configuration is enforced**: `@vaduno/x402` refuses a deployment in
    which *nothing* constrains the chain — no `assets` registry and no
    `policy.networks` — with `NETWORK_UNGATED`, before the payer runs. Opt out
    with `allowChainBlind: true`. So "expressible but not enforced" is closed on
    the rail where chain-blindness could never be a coherent choice.
    See `SECURITY.md` limitation 11.
  - `@vaduno/x402` now populates `intent.network` (v1 network name, v2 CAIP-2
    id — separate key spaces, exactly like the `assets` registry). The network
    also rides on `execution_started` / `execution_result` evidence rows, so a
    record says *where* money moved.

- **A host-form `merchants.block` pattern was evadable by omitting one optional
  field.** `merchantMatches` returns false for a host pattern with no parseable
  `merchant.url`. On the allow side false means denied — fail closed. On the
  **block** side false meant *not blocked*, so an agent (which the threat model
  assumes controls every intent field) dropped `merchant.url` and walked past
  the entire blocklist. An unevaluable host-form block pattern now denies
  `MERCHANT_URL_UNVERIFIABLE`. **Behaviour change, in the tightening
  direction:** if you run a host-form blocklist and some intents legitimately
  carry no URL, those intents now deny — set `merchant.url`, or express the rule
  with `id:` patterns.

- **A refusal that could not be recorded left no record.** An intent holding a
  value JSON cannot represent — `NaN` or `±Infinity` amount, a bigint, a `Date`,
  a cycle — made the very first ledger append throw, so the guard returned
  `AUDIT_WRITE_FAILED` and wrote **zero** ledger entries, versus two for an
  ordinary deny. The refusal was right; the evidence of the most suspicious
  attempt an operator could receive was the evidence that vanished. The intent
  is now inspected up front (`policy/intent-shape.ts`, accepting exactly
  `canonicalJson`'s value space), a **sanitized** copy is recorded — offending
  values replaced by a marker, tagged `intentSanitized: true` with the list of
  offending paths — and the payment is denied `INVALID_AMOUNT` (when the money
  itself is unrepresentable) and/or `INTENT_NOT_SERIALIZABLE`. Same two ledger
  rows any other deny leaves.

### Changed — a documented claim that outran the evidence

- **`SECURITY.md` and `policy/engine.ts` ranked host patterns as categorically
  stronger than `id:` patterns, and said host patterns avoid
  attacker-controlled fields. That was wrong.** `merchant.url` is caller-set
  exactly as `merchant.id` is; the guard never contacts the URL and has no
  independent knowledge of the payee. What a host pattern buys is **matching
  precision** — URL parsing plus a dot boundary, so lookalikes and FQDN variants
  cannot slip through — not trust. It is meaningful only if the caller derives
  `merchant.url` per intent from the real destination; fixed once at
  construction, it matches for every recipient. In a signer-level integration
  the ranking inverts outright: `merchant.id` there carries the payee address
  extracted from the bytes about to be signed, so `id:` is the stronger control.
  No verification the library cannot perform was invented; the claim was
  corrected. `SECURITY.md` limitation 5, the threat table, the
  `merchantMatches` docblock, and `packages/guard/README.md` now agree.

  **A documentation fix was not enough, and the re-examination found why.**
  `merchants.allow` is **disjunctive** — an intent passes if *any* entry
  matches — so a host-form entry there can only ever *widen* the recipient
  constraint, never narrow it. `["host:api.example.com", "id:0x…"]` does not
  mean "this host AND this recipient"; it means "this recipient OR anyone that
  host names", and the conjunction is not expressible at all. On x402, where
  `payTo` is decoupled from the resource host and is what the EIP-712
  authorization actually commits to, that makes a host entry in `allow` a
  recipient bypass wearing the shape of a control. Measured: a policy of
  `merchants.allow: ["host:api.example.com"]` against a server on that host
  naming an arbitrary `payTo` **paid, 200 OK**, with every control the operator
  wrote satisfied. So `@vaduno/x402` now **refuses** a policy carrying a
  host-form `allow` entry (`RECIPIENT_UNGATED`) before the payer runs; opt out
  with `allowHostOnlyMerchantPolicy: true`. Host patterns in `merchants.block`
  are untouched — a match there always denies, so disjunction only tightens.
  The rail-agnostic guard still cannot verify a payee; the *adapter*, which
  knows this rail's commitment structure, can refuse the configuration that
  pretends otherwise.

  **This is a breaking change for existing x402 callers, and our own demo was
  the first casualty** — worth stating plainly, because it is exactly what an
  upgrader will hit. `examples/x402-agent` carried
  `merchants: { allow: ["trusted-api.com"] }`, so after the gate landed every
  one of its eight scenarios refused `RECIPIENT_UNGATED` and the run ended with
  `ledger entries: 0`: a demo of a spend firewall that demonstrated nothing,
  including the controls that were still working. Fixed the way the new
  guidance says to — `allow: ["id:<payTo>"]` to bind the recipient,
  `block: ["evil-api.com"]` for the host rule (a blocklist match always denies,
  so disjunction only tightens), plus a `networks` block now that the chain is
  policeable. If your policy allowlists hosts on x402, this is the migration.

### Fixed — a denial-of-service surface introduced by the DEFECT-7 audit fix

- **A counterparty could inflate the tamper-evident ledger at will.** Making
  every refusal audited (so a malformed, possibly hostile intent stops leaving
  *zero* evidence) turned an O(1) fail-closed rejection into an unbounded,
  un-deduplicated, counterparty-driven writer into the audit log: every
  offending value produced a full `{path, problem}` record on the
  `intent_received` row *and* was re-joined into one `policy_decision` reason
  message. Measured at a steady **~62x, linear and uncapped** — 100,000 bad
  values in one intent wrote **18,678,768 bytes** of ledger, and a
  100-million-slot sparse array (O(1) caller bytes) drove the walk itself out
  of memory. `packages/guard/src/policy/intent-shape.ts` is now bounded in
  every dimension: at most 8 problem records are retained with paths and
  descriptions clamped, containers are capped at 10,000 entries, the whole walk
  at 20,000 nodes, and everything not enumerated is **counted**
  (`problemsTotal`, `problemsTruncated`, and per-container "N not inspected"
  markers) so the trace stays truthful. The same intent now writes **592,130
  bytes**, and writes the same 592,130 bytes at any larger n. The refusal is
  still audited — that was the point of DEFECT 7 and it is kept.
- **The sanitized deep copy was built unconditionally and discarded.** A clean
  intent — the common case — paid for a full materialized clone that was thrown
  away (+27 MB retained for one clean intent). Inspection is now two passes:
  detect-only first, and the copy is built only when there is something to
  sanitize.
- **A size refusal was reported as a serialization failure.** An intent that
  merely breached an inspection bound was denied `INTENT_NOT_SERIALIZABLE`
  ("holds values the audit trail cannot record exactly"), which is false for
  25,000 perfectly recordable strings and sends the operator after the wrong
  fix. Size breaches now deny `INTENT_TOO_LARGE`; the two codes are reported
  independently and an intent can carry both.

### Fixed — `FileMutex` could admit two simultaneous holders

- **The stale-lock reclaim rested on a single wall-clock subtraction.**
  `FileMutex` is the cross-process exclusion under four correctness properties —
  the ledger's compare-and-append (a fork), the consume store (a double spend),
  the spend limiter (a cap bypass), and the revocation freeze store — and it had
  **no test**. Reclaim treated a lock as abandoned when
  `now() - lockfile.mtimeMs > staleMs`, against an mtime written once at
  creation and never refreshed. Two ways that deleted a *live* holder's lock,
  both reproduced against the pre-fix code in
  `packages/guard/test/file-mutex.test.ts`:
  - a holder whose critical section merely **outlasts `staleMs`** is
    indistinguishable from a dead one, because the only evidence was the
    creation time;
  - a **forward clock jump** larger than `staleMs` — an NTP correction, a VM
    resume — instantly ages every live lock on the box past the threshold, with
    nothing anomalous about the holder or the load.

  A holder now **heartbeats** the lockfile's mtime every `staleMs/3` while it
  works, and a reclaimer never deletes on first sight: it records the mtime,
  waits a confirmation window measured on a **monotonic** clock (so the jump
  that made the lock look stale cannot also fast-forward the confirmation),
  re-stats, and reclaims only if nothing refreshed it. Crash recovery is
  unchanged — a dead holder never heartbeats — and is pinned by its own test.
  Residual, documented not hidden: a holder whose *event loop* is blocked
  cannot heartbeat, so a synchronous stall past `staleMs` plus the confirmation
  window is still reclaimable; that process cannot make progress anyway.

### Fixed — what the reattack on this release's own fixes found

Every fix above was independently re-attacked before release. The reattack
confirmed the original defects closed — and surfaced the following, each
reproduced against the fixed tree, then fixed with the reproduction as a test.

- **The blocklist could still be spelled around — with the OTHER wire spelling
  of the same chain.** x402 v1 names the settlement network `"base-sepolia"`;
  x402 v2 names the same chain `"eip155:84532"`. `normNetwork` treated bare
  names and CAIP-2 ids as disjoint key spaces, so `block: ["eip155:84532"]`
  did not block an intent whose network was `"base-sepolia"` — and one adapter
  speaks both protocol versions, so an allow list naturally carries both
  spellings. Measured end to end: with both spellings allowed and one blocked,
  a hostile 402 server answering in the other spelling was **paid, 200 OK**
  (money moved on testnet; the mirror direction too). A curated v1-name →
  CAIP-2 alias table (the EVM networks the x402 registry defines: base,
  base-sepolia, avalanche, avalanche-fuji, polygon, polygon-amoy, iotex, sei,
  sei-testnet) now canonicalizes both spellings to one comparison key — on the
  intent, the allow list and the block list alike. **Behaviour change, both
  directions of the same unification:** `block: ["eip155:84532"]` now blocks
  `"base-sepolia"` (tightening), and `allow: ["base-sepolia"]` now admits
  `"eip155:84532"` (the same chain it always claimed to admit). **Documented
  limit:** non-EVM v1 names (`"solana"`, `"solana-devnet"`) are NOT aliased —
  their CAIP-2 references are genesis-hash prefixes this table will not vouch
  for — so a policy constraining a non-EVM chain must name both spellings
  itself.
- **A canonicalizable non-string `intent.id` executed — and the first cut of
  the refs fix let distinct hostile ids collide.** An id of `42`, `null` or
  `true` passed shape inspection (the values are recordable) and EXECUTED,
  with `GuardResult.intentId` returning the raw non-string at runtime despite
  its declared `string` type — one payment with three identities. And the
  constant `"(unknown)"` index merged every distinct non-string id into ONE
  trail (denied attempts with ids `111n` and `222n` shared a single index),
  making rows unattributable under concurrency — evidence loss, not the "no
  evidence loss" the first report claimed. Two changes: non-string
  `intent.id` / `intent.agentId` are now **denied `INTENT_ID_NOT_STRING`**
  with the usual two rows, before any budget or mandate use; and the ledger
  index for a non-string id is an injective type-tagged rendering —
  `"(number 42)"`, `"(bigint 111)"` — so distinct attempts stay distinct.
  `GuardResult.intentId` now equals that index on every path. **Behaviour
  change:** intents whose id/agentId is not a string used to execute (against
  the declared types) and are now refused with evidence.
- **`settle()` lost its `execution_result` row on a hostile outcome value.**
  `guard.settle(id, { status: "failed", error: 10n })` made the best-effort
  append throw inside `canonicalJson`: the settlement of a REAL authorization
  went unrecorded — three rows instead of four, `auditDegraded` flagged. The
  outcome's `error` (and the id ref) are now sanitized before any evidence
  write; a non-string error is recorded as a bounded tagged rendering and the
  fourth row always lands.
- **A hostile approval-handler response converted a human APPROVAL into a
  deny — and lost the `approval_resolved` row.** With step-up triggered and a
  handler returning `{ approved: true, note: 10n }`, the hard
  `approval_resolved` append threw, the outer catch denied
  `GUARD_INTERNAL_ERROR`, and the one row missing was the human's actual
  decision. The response now goes through the same inspector the intent does:
  recorded sanitized (`responseSanitized: true`), the decision honored, the
  append still hard.
- **A malformed `assets` registry entry crashed the payer instead of naming
  the configuration error.** Writing `address:` where `asset:` belongs
  surfaced as a raw `TypeError: Cannot read properties of undefined (reading
  'toLowerCase')` mid-payment. `createX402Fetch` now validates every entry at
  wrap time and refuses by name (`assets[i] is not a usable AssetInfo …`),
  before any request is in flight.

**Known limits, stated rather than hidden:** (1) an intent nested past
structuredClone's own recursion tolerance (~1,000+ wrappers) falls to the
non-cloneable path — denied `INTENT_NOT_SERIALIZABLE` with ONE best-effort
row (no `intent_received`), never zero, but thinner than the two-row contract
every other deny meets; (2) an OBJECT-typed id collapses to the `"(object)"`
index (nothing legitimate uses one, and the full value still rides sanitized
in `data.intent`); (3) the x402 `assets` registry keeps v1 names and CAIP-2
ids as separate keys by documented design — the alias unification applies to
`policy.networks`, and an assets entry gates exactly the wire spelling it
names, refusing unlisted ones.

## 0.6.0 — 2026-08-05

### Fixed — a security defect found by running against a live host

`@vaduno/agent` shipped through 0.5.0 having never run in a live session, and
its README said so. Pointing a passive hook at a real Claude Code session found
three mismatches. **Upgrade from 0.5.0 if you use the Claude Agent SDK binding.**

- **A non-payment tool returned `permissionDecision: "allow"`, which
  short-circuits the host's own permission evaluation.** Registered the obvious
  way — a `*` matcher — the spend firewall auto-approved every OTHER tool in the
  session: a security package that silently switched off the permission prompts
  around it. It now returns `{}`, meaning no opinion, and the host's rules
  decide. This is the reason to upgrade.
- **A failed tool never reaches `postToolUse`.** It raises a separate failure
  event carrying `error` and no `tool_response`, so the failure heuristic could
  never fire and a failed payment was never settled — its authorization held
  budget until the rolling window aged out. New `postToolUseFailure` handler;
  register it alongside the other two. A user interrupt counts as a failure,
  because an interrupt says nothing about whether the rail was reached.
- **Correlation now prefers `tool_use_id`**, the host's own id, present on every
  observed event. The input fingerprint remains as a fallback for hosts that
  send none.

Two tests in `@vaduno/agent` had asserted the first defect as correct — a suite
cannot discover that its own premise is false. The harness that found it is in
`examples/cli-agent-hook`: a passive observer, and an enforcing hook that has
denied a real tool call in a live session.

### Changed

- `ClaudeAgentBinding` gains `postToolUseFailure`, and `preToolUse` may now
  return `{}` (no opinion) as well as a decision. Callers that only forwarded a
  decision object should forward whatever it returns verbatim.

### Note

This proves the agent-side binding against a real host. No money moved and no
payment rail was involved — that remains untested against anything live.

## 0.5.0 — 2026-08-04

### Fixed

- **The x402 version discriminant is now TOTAL (`@vaduno/x402`).** Both sites
  that read `x402Version` did `typeof v === "number" ? v : 1`, so the STRING
  `"2"` silently became 1 — a downgrade channel letting v2 data be read under
  v1 rules — and `0` / `-7` / `1.5` passed through verbatim. Every possible
  value now has a defined outcome per carrier (absent is the one documented
  v1 back-compat default; nothing else is ever coerced), and the full
  decision table is frozen as vectors (`spec/vectors/x402-http-v{1,2}.json`)
  asserted by `packages/x402/test/vectors.test.ts`.
- **The v2-shape heuristic no longer depends on `amount` being a string
  (`@vaduno/x402`).** A v2 body carrying a NUMERIC amount skipped detection
  and died on the misleading "maxAmountRequired must be a non-empty string";
  it now fires on `amount` of any type (when `maxAmountRequired` is absent)
  and on a top-level `resource` object — and at the fetch layer, the
  PAYMENT-REQUIRED header (the dominant real-world v2 signal) routes to the
  v2 parser before the body is ever read.

### Added

- **x402 v2 support (HTTP transport), opt-in (`@vaduno/x402`).** On a 402
  carrying a `PAYMENT-REQUIRED` header the adapter parses the base64
  PaymentRequired (total version check; CAIP-2 network grammar enforced;
  `maxTimeoutSeconds` required; body-level `ResourceInfo`; `extensions`
  validated, size-capped and defensively copied), selects a requirement,
  runs the guard, and only then calls the new `v2.pay(req, ctx)` — which
  returns the `PAYMENT-SIGNATURE` header value; settlement is read from
  `PAYMENT-RESPONSE`, including the specced failure form (402 +
  `success:false`, still counted — pessimistic accounting). The v1 `pay()`
  contract is unchanged; without the `v2` option, v2 402s are refused with
  `V2_NOT_CONFIGURED`. Carrier binding is single and total: header present →
  body never read; `x402Version: 2` in a JSON body refused; v1 fields inside
  a v2 requirement (`maxAmountRequired`, per-requirement `resource`) refused
  as mixed-version shapes. v2 `payTo` role constants are refused by default
  (`PAYTO_ROLE_REFUSED`; opt in via `v2.allowPayToRoles`). The trusted asset
  registry keys v1 names and v2 CAIP-2 ids separately, matching v2 networks
  case-sensitively (asset case-folded only on `eip155:`). All v1 security
  properties are re-proven on the v2 path by tests: redirect `manual`,
  origin match (against `resource.url`), asset registry, pessimistic
  accounting, bounded untrusted input, extra validation, and
  validated-object-is-paid-object identity. v2 core has no sessions or
  reusable authorizations (spec: out of scope; single-use EIP-3009 nonces;
  `upto` settles at most once — an unanalysed `batch-settlement` scheme exists in the spec tree), so cap accounting remains
  count-the-authorized-amount-once-at-transmission — for `upto`, the
  authorized MAX, never reconciled downward from the untrusted settlement.
- **x402 carrier conformance vectors** (`spec/vectors/x402-http-v1.json`,
  `x402-http-v2.json`), the v2 examples VERBATIM from the x402 spec's
  `transports-v2/http.md` (coinbase/x402 @ dd927a26). Added alongside the
  frozen set; every pre-existing vector is byte-identical. Documented in
  `docs/WIRE-FORMAT.md` §8.

## 0.4.0 — 2026-08-04

### Fixed

- **Archival evidence verification no longer fails by default
  (`@vaduno/transparency`).** `verifyCosignatures`/`checkCosignatureQuorum`
  defaulted `maxAgeSeconds` to 24h AND rejected `Infinity` via an isFinite
  guard, so an `EvidenceBundle` verified months or years later — the entire
  point of the evidence layer — failed `QUORUM_NOT_MET` with default
  options, and "unbounded age" was not even expressible. Evidence
  verification is now TEMPORAL-PRECEDENCE-based: no staleness bound by
  default (a witness attestation "seen no later than T" does not decay),
  the future-skew rejection retained, `maxAgeSeconds` an opt-in LIVENESS
  bound with `Infinity` as the explicit spelling of "unbounded" (NaN /
  negative bounds and non-finite skew still verify nothing — fail closed).
  A years-old cosignature verifying under default options is pinned as an
  acceptance test.
- **`rawEd25519PublicKey` refuses non-Ed25519 keys
  (`@vaduno/transparency`).** It extracted "the last 32 bytes of the SPKI
  DER", which is correct only for Ed25519's fixed 44-byte SPKI — handed any
  other key (an ML-DSA-44 key, an RSA key) it silently returned garbage,
  from which a plausible-looking but wrong key id would be minted. It now
  requires `asymmetricKeyType === "ed25519"`.

### Added

- **Post-quantum readiness for the evidence layer — hybrid, additive, and
  probed at runtime.** The hash chain and RFC 9162 Merkle tree are SHA-256
  and already PQ-adequate (Grover halves the bits; 128-bit preimage
  resistance remains); the SIGNATURES are the exposed surface, and NIST IR
  8547 sunsets ECC for new use in 2030 (disallowed 2035) while audit
  evidence signed today will still be verified after that. What shipped:
  - **Hybrid (v2) mandates (`@vaduno/guard`):** `issueHybrid()` signs the
    same `vaduno-mandate/v2`-tagged payload with BOTH Ed25519 and ML-DSA-44
    (FIPS 204); verification enforces exact structural bounds pre-crypto
    (algs suite fixed, `kids` keys equal to `algs` with `^[0-9a-f]{16}$`
    shape, signatures checked on DECODED length — Node's base64 decoder
    skips invalid chars, so encoded-length checks check nothing), looks
    keys up by **(algorithm, kid)** so a truncated-hash kid collision
    cannot cross families, and refuses a present-but-invalid half wherever
    it can be verified. v1 is FROZEN: its vectors are byte-identical and v1
    mandates verify forever. New verification policy `requireAlgs` —
    honestly documented as THE only post-CRQC defense, because an attacker
    who can forge Ed25519 mints a fresh v1 under any registered kid rather
    than stripping a v2 (the attack and the remedy are both tests).
  - **ML-DSA-44 (0x06) witness cosignatures (`@vaduno/transparency`):** per
    C2SP tlog-cosignature, signing the spec's BINARY subtree struct
    (`"subtree/v1\n\0"` label, length-prefixed name/origin, u64 timestamp /
    start=0 / end, raw root) — a different structure from the 0x04 text
    payload, built by a separate builder, with the coverage asymmetry
    documented (0x06 covers tree state, not extension lines) and a
    dedicated `rawMlDsa44PublicKey` SPKI parser (the Ed25519 last-32-bytes
    shortcut would mint garbage key ids). `assessCheckpointAnchor` labels
    anchor strength (`witnessed-pq` / `witnessed` / `unwitnessed`) with
    `witnessedAt` computed ONLY from cosignatures at least as strong as the
    reported label — a backdated forged classical cosignature cannot move a
    PQ-witnessed time (attack-tested).
  - **Runtime capability probe (`@vaduno/guard`):** `mlDsa44Available()` /
    `nativeMlDsa44Ops()` ask `node:crypto` directly — ML-DSA needs Node >=
    24.7 built against OpenSSL >= 3.5, and a version string cannot decide
    that. Signing without support throws typed `PqUnavailableError` naming
    the real requirement; verification degrades honestly (v2 rests on its
    classical signature unless `requireAlgs` refuses; unverifiable 0x06
    lines are ignored, and no label ever upgrades on unverified material).
  - New ADDITIVE vectors `spec/vectors/mandate-v2.json` and
    `spec/vectors/cosign-mldsa44-payload.json`; every existing vector file
    is untouched. Docs: `docs/SECURITY-MODEL.md` gains a "post-quantum
    posture" section stating exactly what holds (never "quantum-safe" —
    the release gate now rejects that phrase in package READMEs); the
    downgrade residual, the kid-truncation residual, the witnessing
    asymmetry and the hybrid-vs-pure policy split are stated rather than
    papered over. Zero new runtime dependencies.

- **Pluggable non-exportable signing: `Ed25519Signer` + `checkedSign`
  (`@vaduno/guard`).** Vaduno's evidence keys — mandate, tree-head,
  checkpoint, cosignature, status-list — can now live in a cloud KMS/HSM;
  only signatures enter the process. `checkedSign` is the single gate: copy
  the message in, race a deadline (`SignerTimeoutError`), require exactly 64
  bytes, verify against the signer's declared public key on the original
  bytes — only a verified signature is ever returned, and every failure
  denies. `MandateManager`, `RevocationRegistry`, and `LedgerMirror` accept
  `{ signer }`; each SNAPSHOTS the declared public key at construction (a
  backend that rotates mid-life is refused, never silently trusted), and
  misconfiguration throws at construction in all three — both key and
  signer, wrong algorithm, an unparseable declared or legacy key — with
  `MandateManager` (the only one that also takes a verify key) additionally
  refusing a `publicKeyPem` that does not match the signing key, whether it
  comes from a `signer` or a legacy `privateKeyPem`. Async twins `signTreeHeadWith`
  / `signCheckpointWith` / `cosignCheckpointWith` (`@vaduno/transparency`)
  and `publishStatusListWith` (`@vaduno/revocation`) sit beside the
  untouched sync functions with byte-identical wire output; a legacy
  `privateKeyPem` wraps into `LocalKeySigner`, so there is one signing path.
  `RevocationRegistry.publish()` now reserves its version before the signer
  round-trip, so concurrent publishes can neither share a version nor
  regress the rollback floor. `signCheckpointWith` refuses checkpoint bodies
  containing control or non-ASCII bytes (the untagged, origin-led payload
  must not be shapeable into a binary transaction framing). Zero new runtime
  dependencies — KMS examples live in `docs/signers.md` only, which also
  states the NORMATIVE key-separation requirement: keys behind a signer are
  minted for Vaduno and hold no other signing authority (blockchain wallet
  keys are explicitly prohibited).
- **Deterministic risk scorecard: ledger-derived tiers, step-up routing,
  auto-freeze.** Opt-in via `risk: new RiskScorecard({...})` on the guard.
  Eight deterministic signals (integer/BigInt math over the ledger, no model,
  nothing learned): `FIRST_SEEN_MERCHANT`, `AMOUNT_ABOVE_MERCHANT_TYPICAL`
  and `AMOUNT_ABOVE_GLOBAL_TYPICAL` (lower-median × multiplierBps,
  minHistory-gated), `OUT_OF_HOURS` (config-declared half-open UTC windows),
  `VELOCITY_BURST`, `DENY_STREAK`, `FIRST_USE_OF_MANDATE` (joined from
  `mandate_consumed` entries — `execution_result` rows carry no mandateId),
  and `CAP_APPROACH` (thresholdBps of `perDayMinor`; configured without a
  perDayMinor is a `RISK_UNSCORABLE` deny, not a skip). Score ≥ `stepUpAt`
  routes `require_approval` through the EXISTING approval branch
  (`RISK_STEPUP` + the fired signals in the reasons); score ≥ `denyAt` denies
  (`RISK_DENY`) and the approval handler is never invoked — approval answers
  a step-up, it never overrides a deny. Both risk denials are ordered BEFORE
  `limiter.reserve()` and `mandates.consumeOnce()`, so a risk deny never
  burns budget or a mandate use. Intents get a preliminary pass outside the
  mutex and, when still headed for execution, a final re-evaluation inside
  the critical section — risk that rises in between without an approval
  denies `RISK_STEPUP_UNAPPROVED`. Every assessment is hard-appended as a
  `risk_scored` ledger entry (one additive `LedgerEntryType`) carrying a
  ledger-head ANCHOR; `anchoredPrefix()` + `RiskScorecard.assess()` replay
  it bit-for-bit, including under concurrent traffic. `autoFreeze.atScore`
  (validated ≥ `denyAt`) denies the triggering intent and then freezes via
  the existing per-process `freeze()`, whose signature gains an optional
  structured `details.autoFreeze: {intentId, score, atScore}` recorded on
  the `guard_frozen` entry. The merge is monotone tighten-only
  (allow < require_approval < deny) and the assessment is agentId-invariant;
  constructor-time validation throws listing EVERY violation, including
  unknown signal keys. No `risk` option configured = the pipeline is
  unchanged. Mechanism-only analogue of 3DS2 risk-based authentication
  routing and Visa Advanced Authorization / Mastercard Decision Intelligence
  signals — single-deployment, deterministic, and conferring no liability
  property of any kind (see SECURITY.md Known Limits item 9 for the honest
  boundary).

- **Merchant-scoped, multi-window velocity controls.**
  `velocity.maxTransactions` now also accepts an ARRAY of count limits (burst
  AND sustained, all enforced), and the new
  `velocity.maxTransactionsPerMerchant` (same shapes) counts per merchant,
  denying `MERCHANT_VELOCITY_EXCEEDED`. Merchant identity is the exported
  `merchantKeyOf()` — URL host when present, else the id, in two disjoint
  prefix families — and it is ONE function so the limiter and any future
  consumer cannot disagree about which merchant a spend belongs to. Counts
  ride the existing atomic `reserve()` step in all three stores (memory,
  file, Postgres — one idempotent `ADD COLUMN IF NOT EXISTS merchant_key`),
  so they inherit the same cross-process atomicity amounts have. A
  merchant-dimension window with no merchant key on the request denies
  `MERCHANT_KEY_MISSING`, never skips; records written before merchant
  attribution (including Postgres NULL rows) count toward EVERY merchant
  window until they age out. Per-merchant velocity alone is NOT a security
  boundary — merchant fields are attacker-controlled and rotation mints
  fresh per-merchant budgets; it is a tightening layered UNDER global count
  windows (which are rotation-proof) and the allowlist. Scope stays
  `policy.id`, so agentId rotation mints no count budget.

### Fixed

- **Malformed spend-window config silently enforced NOTHING (fail-open).**
  In 0.3.0, a window configured with `maxCount: NaN` or `windowMs: 0`
  (e.g. `velocity: { maxTransactions: { count: NaN, perSeconds: 60 } }`)
  made every comparison in the evaluation loop false — the window LOOKED
  configured and enforced nothing, in the policy engine and in every store.
  Every window's configuration is now validated before any cap or count
  check (`windowConfigError()`, exported); one malformed window refuses
  everything under that policy with `SPEND_WINDOW_INVALID`, in the advisory
  engine AND all three stores. Corrupted config is now a DoS the operator
  notices, never an uncapped budget. (`maxCount: 0` — which previously
  refused, but with the window's own code — is also rejected as invalid
  config: a zero-slot window is "deny everything", and the denial should
  say so.)

## 0.3.0 — 2026-08-03

### Added

- **Two-phase `authorize()` / `settle()` on the guard, and `@vaduno/agent`.**
  Every agent framework's approval hook is decide-only (Claude Agent SDK
  `PreToolUse`, Vercel AI SDK `toolApproval`, OpenAI Agents `needsApproval`,
  LangChain `wrapToolCall`), so none of them could use
  `execute(intent, executor)`. `authorize()` runs the same pipeline and stops
  after the budget is reserved and any mandate use is consumed; the caller runs
  the payment and reports back via `settle()`. `@vaduno/agent` packages this as
  `createSpendHooks` plus a thin Claude Agent SDK binding.
- **Prune APIs**: `SpendLimiter.pruneBefore(beforeMs)` and
  `ConsumeStore.pruneMandates(ids)` — the retention advice in SECURITY.md now
  points at something that exists. `pruneMandates` deliberately takes ids from
  the caller because pruning a claim re-arms its intent id.
- **`PostgresRevocationStore`**: status-list bit indices unique across
  instances.
- **Frozen wire format** (`docs/WIRE-FORMAT.md` + committed test vectors) and
  mandate signing hardening: domain tag, format version, algorithm pin, key id.
- **`requireHydration` guard option and `isFreezeDegraded()` /
  `isLimiterDegraded()` accessors.** See the fixes below for why each exists.
- **`PostgresLedgerStore`**: the audit ledger for multi-instance deployments.
  This package shipped shared spend caps and shared consume-once with NO
  shared ledger; the one backend with real transactions was the one backend
  the ledger could not use.
- **Cross-process freeze: a shared `FreezeStore` + `createFreezeCheck`.**
  Measured before the fix: guard A calls `freeze("credentials leaked")`, A
  denies, guard B EXECUTES — for B's whole lifetime, because `this.frozen` is
  an instance field with no push and no pull (`hydrateFromLedger` is one-shot,
  so an operator could not even poll it). The fix reuses the existing
  `revocationCheck` seam — `VadunoGuard` itself is unchanged, zero lines: a
  `FreezeStore` holds one global row `{epoch, frozen, reason, by, at}`, and
  `createFreezeCheck(store)` (compose via `allChecks`) denies `GUARD_FROZEN`
  with the operator's reason on every wired process's very next authorization
  — checked inside the critical section, after human approval, before the
  budget reservation. Every freeze bumps a monotonic epoch and
  `unfreeze(expectedEpoch)` is compare-and-set, so a stale operator cannot
  lift a re-freeze they never saw; a `freeze("")` never blanks a live reason.
  Fail closed and stated loudly: an UNREACHABLE freeze store denies EVERY
  payment (`FREEZE_CHECK_FAILED`) — a deliberate total stop that makes the
  store a hard availability dependency (see SECURITY.md Known Limits 2). A
  freeze denies NEW authorizations only: it never recalls in-flight money and
  deliberately does not gate `settle()`, which records money that already
  moved. Backends: `MemoryFreezeStore` + `FileFreezeStore`
  (`@vaduno/revocation`; File shares the `FileMutex` primitive and its
  `staleMs` residual) and `PostgresFreezeStore` (`@vaduno/postgres`; the
  compare-and-set IS `UPDATE … WHERE epoch = $expected`; schema adds
  `vaduno_freeze`). Proven by a seven-test conformance suite run against two
  independent guard handles over one shared freeze resource (Memory and File
  on every test run; Postgres env-gated in the CI job, NOT exercised against
  a live database on the development machine). `guard.freeze()` — the local,
  per-process flag — is unchanged and independent: a local freeze does not
  write the store, and a store unfreeze does not clear a peer's local flag.

### Fixed — concurrent ledger writers forked or silently dropped entries (breaking `LedgerStore` change)

- Two `AuditLedger` instances over one store — two processes, or two instances
  in one process — both read tip seq N and both wrote N+1: the per-instance
  promise queue never protected the store. Measured, not theorized: 30
  concurrent appends across three instances produced 10 distinct sequence
  numbers, each written three times. Memory/Jsonl accepted the duplicates
  (a FORK — the honest ledger then failed `verify()` forever, stamped
  `chain:{ok:false}` on every evidence bundle, and made `hydrateFromLedger()`
  throw on every restart); Supabase's `seq bigint primary key` rejected the
  loser and the rejection was swallowed into `auditDegraded` — money moved,
  the record was DROPPED, and `verify()` stayed green. The quiet one.
- `LedgerStore.append` is now **compare-and-append** —
  `append(entry, {prevSeq, prevHash})` persists only if the store's tip still
  matches, else reports the real tip; `AuditLedger` re-chains and retries
  (bounded, then fails CLOSED as `AUDIT_WRITE_FAILED` / `auditDegraded`).
  Hashing stays client-side, so a hostile store still cannot fabricate
  history. Atomicity is per-backend: Memory compares-and-pushes in one
  synchronous body; Jsonl re-reads the tip under the same `FileMutex` the
  other file stores share (inheriting its documented `staleMs` reclaim
  window); Supabase/Postgres get it from the schema — `seq` primary key plus
  a new `unique (prev_hash)` index (one child per parent) make a fork
  unrepresentable at the database, and the loser's 23505 is classified as
  contention and retried instead of rethrown. **Breaking for third-party
  `LedgerStore` implementers** (this is pre-1.0; the fix required it):
  a store built against the pre-0.3.0 `append(entry): Promise<void>` shape is
  REFUSED at runtime rather than silently being the unsafe path.
  `AuditLedger.append(type, data, refs)` and every guard call site are
  unchanged. Supabase deployments must apply the 0.3.0 `supabase/schema.sql`.
- `verify()` now distinguishes a fork (`duplicate or regressed seq … a second
  writer, not a deletion`) from a gap (`entries missing`), so an honest ledger
  that hit this race is no longer forensically misdiagnosed as
  tampered-by-deletion; `head()` refuses to anchor a forked or truncated
  chain instead of blessing whichever rows a later `verify()` would read.
- Proven by a conformance suite that runs two-to-three independent writer
  handles per backend (fresh store objects on one path for jsonl — a queue
  hidden in the store object still fails it) plus a two-OS-process test on
  one jsonl file with a file barrier so the bursts overlap by construction.
  Scope of that proof, exactly: Memory and Jsonl run against the real stores.
  Supabase runs against a schema-faithful in-repo fake, not a live instance.
  `PostgresLedgerStore` rests on the same two constraints; its suite is wired
  into the CI job that runs against a real Postgres 16, but it is env-gated
  and skipped on every machine it was developed on. Its live evidence is
  whatever that CI job reports, and nothing more.

### Fixed — two-phase spends were invisible to restart recovery

- **`settle()` recorded no money.** Its `execution_result` row held
  `{success, selfReported}` with no `amountMinor`/`currency`, and both spend
  consumers filter such rows out. Measured: 4000 of a 5000/day cap spent via
  `authorize()`+`settle()`, restart, `hydrateFromLedger()` — another 4000
  AUTHORIZED (the `execute()` control correctly denied). This is the path every
  framework integration takes. The authorization now snapshots
  amount/currency/merchant/rail onto its `execution_started` row, and
  `settle()` recovers that snapshot so its row carries exactly the economic
  fields an `execute()` row carries (plus `selfReported: true`), and names the
  agent instead of an empty `agentId`.
- **Settle dedupe is keyed by OUTCOME, not position** — an "executed" settle is
  suppressed only by an existing success row for the current authorization; a
  "failed" settle by any result row. A positional check (any result row after
  the authorization) let a late-retried `settle(failed)` permanently suppress
  the genuine executed outcome on the documented recovery interleave
  (`settle(failed)` → `releaseSpend` → re-authorize same id → late retry →
  `settle(executed)`) — the ledger then said `success: false` for a charge that
  happened, and a restart re-authorized the full amount. A retried settle still
  cannot double-count: at most one countable success row per authorization, and
  the reservation commit is idempotent.
- **`hydrateFromLedger()` now returns a `HydrateReport`**
  (`{restoredSpendRows, skippedUnparseableSpendRows}`) instead of `void`. A
  spend row the restore cannot parse is still skipped — a malformed historical
  row must not NaN-poison the caps or crash startup — but the skip is now
  REPORTED. Nonzero `skippedUnparseableSpendRows` (which is what a pre-0.3.0
  `settle()` row hydrates as) means the restored caps under-count; reconcile
  against the rail.
- **`ledgerSpendHistory()` validates before counting** — requires a
  safe-integer amount and string currency, and takes an optional
  `onUnparseable` callback fired per malformed row. Previously
  `totalMinor += data.amountMinor ?? 0` counted a malformed row as a $0 spend
  and string-concatenated a string amount into the running total. A throwing
  callback is swallowed: policy evaluation never becomes an outage over a bad
  historical row.

### Fixed — freeze and hydration semantics

All three reproduced before fixing. `freeze()`/`unfreeze()` flip their flag
synchronously, stamp a monotonic epoch, and append lock-free through the
ledger's own queue — so a hydrate snapshot can no longer clobber a freeze taken
during startup, no deferred re-assertion exists to go stale, and freezing from
inside an executor cannot deadlock. A freeze whose `guard_frozen` append failed
stays enforced locally and reports `isFreezeDegraded()` (it would not survive a
restart). An attempted-and-FAILED hydrate now denies everything
(`HYDRATION_REQUIRED`) until a retry succeeds — serving with fresh, empty state
after the ledger failed verification is the permissive direction — and
`requireHydration: true` covers the restart that never attempts hydrate at all.

### Fixed — the rest

- **Approval fingerprint collision**: `approvalFingerprint` joined raw
  attacker-controlled strings with `|`, so a crafted `merchant.id`/`url` pair
  could make one human approval cover a payment to a different destination.
  Now domain-tagged canonical JSON (injective; throws rather than guesses).
- **JSONL stores no longer trust a stale cache**: both `JsonlLedgerStore` and
  the transparency store served a cached chain whenever the file SIZE was
  unchanged, so a byte-length-preserving edit passed `verify()` — and defeated
  `verify(retainedHead)` too. Every read now re-reads bytes; the deliberate
  perf trade is re-parsing on every `all()`/`verify()` instead of serving a
  cache that can lie.
- **x402 402-body handling**: with no `Content-Length` the whole body was
  buffered BEFORE the 64 KB cap applied (200 MiB measured); the cap also
  counted UTF-16 code units, admitting ~3x the stated bytes. Now an abortable
  byte-counting read that cancels at the cap; `extra` is validated by key and
  type; x402 v2 is refused by name.
- **`isAuditDegraded()` means exactly one thing**: an audit record failed to
  persist. Limiter commit/release failures — benign over-holds — moved to
  `isLimiterDegraded()`, and the two-phase/failed-execution audit appends that
  used to fail silently now flag `auditDegraded`.
- Doc-truth corrections: freeze is per-process (three places said otherwise),
  the ledger append queue is per-INSTANCE not per-process, and six other
  statements that were false.

## 0.2.2 — 2026-07-30

**The first release published from CI, and the first with provenance
attestation.** No library code changed — `dist/` is functionally identical to
0.2.1. What changed is who built it and what the shipped documentation says.

### Added

- **Provenance attestation.** Every package is now published by a GitHub Actions
  workflow via npm Trusted Publishing (OIDC), so the registry can prove which
  repo, commit and workflow produced each tarball. This cannot be added to an
  existing version retroactively, which is most of the reason this release
  exists. 0.1.0 through 0.2.1 were published from a laptop and carry no
  attestation.

### Fixed — in the READMEs npm actually renders

- **`@vaduno/guard`'s README still said "rail ran exactly once"** in the retry
  storm example, six lines below the table that had already been corrected to
  "at most once" in 0.1.1. At most once is the claim that is always true: a
  denied or failed intent runs the rail zero times.
- **It pointed multi-instance users at "a DB unique index"** — a thing they were
  expected to build. `PostgresConsumeStore` has shipped since 0.2.0; the README
  now says so.
- **It never documented that caps are scoped to `policy.id`.** This is
  security-relevant, not a detail: a reader building per-agent budgets would
  reasonably have keyed on `agentId`, which is exactly the bypass fixed in
  0.2.1. Now stated, with the reason.
- **It never documented burn-on-failure or `releaseSpend()`.** Someone whose
  executor throws needs to know the spend stays counted, and how to reclaim it
  when they can prove the rail did not charge.
- The root README claimed "two API changes came from security review". Every API
  change so far has, which is both more accurate and more useful to know.

### Changed (repository only)

- `.github/workflows/publish.yml` + `scripts/publish-ordered.mjs`. Three dry runs
  were needed to get this right, and each found a real bug: `npm@latest` now
  resolves to npm 12 which cannot run on Node 20; a shasum equality check
  rejected a legitimate CRLF-vs-LF difference between a Windows-published tarball
  and a Linux-built one; and the output contradicted itself by printing "bytes
  differ" and "identical" on consecutive lines. Rehearsing the release beat
  discovering those during one.

## 0.2.1 — 2026-07-29

**Two cap bypasses shipped in 0.2.0. Upgrade.** Both were introduced by the
0.2.0 limiter itself — the release whose entire purpose was to make caps hold —
and both were found by a fact-check pass *after* publishing, not before.

### Fixed

- **Rotating `intent.agentId` reset the cap.** The reservation was scoped to
  `agentId`, a field this project's own threat model
  ([CONTRIBUTING](CONTRIBUTING.md) rule 4, [`types.ts`](packages/guard/src/types.ts))
  states the attacker controls. Reproduced: two guards sharing one limiter,
  `$100` through a `$50/day` cap, by changing one string. The same test with a
  fixed `agentId` correctly denied — which is why the conformance suite missed
  it entirely.

  Reservations are now scoped to **`policy.id`**, which the operator sets. Note
  this also means the pre-0.2.0 behaviour is restored: the old in-memory history
  deliberately *ignored* `agentId` for exactly this reason, and 0.2.0 silently
  regressed a mitigation `SECURITY.md` had claimed since 0.1.0. If you want
  per-agent budgets, derive the scope from an id **you** assign to a trusted
  principal, never from the intent.

- **Reusing an `intent.id` ran the rail again while counting one charge.** A
  replayed reservation returned `ok` and the guard fell through to the executor.
  Reproduced: the same intent id twice ran the rail **twice**, counted once; a
  throwing executor retried eight times ran the rail **eight times** and still
  counted one `$50` charge. That directly contradicted the burn-on-failure
  guarantee 0.2.0 added, which exists so an executor timing out *after* the
  charge lands cannot be retried past the cap.

  A replayed reservation now returns `status: "replayed"` — `executed` if the
  first attempt committed, `unresolved` if it never settled (money may have
  moved; the guard will not guess). When a mandate is present the mandate's
  consume-once registry still decides, because it holds strictly better
  information: the intent digest, so id reuse with *different* money is DENIED
  rather than replayed, and the settled outcome, so a failed attempt replays
  `failed` rather than `unresolved`.

### Changed (breaking, and it is a one-day-old interface)

- `ReserveRequest.agentId` → **`ReserveRequest.scope`**. Any `SpendLimiter` you
  wrote against 0.2.0 needs this rename, and should key on `scope`. The
  Postgres schema column `agent_id` → `scope` with it.
- `ReserveResult` gains `state` on a replay, so the caller can tell "the rail
  ran" from "the rail may have run".
- `GuardResult`'s `replayed` variant has `mandateId` **optional** — an intent id
  can now be replayed by the limiter with no mandate involved.

### Documentation corrections

The same pass found five claims a reader could have disproved:

- **The conformance suites are not published.** `@vaduno/guard` ships only
  `dist/`, yet both suites' own docblocks told you to
  `import … from "@vaduno/guard/test/…"`, CONTRIBUTING repeated it, and
  `@vaduno/postgres@0.2.0`'s README says they "ship with `@vaduno/guard`" —
  that one is immutable on npm now. They are repo test files; copy them or send
  a PR.
- "This project has shipped that bug twice" — written twice, **shipped once**.
  The `maxUses` gate was fixed six days before the first publish.
- "All five packages are versioned together" — six.
- The changelog claimed two breaking minor bumps; there had been one.

Tests 357 → 364, including regression tests for both bypasses.

## 0.2.0 — 2026-07-29

Spend caps now hold across processes. Until this release they did not, and
there was no way to make them.

### Added

- **`SpendLimiter`** — an atomic `reserve` / `commit` / `release` contract where
  every rolling window is evaluated *inside* the reserving call. Ships
  `MemorySpendLimiter` (default, single process) and `FileSpendLimiter`
  (several processes on one box).
- **[`@vaduno/postgres`](packages/postgres)** — `PostgresSpendLimiter` and
  `PostgresConsumeStore`, for caps and mandates that hold across **multiple
  instances**. Verified by both conformance suites against a real Postgres 16
  in CI — 40 tests, no mocks, because the property being tested lives in the
  database. `pg` is an optional peer dependency; `@vaduno/guard` still has zero
  runtime dependencies.
- **A `SpendLimiter` conformance suite** (23 cases per limiter) run against two
  independent handles on one backing store, plus `guard.releaseSpend(intentId)`.
- **`npm run demo:cross-process`** — spawns two real OS processes racing one
  $50/day cap. Shows $100 spent with the per-instance default and exactly $50
  with a shared limiter. Runs in CI on Linux, Windows and macOS and fails the
  build on any overspend.

### Fixed

- **Rolling spend caps did not hold across processes, and could not be made to.**
  `SpendHistory.totalsSince()` is a read-only query, so the guard could only ever
  check-then-act: read totals, execute, append. Two processes both read `$0`,
  both passed a `$50` check, both spent. Pointing that interface at a shared
  database would *not* have fixed it — the race lives in the gap between the read
  and the append, not in where the rows are. The budget check moved inside the
  mutating call, exactly as `maxUses` had to move inside `claim()` when the
  consume store had this same bug one layer down.

### Changed — read this one before upgrading

- **A failed execution now KEEPS its spend counted.** Previously a thrown
  executor freed the entire reserved amount. But a timeout *after* the charge
  landed is indistinguishable from a clean failure, so an executor that failed
  post-charge could be retried past any cap: N timeouts, N real charges, none of
  them counted — and with no mandate configured, nothing else bounded it. The
  amount now stays reserved (counted, but reclaimable). Call
  `guard.releaseSpend(intentId)` when you can prove the rail did not charge; it
  cannot un-count a successful execution, so a mistaken call is safe.
- `policyWindows(policy)` derives rolling windows in one place, so the advisory
  pre-check and the authoritative reserve can never disagree about a cap.
- `FileConsumeStore` now uses the extracted `FileMutex` that `FileSpendLimiter`
  also uses. Same lock, one implementation — two copies of a subtle lock is how
  the two copies drift.
- The release gate discovered packages from a **hardcoded list**, so
  `@vaduno/postgres` would have shipped completely ungated while the gate
  reported success. Now discovered from the filesystem.

Additive otherwise: `history` still works as an advisory fast-fail, and code
that does not pass `limiter` behaves as before — single-process, as documented.

Tests 309 → 357, plus 40 more against real Postgres in CI.

## 0.1.1 — 2026-07-28

No code changed. `dist/` is byte-identical to 0.1.0. This release exists
because the *documentation* shipped inside the packages was wrong in ways a
reader could act on.

### Fixed

- **The quickstart taught the weaker merchant matcher.** `@vaduno/guard`'s
  README showed `merchants: { allow: ["openai", "anthropic", "aws"] }`. A bare
  token matches the **agent-supplied** `merchant.id`, which a compromised agent
  controls; a dotted pattern like `"openai.com"` matches the URL host, which it
  does not. Anyone who copy-pasted the old example got a policy weaker than
  they had reason to expect. The example now uses `["openai.com",
  "anthropic.com", "aws.amazon.com"]`, matching the demos.

- **"Never holds funds or keys" was imprecise everywhere it shipped** — in all
  five package descriptions and in the `@vaduno/guard`, `@vaduno/stripe` and
  `@vaduno/transparency` READMEs, which npm renders as the package pages. The
  accurate claim, which `SECURITY.md` has always made, is no keys **to funds**:
  no custody, no card PANs, no wallet or bank credentials. Mandates are signed
  with an Ed25519 key that belongs to the *issuer* and cannot move money — and a
  guard that only validates and consumes needs nothing but the public half. A
  total compromise of Vaduno still cannot originate a payment.

- **`@vaduno/stripe`'s README claimed the adapter was "test-mode-only".** It has
  never run against Stripe in *any* mode — not test, not live. Nothing in the
  package has contacted `api.stripe.com`; the decision path, signature check and
  deadline are verified against an in-process mock of the
  `issuing_authorization.request` webhook. The README now says so at the top,
  where someone deciding whether to trust it will actually see it.

- **`@vaduno/stripe`'s README told readers to size their handler against a
  2-second deadline.** Stripe's authorization window is ~2s, but the adapter's
  own `decisionTimeoutMs` defaults to **1300ms** so its fail-closed DECLINE
  lands *inside* that window instead of racing it. A handler tuned to 2s would
  be declined by the adapter first.

- **`@vaduno/guard`'s README misstated its own citation.** It read
  "prompt-injection attacks against commerce agents succeed in 86% of
  attempts". [WASP](https://arxiv.org/abs/2504.18575) measures **web** agents,
  reports attacks that ***partially*** succeed, and gives 86% as an ***upper
  bound***. Overstating the threat you exist to mitigate is not a harmless
  error. Corrected to match the root README.

- **`@vaduno/guard`'s README claimed a retry storm runs the rail "exactly
  once".** At most once. A denied or failed intent runs it zero times, and the
  weaker claim is the one that is always true.

- **`@vaduno/guard`'s README never mentioned that spend caps are
  per-instance.** It documented the cross-process `ConsumeStore` requirement
  for consume-once and stopped there, leaving a reader to assume rolling caps
  came along. They do not.

### Changed (repository only — not shipped in any package)

- `vitest` `^2.1.9` → `^3.2.6` across all five packages shipping then (the lockfile resolves
  3.2.7). This cleared **one** critical advisory, GHSA-5xrq-8626-4rwp —
  arbitrary file read/execute when the Vitest UI server is listening, never
  applicable here because the UI is never started. Dependabot counts it once
  per manifest, so it showed as six alerts; it is one advisory. A
  devDependency either way: consumers are unaffected.
- Added a **ConsumeStore conformance suite** (17 cases per store) so a
  Postgres/Redis implementation can be *verified* rather than merely typechecked.
  The interface is satisfied by an implementation that double-spends; that is
  the bug this project shipped once already. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Documented two limits in the README that previously lived only in
  `SECURITY.md`: rolling **spend caps are per-guard-instance and do not hold
  across processes** (only consume-once does, and only with a shared store),
  and the Stripe handler's fail-closed deadline is **1300ms**, not the "2
  seconds" previously claimed.
- Test count 275 → 309.

## 0.1.0 — 2026-07-28

First public release. Five packages:

- **`@vaduno/guard`** — the spend firewall: deterministic policy (rolling
  day/week/month caps, merchant allowlists, velocity limits, approval
  thresholds), signed consume-once mandates with idempotent replay, and a
  hash-chained audit ledger. Zero runtime dependencies.
- **`@vaduno/transparency`** — RFC 9162 Merkle transparency log with inclusion
  and consistency proofs, C2SP `tlog-checkpoint` signed notes, and k-of-n
  witness cosigning for non-equivocation.
- **`@vaduno/revocation`** — enforced kill switch: W3C Bitstring Status List
  credentials, fail-closed revocation checked at authorization time, agent-wide
  kill, and best-effort fan-out to rail-native revocation.
- **`@vaduno/x402`** — HTTP 402 stablecoin rail adapter.
- **`@vaduno/stripe`** — Stripe Issuing adapter; the guard answers
  `issuing_authorization.request` in real time. Never run against Stripe.

Published under the name Vaduno after two earlier names were withdrawn — the
npm name `paygent` was taken, and `swale` collided with a pending USPTO mark in
the exact classes this project occupies. `scripts/check-name.mjs` exists so it
does not happen a third time.
