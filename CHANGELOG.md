# Changelog

All seven packages are versioned together and released as a matched set.

This project is pre-1.0. Under semver, 0.x minor bumps may break the API. Two
have, and each was breaking because the fix for a real security bug required it.
See [`SECURITY.md`](SECURITY.md) for what is and isn't guaranteed.

## Unreleased

### Added

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
