# guarded-signer — the guard in the MANDATORY signing path

`examples/x402-live/pay.mjs` wraps **fetch**: the guard decides whether the
host's `pay()` callback may run. This example moves the guard one layer down,
into the **signer itself** — the shape the shipped Cloudflare Agents SDK x402
client actually accepts (`withX402Client(client, { account })`, where
`account` is the structural type `ClientEvmSigner`: `{ address, signTypedData }`).

```
withX402Client / any x402 client
        │
        ▼
account.signTypedData({ domain, types, primaryType, message })
        │                     ▲
        │   GuardedAccount    │  the ONLY door to the key
        │   1. snapshot the request, then extract payee /
        │      amount / asset / chain from the snapshot
        │   2. refuse anything the SIGNATURE does not commit to
        │   3. guard.authorize() — policy + atomic spend
        │      limiter + hash-chained audit ledger
        │   4. allow → delegate to the real account
        │      deny  → throw. No signature exists.
        ▼
real viem account (closure-only; never a property)
```

## What it is

A ~1400-line viem-compatible account whose only working capability is a
policy-gated `signTypedData`. Every payment authorization an x402 client can
produce — EIP-3009, Permit2, v1 and v2 — terminates in that one method, so
policy runs before any signature exists, and a denial means no signature exists
at all. A payment that was never signed cannot be settled by anyone, anywhere.

That is the difference between a firewall and telemetry: the SDK's optional
`confirmationCallback` can be set to `null` and skipped; the signer cannot,
because the signer is where signatures come from.

**Run it** (reuses the `x402-live` wallet, Base Sepolia testnet only):

```
node examples/guarded-signer/pay.mjs
```

**Run the offline regression suite** (no wallet, no network — a fresh throwaway
key and an in-memory ledger):

```
node examples/guarded-signer/regress-defects.mjs      # 37 checks
```

Every check in it was observed FAILING against the unfixed wrapper before the
fix was written. The adversarial harnesses that found the defects are here too
and are the reproductions: `attack-run.mjs`, `attack-semantic.mjs`,
`attack-fresh.mjs`, `attack-a…f`, `attack-9-commitment.mjs`, `probe-1…8`,
`_probe-new.mjs`.

`attack-9-commitment.mjs` is the one that takes **viem itself** as the oracle
rather than reasoning about `types`: for every shape the wrapper agrees to
sign, it perturbs each leaf of the message and measures which ones move
`hashTypedData`. A field is committed iff changing it changes the digest —
nothing else counts.
`_verify-invariant.mjs` is the independent verifier: it interposes on both the
guard and the key and asserts that every signature returned is over bytes the
guard was asked about and approved.

**A harness must assert the invariant, not the behaviour of the day it was
written.** Two here had rotted into the opposite. `attack-run.mjs`'s ATTACK 4/6
inferred "policy was skipped" from `sig2 !== sig1`, which stopped being valid
once the intent id became the digest — a different signature is now the correct
outcome, so it reported `bypassFound: true` against correct code; it now reads
the ledger for a `policy_decision` row under the exact digest. And
`_verify-invariant.mjs`'s V8 asserted `pass = sig !== null` for
"host-pattern allowlist still authorizes an arbitrary payee" — a test that goes
green when the hole is open — and, once the constructor diagnostic landed, threw
during setup and took the whole file's summary with it. A harness that cries
wolf against correct code is worse than no harness, and one that certifies a
closed hole is worse than that.

**Verify a settlement independently** — decodes the on-chain transaction input,
recomputes the EIP-712 digest from the token's own `DOMAIN_SEPARATOR()`,
recovers the signer, and checks the ledger row is keyed on that exact digest:

```
node examples/guarded-signer/verify-ledger-binding.mjs
```

Most recently verified settlement — Base Sepolia, `0.01 USDC` to x402.org's
`payTo`, through the digest-bound wrapper:

```
tx      0x8f47f9f420042bdbca67e30ba260c40bf800b0feb1de6fcaae0780a7ddaa74e5
block   45127550            receipt status: success
log     Transfer 10000 units  0xA7690bB9…8fA7 -> 0x209693Bc…287C  (USDC 0x036CbD53…CF7e)
digest  recovers to the payer, and the ledger row is keyed on that exact digest
payer   39.840000 -> 39.830000 USDC  (down exactly 0.010000)
```

Those figures are read back from the chain by
`verify-onchain.mjs receipt <tx> <expectedBeforeAtomic>` and
`verify-ledger-binding.mjs`, not reported by the script that made the payment.

**The script itself reports what moved from the settlement transaction's own
Transfer log, never from a balance read**, and that is not fussiness. Three
balance-based versions each printed `spent: 0.000000 USDC` for a payment that
had genuinely settled: reading straight after the 200 (which means the
facilitator *accepted* the authorization, not that the transfer landed);
reading `latest` after waiting for the receipt (the public RPC is
load-balanced, so the node answering `balanceOf` was behind the node that
answered the receipt); and pinning the read to the settlement block (that node
did not have the block yet — `block not found`). A report that *understates* a
payment is exactly as wrong as one that overstates it.

## The invariant

**Sign exactly the bytes you policed, and police only facts the bytes carry.**
Everything below is a consequence of it.

**The request is snapshotted before it is read, and the snapshot is what gets
signed.** `structuredClone` runs at the top of `signTypedData`, before a single
field is inspected, and the clone is handed to the real account. Without it the
wrapper read the caller's live object during the checks and passed *that same
object* to the key several awaits later — a time-of-check/time-of-use gap with
two working exploits: accessors returning a benign payee during the check and a
hostile one at signing, and (needing no accessors at all) a caller that simply
does not `await` and mutates its own object across the gap. Both produced a
valid signature for 100 USDC to an attacker while the hash-chained ledger
certified 0.01 USDC to the legitimate seller — an audit trail that is
cryptographically intact and materially false, which is worse than no audit
trail at all.

The same rule applies to the `resolveAuthCapture` declaration, which is also
snapshotted: it is read once for the nonce re-derivation and again to build
`merchant.id`, and a declaration whose getters returned different values on
those two reads passed the cryptographic check as the attacker and was policed
as the allowlisted seller.

**A fact the signature does not commit to is refused, not policed.** `message`
is a plain object; the EIP-712 digest covers only the fields listed in
`types[primaryType]`, in that order, with those types. Reading `message.to` by
name while `types` omits `to` yields a signature over a struct with **no
recipient**, while the guard is told the payee is an allowlisted seller and the
ledger certifies it. The wrapper now checks that the type declaration commits to
every field it relies on — and one level up, that the domain still commits to
`chainId` (the policed network) and `verifyingContract` (the asset, hence the
**decimals**). Narrowing the domain was a walk-around of the decimals fix: the
same signature valid at a 2-decimal dollar token is worth $100.00 while the
guard counts $0.01.

That domain check used to run **only** when the caller declared
`types.EIP712Domain` explicitly. The premise behind the exemption — "viem infers
the domain type from whichever fields are *present*, so presence is commitment"
— is false, and it made this file violate the very principle it exists to state.
`getTypesForEIP712Domain()` includes `chainId` only when
`typeof domain.chainId` is `"number"` or `"bigint"`, while the wrapper's
`asChainId` deliberately accepts decimal **strings**. So
`domain.chainId: "84532"` was present, was read, was policed as
`network: eip155:84532`, selected the `(chainId, asset)` registry row that
supplies the decimals — and was not in the signed bytes at all. Measured:
`digest(chainId="84532") === digest(chainId="1")`, and one signature recovers to
the signer under every chain framing, so the same bytes are valid on a chain
whose registry row calls the token 2-decimal. The decimals defect walking around
again, through the inferred path this time.

The wrapper's own evidence proved it and nothing consulted it: the ledger row
recorded `committed.domain = [name, version, verifyingContract]` while
`intent.network` said `eip155:84532`. The gate now reads **that same
derivation** — `committedFieldSet(typed).domain` — on both paths, which makes
the recorded evidence load-bearing rather than decorative and covers the
explicit and inferred cases with one check. Hardening `asChainId` to reject
strings would be defence in depth, not this fix, and is deliberately not done:
it would turn a precise `TYPED_DATA_NOT_COMMITTED` into a generic
`UNRECOGNIZED_TYPED_DATA` and send the operator hunting an unsupported payment
shape instead of an uncommitted field.

**Honest reachability:** the pristine shipped `@x402/evm` path does *not* trigger
this — `getEvmChainId()` does `parseInt()` and yields a number, so an ordinary
SDK-built request is unaffected and still signs. It fires for a caller handing
the wrapper a JSON-sourced or hand-built request, which is exactly the
untrusted-input threat model the snapshot and these commitment checks exist for.
The `networks.allow` gate itself was never broken by this: a decimal-string
`chainId` naming a forbidden chain was still refused `NETWORK_NOT_ALLOWED`. What
was broken is the premise underneath it — the gated chain was unsigned, so the
same bytes were valid on every chain.

**Amounts are scaled from token atomic units into the policy currency's minor
units.** The registry's `decimals` is *used*, not just recorded:
`currencyDecimals` states the policy currency's granularity and each token's
atomic value is converted into it. Downscaling rounds **up**, so the guard can
over-count by at most one minor unit and can never under-count. Treating atomic
units as minor units unconditionally is how 10,000 units of a 2-decimal dollar
token (GUSD and EURS are real ones) — $100.00 — passed a cap that thought it was
seeing $0.01. A currency whose registered assets *disagree* about decimals is
refused rather than guessed at. No floats anywhere; all scaling is `bigint`.
A scaled amount past `Number.MAX_SAFE_INTEGER` cannot be handed to the policy
engine at all; it is refused `AMOUNT_NOT_REPRESENTABLE` before policy runs,
naming *both* things that can cause it (an absurd amount, or a
`currencyDecimals` finer than the payments denominated in it) because from one
request the wrapper genuinely cannot tell which. It used to collapse to the
fail-closed `0` and be denied `INVALID_AMOUNT` — the right verdict reached by a
lie, which sent the reader to audit the payment when the cause was often the
configuration.

**The digest is bound into the record, and so is the set of fields it covers.**
`metadata.digest` says *these bytes were policed*; `metadata.committed` says
*which facts those bytes carry* — the domain fields (taken from viem's own
inference, so it is the same answer `hashTypedData` used) and every struct
reachable from `primaryType`. That second question is the one this whole family
of defects turned on, and a digest alone cannot answer it after the fact: a
`TransferWithAuthorization` whose `types` omits `to` hashes to a perfectly valid
digest. Such a request is refused today, but "refused today" is a property of
today's code and the ledger outlives it. An archive that cannot be re-checked
has to be trusted instead.

Struct references in that record resolve **exactly as viem resolves them**:
`encodeField` tests the FULL declared type name against `types` before it looks
at an array suffix, so a field declared `Witness[]` hashes against
`types["Witness[]"]` when that key exists, and the brackets come off only as a
fallback. Stripping them first — which the recorder originally did — wrote a
*different* struct's field list into the row when both keys were declared, and
omitted the witness entirely when only the bracketed one was. That was never a
signing hole (the payee check passes the declared type name through verbatim),
but it is precisely the row an auditor would re-check, and it was answering
with a field list the digest does not cover.

The *first* attempt at that fix then introduced a worse one. Recursing on
`type.slice(0, open)` allocates a fresh string per array level, so a
counterparty declaring a type with 100,000 array levels made the wrapper
allocate O(n²) characters and die with `FATAL ERROR: Reached heap limit` —
while viem hashed the identical input in 37 ms. A crash is strictly worse than
a refusal here, because this process is the one writing the ledger. Candidate
names are now tested by length + prefix comparison against the declared keys,
which materialises nothing, and nesting past 32 levels is **refused**
(`COMMITMENT_RECORD_UNCOMPUTABLE`) rather than left unresolved — an unresolved
reference would silently omit a struct, which is the defect being fixed. That
refusal is its own code because the digest in that case is perfectly
computable; reporting it as `DIGEST_UNCOMPUTABLE` would be a false diagnosis in
a file whose whole subject is refusals that point at the wrong cause.

**The walker itself used to do exactly what its sibling refuses to do.** Its
depth guard was `if (depth > 32 || Object.hasOwn(struct, name)) return` — a
*silent* drop. With 40 distinct nested structs viem hashes all 40 (every one is
in the typehash string) while `committed.struct` recorded 33 and said nothing
about the other 8; at 64 and at 300 it recorded the same 33, so there was no
upper bound and no marker. An evidence record that silently omits part of what
was signed is worse than one that refuses to be computed, because the omission
is indistinguishable from the struct not existing. The guard now **throws**, and
the caller turns it into the same audited `COMMITMENT_RECORD_UNCOMPUTABLE`
refusal its sibling produces. The already-visited test runs *first*, so a
self-referential or mutually recursive declaration still terminates there and
keeps its own (correct, different) diagnosis: viem cannot hash those at all, and
they are refused `DIGEST_UNCOMPUTABLE` before the record is ever attempted.

**Idempotency comes from the EIP-712 digest.** The intent id is
`sig:` + `hashTypedData(request)` — a function of every byte that will be
signed. Two calls collide on an id if and only if they would produce the same
signature, so the guard's *replay* branch can only ever re-issue a signature
that was already policed and counted. The previous id was a hand-written list of
fields, and any such list is a list of the bytes an attacker may vary for free:
`domain.name`/`version`/`salt` and the `types` definition were all outside it,
as were every Permit2 witness field except `to`, and validity windows written in
hex stringified to `"null"`.

**An authorization that cannot settle cannot burn budget.** `message.from` must
be this wallet, and an already-expired `validBefore` is refused. Neither could
ever settle on-chain (EIP-3009 requires `ecrecover(digest) === from`), but both
used to *sign* and consume the daily cap, which the ledger then recorded as real
spend — a free denial-of-service against the budget. Optional
`maxValiditySeconds` caps how long an authorization may stay live.

**Permit2 polices `spender`, not just the witness.** `spender` is the address
the signature empowers to move the tokens; `witness.to` is a hint the downstream
contract may or may not honour. Policing the witness while ignoring the spender
let a signature naming an allowlisted seller grant an arbitrary spender the
right to move the funds anywhere. Spenders must be declared via
`permit2Spenders`; undeclared ones are refused.

**Collector-aliased schemes are refused unless the real payee can be proven.**
`@x402/evm`'s auth-capture scheme signs an EIP-3009 authorization whose `to` is
the hardcoded `EIP3009_TOKEN_COLLECTOR_ADDRESS`, never the merchant; the true
receiver, capture operator, fee recipient and `maxFeeBps` are committed only
inside the opaque `nonce`. A merchant allowlist keyed on `to` therefore polices
the *collector*, and allowlisting it to use the scheme authorises every payee in
it at once. Such a request is **denied by default**
(`AUTH_CAPTURE_UNPOLICEABLE`). A caller that owns the `PaymentInfo` may declare
it through `resolveAuthCapture`; the wrapper re-derives the nonce from that
declaration and refuses unless the derivation reproduces the nonce being signed,
so the declaration *tells* the guard the payee rather than choosing one.

**Host patterns are not a payee control here, so the URL is kept out of
policy.** `merchant.url` is deliberately never populated from the caller's
`merchantUrl`. A host pattern in `merchants.allow` is matched against
`merchant.url`; at fetch level that URL is derived per payment from where the
request is going, but here the only URL available is a constant fixed at wrap
time, identical for every payment this account will ever sign. So
`allow: ["host:x402.org"]` matched for *any* payee and authorized a transfer to
an arbitrary address while the policy read as though it named a merchant.
Withholding the URL is the structural fix: a host-form ALLOW pattern then cannot
match (denied) and a host-form BLOCK pattern makes `evaluatePolicy` refuse
outright. Both fail closed. The URL is still recorded as
`metadata.merchantUrl` — evidence, not a policy input. **At signer level the
`id:` form is the control that binds the payee, and it binds it
cryptographically.**

**Every refusal is written to the ledger, including the local ones.** Refusals
the wrapper decides itself used to append *zero* ledger rows while cap and
merchant denials appended two each — so for a project positioning on evidence,
the most suspicious requests were exactly the ones that vanished. They now go
through `guard.authorize()` with an amount the policy engine rejects
unconditionally, so a refusal row is indistinguishable in shape and hashing from
a policy denial.

**Every ungated capability is stubbed, not passed through.** `signTransaction`,
`signMessage`, `sign`, `signAuthorization` exist but throw. This is
load-bearing: `@x402/evm`'s gas-sponsoring extension will, if `signTransaction`
is usable, sign an **unlimited** (`maxUint256`) ERC-20 approval — a wrapper that
gates typed data while forwarding raw transaction signing is a firewall with a
service door.

**The real account is unreachable through the wrapper.** It lives only in the
factory closure; the returned object is frozen and holds no property that
references it.

## What this does NOT do

This section is the point of the document. This project treats an unsupported
claim as a defect, and the honest limits are load-bearing.

**It is mandatory once injected — it is not impossible to omit.** Nothing in the
SDK forces the wrapper. Every Cloudflare example passes
`privateKeyToAccount(env.KEY)` directly, and swapping in a `GuardedAccount` is a
developer's choice. It is one line, but it is a choice, and a developer who
never makes it gets none of this. "The guard is in the mandatory signing path"
is a claim about *this object*, not about the ecosystem.

**Full closure needs the raw key kept where only the wrapper reaches it.** In
this demo the key is read from a file in the same process, so any code in the
process can read that file and sign around the wrapper entirely. The wrapper
makes the guard mandatory for *every signature this object can produce*; making
it mandatory for the deployment is a **key-custody property** — the raw key must
live in a separate process, Durable Object, or KMS whose sole exposed API is the
gated `signTypedData`. This example demonstrates the seam; it cannot enforce the
custody around it. Treat the single-process version as a development
convenience, not the security boundary.

**The chain gate and the validity ceiling are opt-in.** The intent carries
`network: eip155:<chainId>`, so `policy.networks.allow` can gate the chain — but
`evaluatePolicy` only evaluates that rule when the policy declares it. A policy
with no `networks` block does not constrain the chain at all, and the asset
registry (caller configuration, not policy) is then the only chain gate: any
registered `(chainId, asset)` pair is signable under the same limits. Likewise
`maxValiditySeconds` is unset by default, so a never-expiring authorization
signs. Both are enforced when declared and unenforced when not; neither is a
default.

**Spend is counted at signing time, not at settlement.** The guard has no notion
of *outstanding* authorizations. A signed EIP-3009 authorization is a bearer
instrument until `validBefore`, counted once against today's cap; the cap then
resets while the instrument stays live. N days of signing can leave N × the
daily cap simultaneously redeemable. `maxValiditySeconds` bounds how long that
window is, but does not close it.

**It cannot bind the resource being paid for.** The typed data does not carry
the URL, so the signer binds the **recipient, amount, asset and chain** — not
what was purchased. Resource-level policy needs a layer above this one.

**It cannot stop an in-flight settlement.** Once a signed authorization leaves
the process, Vaduno cannot pause, redirect or claw it back. This is by design:
the guard holds signing *capability* behind policy, and never holds funds.

**Refusals are an unbounded, counterparty-driven writer into the ledger.** Every
local refusal now appends rows, each with a fresh id, so identical junk requests
do not coalesce and attacker-controlled strings are echoed into the refusal
message. Against a `JsonlLedgerStore` that is unbounded disk driven by whoever
is calling `signTypedData`. Truncating echoed strings and coalescing identical
refusals is not implemented.

**`structuredClone` refuses inputs the raw viem account would sign.** A request
carrying any function-valued property, or wrapped in a `Proxy`, is refused
`TYPED_DATA_NOT_SERIALIZABLE`. This fails closed, so it is an availability
limit rather than a hole — but a Proxy is not exotic (instrumentation wrappers,
reactive stores, test doubles), and this wrapper's whole purpose is to sit under
someone else's SDK.

**The evidence record's depth ceiling refuses shapes viem would sign.** A chain
of more than 32 distinct nested struct references, or a type name with more than
32 array levels, is refused `COMMITMENT_RECORD_UNCOMPUTABLE` even though
`hashTypedData` handles it. This is a deliberate availability limit rather than
a hole — the alternative measured here was recording a partial set with no
marker, and the alternative measured for the array case was killing the process
that writes the ledger — but no real payment shape comes near 32, so a
counterparty that hits it is telling you something. The ceiling is a constant in
the file, not a policy input.

**The auth-capture escape hatch covers one of the two shipped flavours.**
`resolveAuthCapture` rescues the EIP-3009 flavour. The permit2 flavour
(`extra.assetTransferMethod: "permit2"`) signs `primaryType:
"PermitTransferFrom"` — no witness, no recipient field anywhere in the signed
struct — with `PERMIT2_TOKEN_COLLECTOR_ADDRESS` as `spender`. There is nothing
in those bytes a declaration could be verified against, so it is not rescuable
and a resolver does not change the outcome. It is now refused by name
(`AUTH_CAPTURE_FLAVOUR_UNSUPPORTED`), which is what makes the PERMIT2 entry in
the default collector list a control rather than unreachable code: it used to
fall through to the generic `UNRECOGNIZED_TYPED_DATA`, telling an operator their
own SDK had produced an unknown shape and pointing at nothing. Fails closed
either way; still a completeness gap, and naming it does not close it.

**The auth-capture nonce derivation is pinned to constants, not to the package.**
`PAYMENT_INFO_TYPEHASH` and the escrow address are a hand-port of `@x402/evm`'s
`computePayerAgnosticPaymentInfoHash` with no version pin or runtime cross-check.
If that package changes the `PaymentInfo` struct or the escrow, the derivation
stops reproducing the nonce and every declared auth-capture payment is refused
`AUTH_CAPTURE_MISMATCH`. That fails closed, so it is a maintenance hazard rather
than a hole — but only the regression suite detects the drift, and only when
someone runs it.

## Safety rails in this example

- Base Sepolia (chain 84532) **only**. The asset registry contains only Base
  Sepolia USDC, so any other chain or token is refused before a signature
  exists. Never mainnet.
- The script aborts on any requirement over 0.10 USDC; the guard's policy caps
  again at 0.05 per transaction and 0.20 per day.
- The wallet is a throwaway funded with worthless faucet USDC. The offline
  suites generate a fresh random key and broadcast nothing.
