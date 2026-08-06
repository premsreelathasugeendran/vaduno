# @vaduno/cloudflare

The [Cloudflare Agents SDK](https://developers.cloudflare.com/agents/)'s x402
payments client holds a raw private key — its own docs say
`privateKeyToAccount(env.PRIVATE_KEY)` — and pays automatically whenever a paid
tool asks. The shipped controls are a per-payment ceiling (`maxPaymentValue`,
default 0.10 USDC) and an optional confirmation callback that, when omitted,
approves everything. There is no cumulative budget, no merchant allowlist, and
no audit trail of what was signed or refused. An agent that is tricked ten
times pays ten times, to anyone, and leaves no record.

This package is a spend firewall for that client. Wrap your signing account
once, and Vaduno policy — caps, merchant allowlists, chain gates, and a
tamper-evident audit ledger — runs **inside `signTypedData`**, before any
payment signature exists. A denied payment never has a signature, and a
payment that was never signed cannot be settled by anyone, anywhere.

Part of [Vaduno](https://github.com/premsreelathasugeendran/vaduno) —
non-custodial by construction. This package never holds funds and never holds
keys to funds: the account object you pass in stays yours, held only in a
closure, and the only thing Vaduno adds is the policy gate in front of it.

```bash
npm install @vaduno/cloudflare @vaduno/guard
```

## The one-line integration

The Agents SDK's `withX402Client(client, { account })` takes an
`account: ClientEvmSigner` — a structural type from `@x402/evm` whose required
surface is exactly `{ address, signTypedData }`. Every payment authorization
the SDK can produce (EIP-3009, Permit2, x402 v1 and v2) terminates in that one
`signTypedData` call. So the integration is: pass the guarded signer where the
raw account went.

```ts
import { privateKeyToAccount } from "viem/accounts";
import { withX402Client } from "agents/x402";
import { guardedSigner } from "@vaduno/cloudflare";
import { AuditLedger, MemoryLedgerStore, MemorySpendLimiter, VadunoGuard } from "@vaduno/guard";

const guard = new VadunoGuard({
  policy: {
    id: "my-agent",
    version: 1,
    currency: "USDC",                                     // minor units below are USDC atomic units
    limits: { perTransactionMinor: 50_000, perDayMinor: 200_000 },   // 0.05 / 0.20 USDC
    merchants: { allow: ["id:0x209693bc6afc0c5328ba36faf03c514ef312287c"] },
    networks: { allow: ["eip155:84532"] },
  },
  ledger: new AuditLedger(new MemoryLedgerStore()),
  limiter: new MemorySpendLimiter(),
});

const account = guardedSigner({
  account: privateKeyToAccount(env.PRIVATE_KEY),          // the host's key, never ours
  guard,
  assets: [
    {
      network: "eip155:84532",                            // CAIP-2, same shape as @vaduno/x402's AssetInfo
      asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      symbol: "USDC",
      decimals: 6,
    },
  ],
});

const client = withX402Client(mcpClient, { account });    // Cloudflare's own call, unchanged
```

That swap is the entire diff. The SDK's optional `confirmationCallback` can be
set to `null` and skipped; the signer cannot, because the signer is where
signatures come from. That is the difference between a firewall and telemetry.

## What it enforces, per signature

- **Sign exactly the bytes you policed.** The request is snapshotted
  (`structuredClone`) before a single field is read, and the snapshot is what
  gets policed *and* signed. Getter games and mutate-across-the-await games
  produce either a refusal or a signature over the vetted bytes — never a
  signature over bytes policy did not see.
- **Police only facts the signature carries.** The EIP-712 digest covers only
  the fields listed in `types`; a request whose type declaration omits a fact
  the policy needs (the payee, the amount, the chain, the token) is refused
  `TYPED_DATA_NOT_COMMITTED` rather than policed off the message object. This
  includes viem's *inferred* domain: `chainId: "84532"` (a string) is present
  and readable but not in the signed bytes, and is refused.
- **Default-deny on shape.** Only EIP-3009
  `TransferWithAuthorization`/`ReceiveWithAuthorization` and Permit2
  `PermitWitnessTransferFrom` are recognized payment shapes. EIP-2612 `Permit`
  and any other approval shape is open-ended spending power, not a bounded
  payment, and is refused.
- **Amounts scale by trusted decimals, rounding up.** The registry's
  `decimals` converts token atomic units into policy minor units; downscaling
  rounds up so the guard can over-count by at most one minor unit and can
  never under-count. A currency whose registered assets disagree about
  decimals is refused, never guessed at.
- **The payee, asset, chain, payer and validity window are policed.**
  `merchant.id` is the payee from the signed bytes; `network` is
  `eip155:<chainId>` so `policy.networks.allow` can gate the chain; a payer
  that is not this wallet, or an already-expired authorization, is refused
  (either would burn budget without ever settling). `maxValiditySeconds`
  optionally caps how long an authorization stays live.
- **Permit2 polices `spender`.** The spender is what the signature empowers to
  move tokens; the witness recipient is a hint. Spenders must be declared via
  `permit2Spenders`.
- **Collector-aliased auth-capture is refused unless proven.** `@x402/evm`'s
  auth-capture scheme signs `to = <token collector>`, never the merchant; the
  real payee lives inside the opaque nonce. Such requests are refused by
  default. A caller that owns the `PaymentInfo` may declare it via
  `resolveAuthCapture`; the wrapper re-derives the nonce from the declaration
  and refuses unless it reproduces the nonce being signed — the declaration
  *tells* the guard the payee, it cannot choose one.
- **Every other capability throws.** `signTransaction`, `signMessage`, `sign`,
  and any other function on the wrapped account become audited throwing stubs.
  `signTransaction` in particular is `@x402/evm`'s gas-sponsoring path that
  signs an **unlimited** (`maxUint256`) ERC-20 approval; a wrapper that gated
  typed data while forwarding it would be a firewall with a service door.
- **Every refusal is written to the ledger** — including the local ones
  (unknown shapes, disabled capabilities), routed through `guard.authorize()`
  with an amount the policy engine denies unconditionally, so a refusal row is
  indistinguishable in shape and hashing from a policy denial. The signed
  path's row records the EIP-712 digest *and* the set of fields it commits to,
  so the evidence can be re-checked after the fact.
- **Idempotent retries.** The intent id is `sig:` + the EIP-712 digest, so an
  SDK retry of byte-identical bytes replays the already-counted authorization
  instead of double-counting, and nothing else can collide with it.

## What this does NOT do

This project treats an unsupported claim as a defect; these limits are
load-bearing.

- **It is mandatory once injected — it is not impossible to omit.** Nothing in
  the SDK forces the wrapper; swapping it in is a developer's choice. "The
  guard is in the mandatory signing path" is a claim about *this object*, not
  about the ecosystem.
- **Full closure needs key custody.** If other code in the same environment
  can read the raw key, it can sign around any wrapper. The wrapper makes the
  guard mandatory for every signature *this object* can produce; making it
  mandatory for the deployment means keeping the raw key where only the
  wrapper reaches it — a separate process, a Durable Object whose only
  exposed API is the gated `signTypedData`, or a KMS.
- **The chain gate and the validity ceiling are opt-in.** A policy with no
  `networks` block does not constrain the chain (the asset registry is caller
  config, not policy), and `maxValiditySeconds` is unset by default.
- **Spend is counted at signing time.** A signed EIP-3009 authorization is a
  bearer instrument until `validBefore`, counted once against the day it was
  signed; the cap then resets while the instrument stays live. N days of
  signing can leave N × the daily cap simultaneously redeemable.
- **It cannot bind the resource being paid for.** The typed data does not
  carry a URL, so the signer binds recipient, amount, asset and chain — not
  what was purchased. That is also why `merchantUrl` is recorded as evidence
  but never used as a policy input: at signer level a host pattern would match
  for every payee. Use the `id:` (payee-address) form in `merchants.allow`.
- **It cannot stop an in-flight settlement.** Once a signed authorization
  leaves the process, Vaduno cannot pause or claw it back. By design: the
  guard gates signing *capability* and never holds funds.
- **`structuredClone` refuses inputs a raw account would sign** — requests
  carrying functions or wrapped in a `Proxy` are refused
  `TYPED_DATA_NOT_SERIALIZABLE`. Fails closed; an availability limit, not a
  hole.
- **The auth-capture escape hatch covers one of the two shipped flavours.**
  The permit2 flavour signs a struct with no recipient anywhere in the signed
  bytes; there is nothing a declaration could be verified against, so it is
  refused by name (`AUTH_CAPTURE_FLAVOUR_UNSUPPORTED`) and a resolver does not
  change that.
- **The auth-capture nonce derivation is pinned to constants** (the
  `PaymentInfo` typehash and escrow address of `@x402/evm` 2.21.0), with the
  test suite cross-checking against a genuine run of the shipped scheme. If
  upstream changes the struct, declared auth-capture payments start failing
  `AUTH_CAPTURE_MISMATCH` — closed, but loudly.

## Options

| Option | Required | What it does |
| --- | --- | --- |
| `account` | yes | The real viem account (`privateKeyToAccount(...)` output fits as-is). Held in closure; never exposed. |
| `guard` | yes | A `VadunoGuard` (or anything forwarding `authorize`/`settle`/`releaseSpend`). |
| `assets` | yes | Trusted `(network, asset) → symbol/decimals` registry, CAIP-2 `eip155:` networks only. Unregistered pairs are refused via currency mismatch. |
| `agentId` | no | Recorded on every intent. Default `"cloudflare-agent"`. |
| `currencyDecimals` | no | The policy currency's minor-unit decimals. Derived from the registry when unambiguous; ambiguity refuses. |
| `maxValiditySeconds` | no | Refuse authorizations valid longer than this. |
| `permit2Spenders` | no | Permit2 spenders this signer may empower. Default: none (all Permit2 refused). |
| `resolveAuthCapture` | no | Declare the `PaymentInfo` behind a collector-aliased authorization; verified by nonce re-derivation. |
| `authCaptureCollectors` | no | Override the known token-collector addresses. |
| `merchantUrl` | no | Evidence only (`metadata.merchantUrl`); never a policy input. Host-form allow patterns plus a `merchantUrl` throw at construction. |

## Dependencies, honestly

- **`@vaduno/guard`** is the only runtime dependency, and it has zero runtime
  dependencies of its own — that property is load-bearing for the supply-chain
  story, and the workspace pins it in a test
  (`packages/guard/test/dependency-freeze.test.ts` freezes this package's
  runtime dependencies to exactly `@vaduno/guard` and its peers to `viem`, so
  adding a dependency fails the suite).
- **`viem` is a peerDependency**, not a dependency. This package needs
  `hashTypedData` (the digest is the intent id), viem's own
  `getTypesForEIP712Domain` (so the commitment gate uses the *same* domain
  inference the hash used, never a second opinion), and
  `encodeAbiParameters`/`keccak256` for the auth-capture nonce re-derivation.
  Every consumer of the Agents SDK's x402 client already has viem — declaring
  it as a peer means your existing copy is used, no second copy is smuggled in,
  and version skew between what you sign with and what this package hashes
  with cannot exist.
- **`@x402/evm` and `agents` are devDependencies only**, used to typecheck the
  returned signer against the *real* `ClientEvmSigner` export and the real
  `withX402Client` option type, and to run the genuine `AuthCaptureEvmScheme`
  in tests. An upstream shape change breaks this package's build, not your
  runtime.
- No Node-only APIs: refusal ids use Web Crypto (`globalThis.crypto`) with a
  non-cryptographic fallback, so there is no `node:` import anywhere in the
  runtime path.

## Where this came from

This package is the productionized port of the `guarded-signer` prototype in
the Vaduno repository (`examples/guarded-signer/`), which went through five
adversarial review rounds (20 confirmed defects, each fix proven by planting
the defect first) and through which real payments settled on Base Sepolia,
each verified by decoding the USDC `Transfer` log on-chain. The port's test
suite re-proves each preserved property the same way: every security test was
first run against a deliberately broken build and observed failing.

Evidence, not adjectives — Base Sepolia transactions you can check yourself:

- [`0x8f47f9…74e5`](https://sepolia.basescan.org/tx/0x8f47f9f420042bdbca67e30ba260c40bf800b0feb1de6fcaae0780a7ddaa74e5)
  — 0.01 USDC through the prototype wrapper; the transaction input decoded, the
  EIP-712 digest recomputed from the token's own `DOMAIN_SEPARATOR()`, the
  signer recovered, and the ledger row keyed on that exact digest
  (`examples/guarded-signer/verify-ledger-binding.mjs`).
- [`0x2936e9…e402`](https://sepolia.basescan.org/tx/0x2936e9fb85bf9f8cf3bd4db48531bf3960684c11df15597d706753059428e402)
  and
  [`0xdda635…f156`](https://sepolia.basescan.org/tx/0xdda635b45a34e78b49ee806488f8831b534d2b411b2b623469c531e02faf6156)
  — 0.01 USDC each through **this package's packaged `dist`** (the `npm pack`
  tarball installed into a clean project outside the workspace), with the deny
  paths exercised in the same runs: a non-allowlisted payee and an over-cap
  amount both refused with no signature produced.

Testnet caveat: those settlements are Base Sepolia (chain 84532) faucet USDC.
No mainnet payment has been made through this code.

## License

MIT
