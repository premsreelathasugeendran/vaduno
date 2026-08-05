# @vaduno/x402

> ### ⚠️ Experimental — never run against a real x402 server
>
> This adapter implements x402 **v1 and v2** (the HTTP transport). It has
> **never run against a live x402 server or facilitator**. The demo and every
> test mock both the server and the payer in-process — the v2 suite includes
> the spec's own wire examples as frozen conformance vectors
> ([`spec/vectors/x402-http-v2.json`](https://github.com/premsreelathasugeendran/vaduno/blob/master/spec/vectors/x402-http-v2.json)) —
> so what is verified is that the code agrees with the specification's text
> and examples, **not** that it interoperates with anything deployed. Treat it
> as a reference implementation, exactly like the Stripe adapter's caveat.

**Policy + audit for [x402](https://www.x402.org/) stablecoin payments.**

x402 revives HTTP `402 Payment Required`: a server answers with a price, your agent pays, and retries. This package wraps that flow so every payment passes a [`@vaduno/guard`](https://www.npmjs.com/package/@vaduno/guard) spend firewall first, and lands in a tamper-evident audit ledger.

**Vaduno never sees your keys.** You supply the signer; the guard only decides whether it may run. That holds for both protocol versions — v2 adds no signing on Vaduno's side (the v2 PaymentPayload, and any sign-in-with-x identity challenge, are your payer's to build).

```bash
npm install @vaduno/x402 @vaduno/guard
```

## Use it like `fetch`

```ts
import { createX402Fetch } from "@vaduno/x402";

const fetchWithPay = createX402Fetch({
  guard,                                   // your VadunoGuard
  agentId: "researcher-agent-1",
  pay: (req) => myWallet.signX402(req),    // v1 signer — keys stay yours
  v2: {
    // v2 is OPT-IN. Without this block, a v2 server (PAYMENT-REQUIRED
    // header) is refused with V2_NOT_CONFIGURED and nothing is paid.
    pay: (req, ctx) => myWallet.signX402V2(req, ctx),
  },
  assets: [                                // bind spend to the REAL token, not a label
    // v1 names and v2 CAIP-2 ids are SEPARATE keys — author both if you serve both.
    { network: "base",        asset: "0x833589...2913", symbol: "USDC", decimals: 6 },
    { network: "eip155:8453", asset: "0x833589...2913", symbol: "USDC", decimals: 6 },
  ],
});

// 402s are paid under policy; everything else passes straight through.
const res = await fetchWithPay("https://api.example.com/premium");
```

## Which protocol version runs, exactly

Version routing is per-response, total, and single-carrier:

- **`PAYMENT-REQUIRED` header present on the 402 → v2.** The header (base64
  JSON, size-capped) is parsed; the response **body is never read** — so a
  server cannot present one price in a v1 body and another in the v2 header
  and have different layers read different carriers. The paid retry sends
  `PAYMENT-SIGNATURE`; settlement is read from `PAYMENT-RESPONSE` (including
  the specced failure form, `402` + `{success: false}`).
- **No header → v1.** The JSON body is parsed exactly as before.
- **`x402Version` is checked totally.** On the body carrier only absent
  (back-compat) and the integer `1` parse; `2` in a body, `"2"`, `1.5`, `0`,
  negative, `null` — every one is a named refusal, never coerced. On the
  header carrier only the integer `2` parses. Versions above 2 raise
  `X402VersionUnsupportedError`.
- **v2 without the `v2` option is refused** (`V2_NOT_CONFIGURED`), not
  half-paid: a spend firewall must not silently start paying a protocol
  version you never configured a signer for.

## Rail-specific security notes

These are the sharp edges of x402 specifically — read them before going live:

- **`merchant.url` is the endpoint you actually contacted**, not the server's `resource` claim (per-requirement in v1, body-level `resource.url` in v2), so host allowlists bind where you really connect. A server claiming a different origin than the one reached is refused (`RESOURCE_ORIGIN_MISMATCH`) before `pay()` is called.

  **This will refuse the official x402 reference endpoint, and that is not a bug.** Fetching
  `https://x402.org/protected` returns a requirement whose `resource.url` is
  `https://x402.vercel.app/protected` — the public domain fronts a Vercel deployment, and the
  server reports the deployment URL. Verified live 2026-08-05: the refusal fires and `pay()` is
  never reached.

  The check stays strict by default because "the host I paid is the host I asked" is exactly the
  property it exists to enforce, and a client cannot tell a friendly CDN alias from a hostile
  redirection of funds. If you have independently satisfied yourself that an alias is legitimate,
  set `requireResourceOriginMatch: false` and pin the recipient another way — an `id:<payTo>`
  merchant pattern binds the address that actually receives the money, which is the thing you
  care about.
- **Money goes to `payTo`, decoupled from the request host.** A host allowlist does *not* constrain the recipient — pin it with an `id:<payTo>` pattern if that matters to you. In v2, `payTo` may be a **role constant** (e.g. `"merchant"`) resolved out of band. Values matching `^[a-z]{1,16}$` are refused by default (`PAYTO_ROLE_REFUSED`) because an unresolvable recipient cannot be allowlisted; opt in per role via `v2.allowPayToRoles`. **That is a shape heuristic, not a list of roles** — `MERCHANT`, `merchant1` and `merchant_wallet` do not match it and are treated as addresses. Pin the recipient with an `id:<payTo>` pattern if you need it constrained rather than merely sniffed.
- **Pass the `assets` registry.** Without it, `currency` comes from the server's spoofable `extra.symbol`. With it, a token that isn't on your list is refused. v2 entries are keyed by CAIP-2 id and matched case-sensitively (asset case-insensitive only on `eip155:` EVM networks); an entry for v1's `"base"` does **not** trust `"eip155:8453"`.
- **Redirects are never followed** (`redirect: "manual"`), on both versions. A 3xx could otherwise divert the probe — or the paid retry, leaking the `X-PAYMENT` / `PAYMENT-SIGNATURE` bearer — to another origin.
- **Spend is counted from the moment the guard authorizes it, and a failure never gives it back.** Once the payment header is transmitted it is a bearer authorization the server can still settle while returning an error — but the accounting is stricter than that: ANY thrown executor keeps the spend counted, including a signer that failed before sending and a transport that died mid-request, because a throw cannot distinguish "never sent" from "sent, then the connection died". Over-hold, never overspend. If you can PROVE the rail did not charge, `guard.releaseSpend(intentId)` reclaims it explicitly; this adapter never calls it for you. Under v2's `upto` scheme the counted amount is the authorized **maximum** (what your signature permits); the smaller settled amount an untrusted `PAYMENT-RESPONSE` may later report is never reconciled downward. Bind a consume-once mandate (`maxUses`) to bound retries.
- **The v2 schemes this adapter was built against carry no reusable authorizations.** `exact` is single-use by EIP-3009 nonce and `upto` settles at most once, so per-authorization counting matches them exactly; sign-in-with-x re-access is a server-side identity grace where no payment occurs. A `batch-settlement` scheme also exists in the spec tree — a signed running total redeemed at session end — and was **not** analysed for this work. Counting stays conservative under it rather than complete: each transmitted signature is counted at its stated amount, so a batch would be over-counted, never under. Read this as the schemes examined, not as a claim about every scheme the spec may define.
- **Untrusted input is bounded on every path.** v1: the 402 body is byte-capped (64 KB, counted as received, abort at the cap). v2: the `PAYMENT-REQUIRED` header is size-capped before decoding, `extensions` (which your payer must echo) are structurally validated, size-capped, and defensively copied, and the 402 body is not read at all. `accepts` is capped on both. `extra` is validated by key and type and defensively copied on both.
- **What is validated is what is paid.** The requirement handed to your `pay()` / `v2.pay()` is the same fixed-allowlist object the guard policed — unknown keys from the wire are dropped, and v2 requirements carrying v1 money/binding fields (`maxAmountRequired`, per-requirement `resource`) are refused as mixed-version shapes.

## Errors

| Thrown | Meaning |
|---|---|
| `X402ProtocolError` | The 402 response was malformed, over a size cap, wrong-typed, or version-confused — **no money moved** |
| `X402VersionUnsupportedError` | The server declared a version this adapter refuses on that carrier (v3+, or v2 declared inside a JSON body), **or** sent v2-SHAPED data with no version declared at all — the undeclared arm is what turns a misleading field error into a named version error — **no money moved** |
| `X402RequirementRefusedError` | Refused before paying (`V2_NOT_CONFIGURED`, `PAYTO_ROLE_REFUSED`, `ASSET_NOT_ALLOWED`, `RESOURCE_ORIGIN_MISMATCH`, `NO_REQUIREMENT_SELECTED`) — **no money moved** |
| `X402PaymentBlockedError` | Policy / mandate / freeze blocked it — **no money moved** |
| `X402PaymentFailedError` | Payer ran; check `.transmitted` — if true, spend is counted because the server may still settle |

## Security

Read [SECURITY.md](https://github.com/premsreelathasugeendran/vaduno/blob/master/SECURITY.md) for the full threat model and known limitations.

## License

MIT
