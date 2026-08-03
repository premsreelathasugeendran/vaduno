# @vaduno/x402

> ### ⚠️ Experimental — x402 **v1 only**, and never run against a real server
>
> This adapter implements x402 **v1**. A v2 body — which renamed
> `maxAmountRequired` to `amount` and moved to CAIP-2 network ids — is refused
> by name with `X402VersionUnsupportedError`, and **no payment is attempted**.
>
> It has also **never run against a real x402 server**. The demo and every test
> mock both the server and the payer in-process, so what is verified is that the
> code agrees with a reading of the specification — not that it interoperates
> with anything. Treat it as a reference implementation.
>
> v2 support is not a parser patch: `validateRequirement` builds its result from
> a fixed allowlist, so accepting `amount` without threading it through to the
> requirement handed to `pay()` would let policy approve one amount while the
> signer signs another. It needs the `pay()` shape decided first, which is a
> one-way semver door.


**Policy + audit for [x402](https://www.x402.org/) stablecoin payments.**

x402 revives HTTP `402 Payment Required`: a server answers with a price, your agent pays, and retries. This package wraps that flow so every payment passes a [`@vaduno/guard`](https://www.npmjs.com/package/@vaduno/guard) spend firewall first, and lands in a tamper-evident audit ledger.

**Vaduno never sees your keys.** You supply the signer; the guard only decides whether it may run.

```bash
npm install @vaduno/x402 @vaduno/guard
```

## Use it like `fetch`

```ts
import { createX402Fetch } from "@vaduno/x402";

const fetchWithPay = createX402Fetch({
  guard,                                   // your VadunoGuard
  agentId: "researcher-agent-1",
  pay: (req) => myWallet.signX402(req),    // your signer — keys stay yours
  assets: [                                // bind spend to the REAL token, not a label
    { network: "base", asset: "0x833589...2913", symbol: "USDC", decimals: 6 },
  ],
});

// 402s are paid under policy; everything else passes straight through.
const res = await fetchWithPay("https://api.example.com/premium");
```

On a `402` it parses the requirement, builds a `PaymentIntent` bound to the **real** request URL, runs the guard, and only if allowed calls your `pay()` and retries with the `X-PAYMENT` header.

## Rail-specific security notes

These are the sharp edges of x402 specifically — read them before going live:

- **`merchant.url` is the endpoint you actually contacted**, not the server's `resource` claim, so host allowlists bind where you really connect. A server claiming a different origin than the one reached is refused.
- **Money goes to `payTo` (an address), decoupled from the request host.** A host allowlist does *not* constrain the recipient — pin it with an `id:<payTo>` pattern if that matters to you.
- **Pass the `assets` registry.** Without it, `currency` comes from the server's spoofable `extra.symbol`. With it, a token that isn't on your list is refused.
- **Redirects are never followed** (`redirect: "manual"`). A 3xx could otherwise divert the probe — or the paid retry, leaking the `X-PAYMENT` bearer — to another origin.
- **Spend is counted once `X-PAYMENT` is transmitted**, because it is a bearer authorization the server can still settle even while returning an error. Bind a consume-once mandate (`maxUses`) to bound retries.
- **The untrusted 402 body is bounded** (64 KB) and `accepts` is capped, so a hostile server cannot exhaust the agent. The cap counts the **bytes actually received** and aborts the transfer the moment it is exceeded — it holds even for chunked/HTTP-2 responses that carry no `Content-Length`.

## Errors

| Thrown | Meaning |
|---|---|
| `X402ProtocolError` | The 402 response was malformed, over the byte cap, or wrong-typed — **no money moved** |
| `X402VersionUnsupportedError` | The server speaks x402 v2+, which this adapter does not — **no money moved** |
| `X402RequirementRefusedError` | Refused before paying — **no money moved** |
| `X402PaymentBlockedError` | Policy / mandate / freeze blocked it — **no money moved** |
| `X402PaymentFailedError` | Payer ran; check `.transmitted` — if true, spend is counted because the server may still settle |

## Security

Read [SECURITY.md](https://github.com/premsreelathasugeendran/vaduno/blob/master/SECURITY.md) for the full threat model and known limitations.

## License

MIT
