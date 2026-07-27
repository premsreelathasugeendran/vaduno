# @paygent/x402

**Policy + audit for [x402](https://www.x402.org/) stablecoin payments.**

x402 revives HTTP `402 Payment Required`: a server answers with a price, your agent pays, and retries. This package wraps that flow so every payment passes a [`@paygent/guard`](https://www.npmjs.com/package/@paygent/guard) spend firewall first, and lands in a tamper-evident audit ledger.

**Paygent never sees your keys.** You supply the signer; the guard only decides whether it may run.

```bash
npm install @paygent/x402 @paygent/guard
```

## Use it like `fetch`

```ts
import { createX402Fetch } from "@paygent/x402";

const fetchWithPay = createX402Fetch({
  guard,                                   // your PaygentGuard
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
- **The untrusted 402 body is bounded** (64 KB) and `accepts` is capped, so a hostile server cannot exhaust the agent.

## Errors

| Thrown | Meaning |
|---|---|
| `X402RequirementRefusedError` | Refused before paying — **no money moved** |
| `X402PaymentBlockedError` | Policy / mandate / freeze blocked it — **no money moved** |
| `X402PaymentFailedError` | Payer ran; check `.transmitted` — if true, spend is counted because the server may still settle |

## Security

Read [SECURITY.md](https://github.com/premsreelathasugeendran/paygent/blob/master/SECURITY.md) for the full threat model and known limitations.

## License

MIT
