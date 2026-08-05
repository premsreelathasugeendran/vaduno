# x402 against a live chain and a live seller

An attempt to settle a real x402 payment on Base Sepolia through the Vaduno
guard. **It did not settle**, and the reason is worth recording precisely.

## What worked

Everything on this side of the wire.

| Step | Result |
|---|---|
| Parse a real 402 from `x402.org/protected` | ✅ 920-byte `PAYMENT-REQUIRED`, two accepts (EVM + Solana), all fields |
| Trusted asset registry | ✅ matched Base Sepolia USDC |
| Policy evaluation | ✅ $0.01 under a $0.05/txn, $0.20/day policy |
| Requirement handed to `pay()` | ✅ correct scheme, network, amount, payTo, asset |
| EIP-3009 authorization | ✅ signature recovers to the payer; EIP-712 domain matches the on-chain USDC contract's own `name()`/`version()` |
| Audit trail | ✅ `intent_received`, `policy_decision`, `execution_started`, `execution_result`; `verify()` ok |
| Pessimistic accounting | ✅ transmitted → spend counted, even though the server errored |

The signature was checked two ways: recovered against the payer's address, and
its EIP-712 domain compared against what the deployed USDC contract actually
reports. Both pass. **The authorization this example produces is valid.**

## What did not work, and whose bug it is

`https://x402.org/protected` — the x402 project's own reference seller —
returns HTTP 402 with a server-side crash on every v2 payment attempt:

```
Cannot destructure property 'extra' of 't' as it is undefined.
```

This is not a Vaduno bug, and it is not a payload-shape mistake:

- The **official `@x402/evm@2.21.0` client** produces a payload that fails
  identically. Five payload variants were tried (bare, with `scheme`/`network`,
  with `paymentRequirements` echoed, with `accepts` echoed, and via the v1
  `X-PAYMENT` header) — all five produce the same server crash.
- **No payment has landed on-chain** for that endpoint's `payTo`
  (`0x2096…287C`) in the last ~50,000 Base Sepolia blocks — roughly 28 hours.
  If the endpoint were working, other people's `$0.01` payments would be
  visible. They are not.

Verified 2026-08-05.

The public facilitator at `https://x402.org/facilitator` is up and advertises
exactly the scheme we need (`x402Version 2`, `exact`, `eip155:84532`), but its
`/verify` body shape is undocumented and none of the tried shapes were accepted;
`@x402/core` ships no facilitator client. Rather than reverse-engineer a
third party's API by brute force, this stops here.

## How to finish it

Any of these would produce the missing artifact — an on-chain
`transferWithAuthorization` this repo can point at:

1. **Wait for the reference endpoint to be fixed**, then re-run `npm start`.
   The code needs no changes.
2. **Find another live x402 seller** and change `TARGET` in `pay.mjs`.
3. **Get the facilitator's `/verify` and `/settle` body shape** from its source
   or a working client, and call it directly. The payload is already correct.

## Running it

```bash
npm -w x402-live run keygen     # throwaway wallet, prints only the address
# fund it at https://faucet.circle.com (Base Sepolia), then:
npm -w x402-live start
```

The wallet lives in `.wallet` (gitignored), holds worthless faucet tokens on one
testnet, and should be deleted when you are done.

## Where the key lives, and why that matters

In `pay.mjs`'s signer — never in Vaduno. `pay()` is the host's callback; the
guard decides whether it may be invoked and records that it was. That is the
project's central constraint, and this example is what it looks like in practice:
the guard reached a decision, authorized a spend, and recorded the outcome
without ever seeing the private key that would have moved the money.

The example also pins the **recipient** rather than the origin. The reference
endpoint declares `resource.url` on its Vercel deployment while being served
from `x402.org`, so `requireResourceOriginMatch` is deliberately disabled and the
policy allowlist binds `id:0x209693bc…` — the address that actually receives the
money. See `packages/x402/README.md` for why that is the better binding.
