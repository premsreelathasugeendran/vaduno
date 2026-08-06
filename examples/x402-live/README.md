# x402 against a live chain and a live seller

A real x402 payment on Base Sepolia through the Vaduno guard. **It settled.**

```
tx       0x620f4c905326835a82b72ce95116e006fb212ef0b4a1ad0a63bf2468c4376b57
network  eip155:84532 (Base Sepolia), block 45089116, status: success
event    Transfer 10000 units of USDC (0x036C…cF7e)
         from 0xA7690bB9d12Dd7Cc7E4dd6F73f01FcE3612c8fA7 (this example's payer)
         to   0x209693Bc6afc0C5328bA36FaF03C514EF312287C (x402.org/protected's payTo)
sender   0xd407…f1bf — the PUBLIC facilitator's signer. The payer holds no ETH;
         the facilitator submitted transferWithAuthorization and paid the gas.
```

Verified independently of the seller's 200 response: receipt fetched by hash,
Transfer log decoded, payer balance re-read (20.000000 → 19.990000 USDC).
Settled 2026-08-05. Every role except the payer — seller, facilitator, chain,
faucet — is somebody else's infrastructure.

**A note on that balance re-read, because the script no longer does it.** A
balance read is the wrong instrument for "did this payment settle?" and it
produced a *false negative* on later runs: `spent: 0.000000 USDC` for payments
that had settled. Three ways, all the same mistake. Reading straight after the
200 — the 200 means the facilitator *accepted* the authorization, not that the
transfer landed. Reading `latest` after waiting for the receipt — the public
RPC is load-balanced, and the node answering `balanceOf` was behind the node
that answered the receipt. Pinning the read to the settlement block — that node
did not have the block yet (`block not found`). The script now decodes the
ERC-20 `Transfer` event out of the settlement transaction's own receipt, which
is exact and arrived with the receipt, and prints any balance figure explicitly
labelled as a possibly-lagging `latest` read.

## The correction

An earlier revision of this file said the payment did not settle and blamed the
reference seller: every attempt got back a 402 carrying
`Cannot destructure property 'extra' of 't' as it is undefined`, the "official
client" appeared to fail identically, and no payment had landed for that payTo
in ~50k blocks. **That conclusion was wrong.** The seller was functional the
whole time. Our payload — and every variant we tried — was missing the REQUIRED
top-level `accepted` field of the v2 PaymentPayload: a verbatim echo of the
requirement being paid.

Reading the x402 source (x402-foundation/x402) settled it:

- The server matches an incoming payment via
  `paymentRequirementsMatchAccepted(required, paymentPayload.accepted)`, whose
  second line destructures `const { extra, ...core } = accepted`. With
  `accepted` undefined, V8 throws exactly the observed message
  (`typescript/packages/core/src/server/x402ResourceServer.ts`; verbatim in the
  installed `@x402/core@2.21.0` dist).
- The facilitator's `/verify` reads `payload.accepted.scheme` after validating
  the inner authorization — hence its
  `Cannot read properties of undefined (reading 'scheme')` on the same body
  (`typescript/packages/mechanisms/evm/src/exact/facilitator/eip3009.ts`).
- Why the "official client" test failed identically: `accepted` is attached
  ONLY by `@x402/core`'s `x402Client.createPaymentPayload` wrapper. The
  scheme-level `@x402/evm` `createEIP3009Payload` returns `{x402Version,
  payload}` with no `accepted`; invoked without the wrapper it reproduces the
  same defective payload we built by hand.

Two real bugs remain on their side, but neither blocked settlement: the server
JSON-parses the `PAYMENT-SIGNATURE` header with no schema validation and turns
a malformed payload into a TypeError relayed in the 402 `error` field (it
should be a 400), and the facilitator does the same on `/verify`. Confusing;
not disabling.

## What the fix was

One payload change in `pay.mjs`'s `signExact` — no Vaduno source changed:

- echo the selected requirement verbatim as `accepted`
- echo the body-level `resource` (optional, from the `ctx` Vaduno passes)
- drop top-level `scheme`/`network` (not part of the v2 PaymentPayload type)

`@vaduno/x402` needed no fix. Its `v2.pay` contract already documented the
mandatory `accepted` echo ("It MUST … echo exactly that requirement as the
payload's `accepted` field") and it transmits the host's header verbatim. The
example's signer simply had not honored the contract it was handed.

## What one run looks like

| Step | Result |
|---|---|
| Parse a real 402 from `x402.org/protected` | ✅ 920-byte `PAYMENT-REQUIRED`, two accepts (EVM + Solana) |
| Trusted asset registry | ✅ matched Base Sepolia USDC |
| Policy evaluation | ✅ $0.01 under a $0.05/txn, $0.20/day policy |
| Requirement handed to `pay()` | ✅ correct scheme, network, amount, payTo, asset |
| EIP-3009 authorization | ✅ signature recovers to the payer; EIP-712 domain matches the on-chain USDC contract's own `name()`/`version()` |
| Settlement | ✅ seller verifies + settles via `x402.org/facilitator`; 200 with the tx hash in the settlement response |
| Audit trail | ✅ `intent_received`, `policy_decision`, `execution_started`, `execution_result`; `verify()` ok |
| On-chain | ✅ receipt `status: success`; Transfer(payer → payTo, 10000); balance −0.010000 |

The guard reached a decision, authorized the spend, the host signed, a third
party settled, and `onSettled` wrote the hash to `last-settlement.json`.

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
project's central constraint, and this example is what it looks like in
practice: the guard reached a decision, authorized a spend, and recorded the
outcome without ever seeing the private key that moved the money.

The example also pins the **recipient** rather than the origin. The reference
endpoint declares `resource.url` on its Vercel deployment while being served
from `x402.org`, so `requireResourceOriginMatch` is deliberately disabled and the
policy allowlist binds `id:0x209693bc…` — the address that actually receives the
money. See `packages/x402/README.md` for why that is the better binding.
