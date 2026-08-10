# keyless-agent — the raw key where the agent cannot reach it

Every other signer example in this repository holds the key in the same
process as the agent, and their READMEs say plainly what that means: an
injected agent can read the key and sign around any wrapper. This example is
the configuration those READMEs point to — the raw key in a **separate OS
process** whose only exposed capability is the policy-gated `signTypedData`
of `@vaduno/cloudflare`'s `createSignerHost`.

```
demo.mjs (the agent — KEYLESS)          host.mjs (the key holder)
──────────────────────────────          ─────────────────────────────────
remoteSigner over a stdio pipe   ──►    createSignerHost: guard (policy +
  holds: an address, a transport          spend limiter + hash-chained
  can do: ASK for signatures              ledger) in front of the key.
                                          Signs, or refuses. Nothing else.
```

Run it (offline — the host generates a throwaway key, nothing is broadcast):

```
npm run demo:keyless
# or: node examples/keyless-agent/demo.mjs
```

What the run proves, each as a hard check that exits 1 on failure:

- the agent's requests to a non-allowlisted payee, over-cap amounts, and a
  wrong chain/asset are **refused with no signature**;
- probing the host for `signTransaction`, `signMessage`, `sign`, `exportKey`
  gets `HOST_METHOD_DISABLED` — the host recognizes exactly one method;
- unparseable wire input is refused without killing the host;
- an allowed payment DOES sign, and the signature **recovers to the host's
  key** — a key this process has never seen;
- a byte-identical replay re-issues the same signature (counted once);
- killing the host kills the agent's signing capability, immediately;
- every string that crossed the boundary is recorded and wire-shaped.

`--live` (`npm -w keyless-agent run start:live`) does all of the above and
then makes the same real x402 v2 purchase as `examples/guarded-signer/pay.mjs`
— 0.01 USDC on Base Sepolia testnet, hard-capped at 0.10 — except the payment
signature is produced in the *other* process. Settlement is verified by
decoding the USDC `Transfer` log from the settlement transaction's own
receipt, never from a balance read. Most recent live run:
[`0x7711f2…fb92`](https://sepolia.basescan.org/tx/0x7711f23c37047bb09c8583cf8a18176451211f87c193e5ddd93e6817cf5efb92)
(block 45279638, 0.01 USDC to x402.org's `payTo`).

## What this does and does not close

**Closed:** compromise of the agent process no longer yields the key or an
ungated signing path. The strongest thing injected code here can do is ask,
and every ask is policed and written to the host's ledger — which also lives
out of the agent's reach.

**Not closed, stated plainly:**

- compromise of the **host** process still owns the key. The host's defense
  is having no other reachable surface, not being uncompromisable;
- the stdio transport authenticates nobody. Anyone who can write to the
  host's stdin can request policy-gated signatures. Put the transport where
  only the agent reaches it, and add caller auth at that layer if the
  deployment needs it;
- nothing forces a deployer to use this arrangement — a deployment that hands
  the agent the key gets none of it;
- everything the in-process wrapper cannot do (bind the resource paid for,
  stop an in-flight settlement, count spend at settlement rather than
  signing) is unchanged here — the boundary moves the KEY, not those limits.

## Safety rails

- Base Sepolia (chain 84532) only; the registry contains only Base Sepolia
  USDC; the policy allowlists only x402.org's `payTo` and caps 0.05 per
  transaction / 0.20 per day (USDC atomic units: 50_000 / 200_000).
- The offline mode uses a fresh random key and broadcasts nothing.
- The live mode aborts on any requirement over 0.10 USDC and reuses the
  `examples/x402-live` faucet wallet. Never mainnet.
