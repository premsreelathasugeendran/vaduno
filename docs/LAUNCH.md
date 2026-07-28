# Show HN draft

Not committed as marketing — kept here so the claims in the post and the
claims in the README can be diffed against each other before posting.

## Title

> **Show HN: Vaduno – a spend firewall for AI agents (v0.1.0, zero users)**

Alternates:
- Show HN: A spend firewall for AI agents that holds no funds and no keys
- Show HN: I gave an agent a payment key, then built the gate in front of it

## Body (post as the first comment, immediately after submitting)

Published today. v0.1.0, zero users, never run in production, and the Stripe
Issuing adapter is test mode only because the live one needs a business entity
I don't have. By my own count worldwide agent-payment volume is about $28K/day,
maybe half of it wash.

It's a deterministic gate in front of your executor function: rolling
day/week/month caps, merchant allowlists, velocity limits, approval
thresholds. No model decides anything, and it holds no funds and no keys.

Where does the signing key live? A human signs a scope ahead of time
(merchants, ceiling, window) with an Ed25519 key that belongs offline or
somewhere the agent process can't reach, and the agent spends unattended
inside it. Automate signing on the agent's own box and the mandate is just an
audit format.

Consume-once is enforced at execution, not only signed. Fire the same intent
six times in parallel and the rail runs at most once; the other five replay
the first outcome. That's true within one process. Cross-process needs a store
with a unique constraint, which today is an interface, not a Postgres adapter
I've shipped.

Stripe's spending_controls, Lithic and Privacy.com already do caps at the
network, where an agent can't route around them. Vaduno can be routed around:
an agent holding a raw wallet key just doesn't call it. On Stripe Issuing it
can't, because the guard answers the card authorisation itself. What's new is
one policy across rails, a portable signed authority, and a log a third party
can verify: hash-chained, upgradeable to RFC 9162 with inclusion proofs.

Caps don't stop prompt injection, they bound the loss. Five rounds of
adversarial review (multi-agent LLM, findings verified by hand) found a
cross-process double spend, a kill switch one hanging rail could park, and a
witness quorum reachable with no witness misbehaving.

Clone it and run `npm run demo`. Criticism of the concurrency and the crypto
is what I'm after.

---

## Answers to have ready

**"How is this not Stripe spending_controls / Lithic / Privacy.com, enforced
at the network where the agent can't dodge it?"**
Those are strictly better inside one rail and you should use them. What I add
is one policy and one signed authority that survive across rails, plus a log
the counterparty can verify without trusting me. On Issuing I sit behind their
controls, not instead of them.

**"A library the agent's own process imports is not a firewall. An injected
agent just calls the executor directly."**
Correct, and that's the honest scope. In-process it's a guardrail against a
confused agent, not a compromised runtime. The only configuration where it's
genuinely non-bypassable today is Stripe Issuing, where the guard answers the
authorisation. Out-of-process and rail-side enforcement is what would make the
rest of it real.

**"Non-custody is a distinction without a difference — the attacker doesn't
need the funds, they need the yes."**
Agreed that the strong reading is wrong: a compromised guard fails open and
your executor moves real money for it. What non-custody buys is narrower —
there's no key or PAN to steal from Vaduno, it can't originate a payment, and
the mandate is signed by a key it doesn't hold, so it can't mint authority
beyond a scope a human already signed.

**"Five rounds of adversarial review means LLMs reviewed LLM code, and
'verified by hand' is unfalsifiable."**
Yes — multi-agent LLM review, not an audit, and you shouldn't take my word for
the verification. The bugs are concrete enough to check against the commits.
I'd rather someone here found the sixth than defended the framing.

**"Where does $28K/day come from?"**
My own count from public x402 facilitator activity and on-chain agent-wallet
flow over a sampled window. No vendor data, no methodology I'd defend as
rigorous. I flag half as wash because a small number of addresses were paying
each other. Happy to post the addresses and the window.

---

## Before posting

- [ ] Repo is public
- [ ] CI badge is green on `master`
- [ ] `npm install @vaduno/guard` works from a clean directory
- [ ] Post on a weekday morning US Eastern; reply to every comment for the
      first few hours — engagement matters more than the post
- [ ] Do not argue with the harshest comment. Concede the true part first.
