# The distribution experiment

Vaduno is a working, tested, published library that **nobody uses**. This document
is the commitment device: what would count as evidence that someone wants it, by
when, and what happens if that evidence does not arrive.

It is written before the work, deliberately. Deciding what counts as success
*after* seeing the results is how a project quietly consumes a year.

## The baseline, measured 2026-08-06

Before any distribution has been attempted — no post, no announcement, no outreach:

| Signal | Value |
|---|---|
| GitHub stars | 0 |
| Forks | 0 |
| Watchers | 0 |
| Issues or discussions opened by anyone | 0 |
| Inbound contact of any kind | 0 |

Nobody has ever asked for this. That is the honest starting position.

## Why npm downloads are not the metric

`@vaduno/guard` reports a weekly download total in the hundreds-to-low-thousands.
That number is worthless here — and it is a *moving* number, so no snapshot of it
is quoted as a fact: the total read ~1,187 on 2026-08-06 and 824 two days later,
with one day at 0. Any specific figure written into a doc becomes the next false
claim within days. What is stable, and what matters, is the *shape* of the daily
curve (this sample measured 2026-08-09):

```
2026-07-28   141      <- publish wave (0.6.0 across the packages)
2026-07-29   330      <-  "
2026-07-30   351      <-  "
2026-07-31    20
2026-08-01    42
2026-08-02    22
2026-08-03   163
2026-08-04   347      <- publish day (0.6.1)
2026-08-05   242
2026-08-06    20
2026-08-07     0
2026-08-08    30
2026-08-09     0
```

The spikes land on publish days — one spike per release, not one ever — and
collapse to near zero between them, some days literally zero. That is registry
mirrors and security scanners reacting to new versions: automated traffic that
would look identical if the package were empty. A package with that download
curve and zero stars, zero forks and zero questions has no human users.

Downloads may be *reported*, but they do not count toward the gate.

## What counts as a human

Each of these requires a person to have made a decision:

- **A star or fork** from an account unaffiliated with the author.
- **An issue, discussion, or pull request** opened by a stranger.
- **Inbound contact** — an email, a message, a mention that is not solicited.
- **A referral source** in GitHub traffic showing someone arrived from somewhere
  real, rather than a crawler.
- **A sustained lift in the non-publish-day download baseline** — the ~20/day
  floor moving to a materially higher floor and staying there for a week with no
  release. This is the only way download data earns any weight, and even then it
  is corroborating, not decisive.

## The gate — 2026-09-03

Four weeks from the day distribution actually begins.

**Continue as a product** if at least **three unaffiliated humans** have engaged
by any of the signals above, *or* any single piece of inbound contact describes a
real use case.

**Reclassify as a portfolio artifact** otherwise — publicly, in the README, in
plain language. Not deleted, not deprecated, not quietly abandoned: relabelled
honestly as a demonstration of engineering rather than a product seeking users.

## The rules that make this real

1. **The date does not move.** Extending the deadline because results are
   nearly-there is the failure mode this document exists to prevent.
2. **The bar does not lower.** Three humans is already a low bar. If it is not
   met, the answer is not a smaller bar.
3. **Author-solicited engagement does not count.** A star from someone who was
   asked to star it measures politeness, not demand.
4. **A negative result is a real result.** Learning that nobody wants this, for
   the cost of four weeks, is cheap. Not learning it, for the cost of a year, is
   not.

## What is true regardless of the outcome

If the gate fails, what remains is a published, MIT-licensed library with 1,201
passing tests (measured 2026-08-09), twenty-one payments settled on a live chain — the count from an
exhaustive on-chain scan of every USDC transfer out of the experiment wallet
(2026-08-09, genesis to tip, zero dropped RPC chunks; an earlier count of
"seven" in this file came from a scan that silently swallowed failed chunks,
which is exactly the defect class this project keeps writing about), including
two through the packaged `@vaduno/cloudflare` build and one signed by a
separate key-holder process the agent could not reach around — plus a
documented adversarial process that found and fixed twenty real defects in its
own code, and a policy engine proven to sit in the mandatory signing path of a
shipped third-party SDK.

That is worth having built. It is simply not the same thing as a product, and
this document exists so the difference stays visible.
