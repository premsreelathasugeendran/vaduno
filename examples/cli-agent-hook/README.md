# Vaduno as a live Claude Code hook

The first place any Vaduno code ran against a host this repo does not control.

Two scripts:

- **`observe.mjs`** — a passive recorder. Logs every hook payload and blocks
  nothing (no stdout, exit 0 = no opinion). Run this first against any new host
  or host version.
- **`guard-hook.mjs`** — a real `VadunoGuard` with a $2.00/day, $0.50/txn policy,
  wired to the published `@vaduno/agent` binding.

## Why it exists

`@vaduno/agent` was written from the documented hook contract and shipped
through 0.5.0 having never run in a live session. The README said so. Pointing
the observer at one session found three mismatches:

| Observed | What the code assumed |
|---|---|
| `permissionDecision: "allow"` **short-circuits** the host's own permission evaluation | that `allow` was a safe way to say "not my business" |
| A failed tool raises a **separate failure event** with `error`, never reaching `PostToolUse` | that failures arrive at `PostToolUse` with an error-shaped `tool_response` |
| Every event carries **`tool_use_id`** | that Pre→Post had to be matched by fingerprinting `tool_input` |

The first was the serious one. With a `*` matcher, a spend firewall that
returns `allow` for every non-payment tool **switches off the permission prompts
around it** — the opposite of its purpose. Two tests in `@vaduno/agent` had
asserted that behavior back as correct, which is the whole lesson: a suite
cannot discover that its own premise is false. Only the host can tell you that.

## Reproducing it

```bash
npm install && npm run build
```

Then in `.claude/settings.json`, register `observe.mjs` on `PreToolUse`,
`PostToolUse` and `PostToolUseFailure` with matcher `*`, use the session
normally, and read `observed-payloads.jsonl`. Swap in `guard-hook.mjs` to
enforce rather than observe.

A denied tool call looks like this — the command never executes, and the model
is told why:

```
$ echo VADUNO_PAYMENT_PROBE
vaduno: PER_TXN_LIMIT_EXCEEDED — 9900 exceeds per-transaction limit 50
```

`guard-hook.mjs` carries a deliberate probe: exactly one Bash command is treated
as a $99 payment so the deny path can be demonstrated in a host that has no
payment tool of its own. Ordinary commands are unaffected — `resolve()` returns
`null` and the binding emits no opinion.

### The resolver bites both ways

That match is an **exact** string comparison, and it did not start that way. The
first version tested `cmd.includes(marker)` — and immediately denied the `git
commit` whose *message* described the marker. A resolver greedy enough to block
work that merely mentions a payment is an outage, not a firewall.

The package README warns about the opposite error: a spending tool you forget to
resolve is a tool with no limit. Both directions are real, and only one of them
is obvious in advance. Write `resolve()` to match the payment you mean, and
nothing else.

## What this proves, and what it does not

**Proves:** the agent-side binding's parsing, correlation and decision plumbing
match a real host's real contract, and a Vaduno deny genuinely prevents a tool
from running in a live session.

**Does not prove:** anything about a payment rail. No money moves here, and the
"payment tool" is one this example defines. For the firewall stopping a *real*
payment, the x402 testnet path is the next rung — real protocol, real
settlement, worthless testnet money.

The cross-process cap is real, though: each hook invocation is a **separate
process**, so the `FileSpendLimiter` in `.state/` is what makes the daily cap
hold across them. An in-memory limiter would reset on every tool call.

## Note on scope

`.state/` and the logs are gitignored — they are session artifacts, not
fixtures. Delete them to start from a clean cap.
