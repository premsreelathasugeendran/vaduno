# @vaduno/agent

Spend-firewall hooks for AI agent frameworks. Binds a Vaduno policy to a
framework's tool-approval hook, so a model that decides to spend money still has
to get past a cap it does not control.

Part of [Vaduno](https://github.com/premsreelathasugeendran/vaduno) — non-custodial
by construction. This package never holds funds, never touches keys to funds, and
never moves money. It answers allow/deny and records what happened.

```bash
npm install @vaduno/agent @vaduno/guard
```

## Why this package exists

`guard.execute(intent, executor)` requires the guard to own the payment call. No
agent framework's approval hook works that way — every one of them is
**decide-only**: it hands you a pending tool call, takes an allow/deny, and runs
the tool itself.

So this binds to the two-phase path instead:

```
before the tool runs → authorize() → allow or deny
after the tool runs  → settle()    → executed or failed
```

An authorization **reserves budget immediately**. That is the whole point: if
`decide()` merely returned an opinion, two concurrent tool calls would both be
told yes and the cap would mean nothing.

## Usage

The core is framework-agnostic. You supply `resolve`, which turns a tool call
into a `PaymentIntent` — or returns `null` for tools that do not spend.

```ts
import { createSpendHooks } from "@vaduno/agent";
import { AuditLedger, MemoryLedgerStore, MemorySpendLimiter, VadunoGuard } from "@vaduno/guard";

const guard = new VadunoGuard({
  policy: {
    id: "research-agent",
    version: 1,
    currency: "USD",
    limits: { perTransactionMinor: 2_00, perDayMinor: 20_00 },
    merchants: { allow: ["openai.com"] },
  },
  ledger: new AuditLedger(new MemoryLedgerStore()),
  limiter: new MemorySpendLimiter(),
});

const hooks = createSpendHooks({
  guard,
  resolve(call) {
    if (call.toolName !== "buy_api_credits") return null;   // not a spending tool
    const { orderId, cents } = call.input as { orderId: string; cents: number };
    return {
      id: orderId,                                          // the settlement key
      agentId: "research-agent",
      merchant: { id: "openai", url: "https://api.openai.com/v1/credits" },
      amount: { amountMinor: cents, currency: "USD" },
      category: "api-credits",
      rail: "stripe",
      requestedAt: new Date().toISOString(),
    };
  },
});

const decision = await hooks.decide({ toolName, input });
if (decision.kind === "deny") return refuse(decision.code, decision.reason);
// ... your framework runs the tool ...
await hooks.settled(decision.intentId, { ok: true });
```

### `resolve` is yours, and it is treated as fallible

Only you know which of your tools move money and how much. Two rules:

- **`null` means "not a payment"** — the guard allows it and records nothing. Do
  not use `null` to skip a check on a tool that *does* spend.
- **A throw is a DENY.** If `resolve` fails you cannot tell what the tool would
  spend, and allowing an unknown spend is the one thing a spend firewall must
  never do. Override with `onResolveError` only if you are certain otherwise.

### `intent.id` is the settlement key

Use a value stable for one logical payment and unique across payments. Reusing an
id is treated as a replay: the tool is denied rather than run a second time, and
the deny tells you which of three states the first attempt is in —
`ALREADY_EXECUTED` (paid), `ALREADY_ATTEMPTED` (ran and failed), or
`INTENT_UNRESOLVED` (outstanding, outcome unknown — reconcile before retrying).

## Claude Agent SDK binding

```ts
import { bindClaudeAgentSdk, createSpendHooks } from "@vaduno/agent";

const sdk = bindClaudeAgentSdk(createSpendHooks({ guard, resolve }));

// PreToolUse  -> await sdk.preToolUse({ tool_name, tool_input })
// PostToolUse -> await sdk.postToolUse({ tool_name, tool_input, tool_response })
```

> **Status, stated plainly: this binding has never been run against a live Claude
> Agent SDK session.** Its hook payload shapes come from the documented contract,
> not from observation. If they have drifted, the fix is a few lines in
> [`claude-agent-sdk.ts`](src/claude-agent-sdk.ts) — the file is deliberately
> thin and imports nothing from any SDK, so the unverified surface is small and
> nowhere near the policy path. The decision logic it wraps is framework-free and
> covered by tests that are checked against real guard behavior.
>
> If you run it against the real SDK, please open an issue either way.

Other frameworks (Vercel AI SDK `toolApproval`, OpenAI Agents `needsApproval`,
LangChain `wrapToolCall`) have the same decide-only shape. Use `createSpendHooks`
directly and translate `SpendDecision` — that is all the SDK binding does.

## Failure modes, and which direction they fail

Every ambiguous case here resolves toward **over-holding budget, never
overspending**:

| Situation | What happens | Why |
|---|---|---|
| `resolve` throws | deny | An unknown spend is never allowed |
| `decide()` throws | deny | A crashed check is not an approval |
| Tool response unreadable | counted as spent | Guessing "failed" would free budget |
| Tool ran and failed | counted as spent | The rail may have charged before failing |
| Framework never calls `settled` | budget stays held | Starves its own cap; never leaks spend |
| Duplicate `intent.id` | deny | Consume-once; the rail does not run twice |
| Process restarts after a spend settled as **executed** | still counted, once the new process calls `guard.hydrateFromLedger()` on the same persistent ledger | The executed settle row carries the amount and currency, so hydration restores it into the caps. Qualifiers: a restart that never hydrates starts with empty state (pass `requireHydration: true` — see SECURITY.md); and rows hydration cannot restore — pre-0.3.0 `settle()` rows carried no amount, and a settle whose dedupe read failed lands without one (see the `settle()` docs) — are each reported in `skippedUnparseableSpendRows` instead of silently under-counting |
| Process restarts after a spend settled as **failed** | the burned hold does NOT survive the restart | Hydration restores only executed rows. "Counted as spent" for a failed call is a live-process hold: after a restart the cap re-admits that amount even though the rail may have charged. Surviving this needs a persistent `SpendLimiter`, not the ledger |

The never-settled row deserves emphasis: an unsettled authorization keeps
holding budget until its rolling window ages out. That is deliberate. Call
`settled` for every allowed call, including failures.

## What this does not do

- **It does not make an agent safe.** It caps and records spending on the tools
  you route through it. A tool you forget to resolve is a tool with no limit.
- **It does not verify the payment happened.** On this path the guard never sees
  the rail — it takes your word via `settled`, and the audit entry is marked
  `selfReported` so the ledger does not present a claim as an observation.
- **It does not stop a payment already in flight.** Vaduno decides before, and
  records after. It never holds funds or the power to reverse them.

## License

MIT
