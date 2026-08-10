/**
 * The Claude Agent SDK binding.
 *
 * SCOPE: most of these prove the TRANSLATION is right — a deny becomes a deny,
 * only authorized calls settle, a crash reads as deny. The final block is
 * different: it pins shapes OBSERVED against a live Claude Code session.
 *
 * That distinction is the lesson of this file. Before the observation, two
 * tests here asserted a non-payment tool returns "allow" — faithfully encoding
 * a wrong assumption about the host and reporting it back as green. A suite
 * cannot discover that its own premise is false; only contact with the real
 * host can. See examples/cli-agent-hook.
 */
import { describe, expect, it } from "vitest";
import {
  AuditLedger,
  MemoryLedgerStore,
  MemorySpendLimiter,
  VadunoGuard,
} from "@vaduno/guard";
import type { PaymentIntent, SpendPolicy } from "@vaduno/guard";
import { createSpendHooks } from "../src/hooks.js";
import type { SpendHooks } from "../src/hooks.js";
import { bindClaudeAgentSdk, memoryInFlight } from "../src/agent-sdk.js";

const CAP = 5_000;

const policy: SpendPolicy = {
  id: "sdk-binding",
  version: 1,
  currency: "USD",
  limits: { perTransactionMinor: 5_000, perDayMinor: CAP },
  merchants: { allow: ["openai.com"] },
};

function setup() {
  const limiter = new MemorySpendLimiter();
  const guard = new VadunoGuard({
    policy,
    ledger: new AuditLedger(new MemoryLedgerStore()),
    limiter,
  });
  const hooks = createSpendHooks({
    guard,
    resolve: (call): PaymentIntent | null => {
      if (call.toolName !== "buy_credits") return null;
      const i = call.input as { id: string; amountMinor: number };
      return {
        id: i.id,
        agentId: "agent-1",
        merchant: { id: "m", url: "https://api.openai.com/v1/pay" },
        amount: { amountMinor: i.amountMinor, currency: "USD" },
        category: "api-credits",
        rail: "mock",
        requestedAt: new Date().toISOString(),
      };
    },
  });
  return { limiter, guard, hooks, sdk: bindClaudeAgentSdk(hooks) };
}

const decisionOf = (out: unknown) =>
  (out as { hookSpecificOutput?: { permissionDecision?: string } })?.hookSpecificOutput
    ?.permissionDecision;

const since = () => new Date(Date.now() - 86_400_000).toISOString();

describe("PreToolUse translates the decision", () => {
  it("gives NO OPINION on a non-payment tool", async () => {
    // This asserted "allow" until a live session showed that allow
    // short-circuits the host's own permission evaluation — so the firewall
    // was auto-approving every unrelated tool. The test was wrong in exactly
    // the way the code was wrong.
    const { sdk } = setup();
    const out = await sdk.preToolUse({ tool_name: "read_file", tool_input: { p: "a" } });
    expect(out).toEqual({});
  });

  it("allows a permitted spend and names the intent in the reason", async () => {
    const { sdk } = setup();
    const out = await sdk.preToolUse({
      tool_name: "buy_credits",
      tool_input: { id: "t-1", amountMinor: 900 },
    });
    expect(decisionOf(out)).toBe("allow");
    expect(out.hookSpecificOutput.permissionDecisionReason).toContain("t-1");
  });

  it("DENIES an over-cap spend, and surfaces the policy code to the model", async () => {
    const { sdk } = setup();
    const out = await sdk.preToolUse({
      tool_name: "buy_credits",
      tool_input: { id: "t-1", amountMinor: 999_999 },
    });
    expect(decisionOf(out)).toBe("deny");
    // The model reads this string; a bare "denied" teaches it nothing and it
    // will just retry the same call.
    expect(out.hookSpecificOutput.permissionDecisionReason).toMatch(/vaduno: [A-Z_]+/);
  });

  it("tags the event name the host expects, when it does have an opinion", async () => {
    const { sdk } = setup();
    const out = await sdk.preToolUse({
      tool_name: "buy_credits",
      tool_input: { id: "t-1", amountMinor: 900 },
    });
    expect((out as { hookSpecificOutput: { hookEventName: string } }).hookSpecificOutput.hookEventName).toBe(
      "PreToolUse",
    );
  });
});

describe("a crashing hook reads as DENY, never as approval", () => {
  it("denies when decide() throws", async () => {
    const exploding: SpendHooks = {
      async decide() {
        throw new Error("limiter unreachable");
      },
      async settled() {},
    };
    const sdk = bindClaudeAgentSdk(exploding);
    const out = await sdk.preToolUse({ tool_name: "buy_credits", tool_input: {} });
    expect(decisionOf(out)).toBe("deny");
    expect(out.hookSpecificOutput.permissionDecisionReason).toContain("limiter unreachable");
  });

  it("does not throw out of the hook — a throwing hook may be treated as no-opinion", async () => {
    const exploding: SpendHooks = {
      async decide() {
        throw new Error("boom");
      },
      async settled() {},
    };
    const sdk = bindClaudeAgentSdk(exploding);
    await expect(
      sdk.preToolUse({ tool_name: "buy_credits", tool_input: {} }),
    ).resolves.toBeDefined();
  });
});

describe("PostToolUse settles exactly the calls that were authorized", () => {
  it("commits the spend after a successful tool run", async () => {
    const { sdk, limiter } = setup();
    const input = { id: "t-1", amountMinor: 1_000 };
    await sdk.preToolUse({ tool_name: "buy_credits", tool_input: input });
    await sdk.postToolUse({
      tool_name: "buy_credits",
      tool_input: input,
      tool_response: { ok: true },
    });
    const t = await limiter.totalsSince(policy.id, since(), "USD");
    expect(t.totalMinor).toBe(1_000);
  });

  it("does NOT settle a tool that PreToolUse denied", async () => {
    // Settling here would record a payment that never happened, and put a
    // fabricated entry in the audit log.
    const { sdk, limiter } = setup();
    const input = { id: "t-1", amountMinor: 999_999 };
    expect(decisionOf(await sdk.preToolUse({ tool_name: "buy_credits", tool_input: input })))
      .toBe("deny");
    await sdk.postToolUse({
      tool_name: "buy_credits",
      tool_input: input,
      tool_response: { ok: true },
    });
    const t = await limiter.totalsSince(policy.id, since(), "USD");
    expect(t.count).toBe(0);
  });

  it("does NOT settle a non-payment tool", async () => {
    const { sdk, limiter } = setup();
    await sdk.preToolUse({ tool_name: "read_file", tool_input: { p: "a" } });
    await sdk.postToolUse({
      tool_name: "read_file",
      tool_input: { p: "a" },
      tool_response: "contents",
    });
    const t = await limiter.totalsSince(policy.id, since(), "USD");
    expect(t.count).toBe(0);
  });

  it("keeps the spend counted when the tool reports an error", async () => {
    const { sdk } = setup();
    const input = { id: "t-1", amountMinor: CAP };
    await sdk.preToolUse({ tool_name: "buy_credits", tool_input: input });
    await sdk.postToolUse({
      tool_name: "buy_credits",
      tool_input: input,
      tool_response: { is_error: true, error: "gateway timeout" },
    });
    // Burn on failure: the rail may have charged before it failed.
    const out = await sdk.preToolUse({
      tool_name: "buy_credits",
      tool_input: { id: "t-2", amountMinor: CAP },
    });
    expect(decisionOf(out)).toBe("deny");
  });

  it("an ambiguous response counts the spend rather than freeing it", async () => {
    // The safe direction. Guessing "succeeded" and guessing "failed" both keep
    // the amount held, so a weird tool_response can never inflate the budget.
    const { sdk, limiter } = setup();
    const input = { id: "t-1", amountMinor: 1_000 };
    await sdk.preToolUse({ tool_name: "buy_credits", tool_input: input });
    await sdk.postToolUse({
      tool_name: "buy_credits",
      tool_input: input,
      tool_response: "who knows",
    });
    const t = await limiter.totalsSince(policy.id, since(), "USD");
    expect(t.totalMinor).toBe(1_000);
  });

  it("settles nothing when PostToolUse arrives twice", async () => {
    const { sdk, limiter } = setup();
    const input = { id: "t-1", amountMinor: 1_000 };
    await sdk.preToolUse({ tool_name: "buy_credits", tool_input: input });
    await sdk.postToolUse({ tool_name: "buy_credits", tool_input: input, tool_response: {} });
    await sdk.postToolUse({ tool_name: "buy_credits", tool_input: input, tool_response: {} });
    const t = await limiter.totalsSince(policy.id, since(), "USD");
    expect(t.totalMinor).toBe(1_000);
  });
});

describe("concurrent tool calls settle against their own authorizations", () => {
  it("two different calls in flight do not cross their intent ids", async () => {
    const { sdk, limiter } = setup();
    const a = { id: "t-a", amountMinor: 1_000 };
    const b = { id: "t-b", amountMinor: 2_000 };
    await sdk.preToolUse({ tool_name: "buy_credits", tool_input: a });
    await sdk.preToolUse({ tool_name: "buy_credits", tool_input: b });
    // Settle out of order, as a real framework would.
    await sdk.postToolUse({ tool_name: "buy_credits", tool_input: b, tool_response: {} });
    await sdk.postToolUse({ tool_name: "buy_credits", tool_input: a, tool_response: {} });
    const t = await limiter.totalsSince(policy.id, since(), "USD");
    expect(t.totalMinor).toBe(3_000);
    expect(t.count).toBe(2);
  });
});

describe("matching PostToolUse to its authorization", () => {
  it("settles even if the host reordered the tool_input keys", async () => {
    // Found by probing: with plain JSON.stringify the match was LOST here, the
    // spend never settled, and the reservation held budget until its window
    // rolled off. Safe direction, still a bug — the cap silently starves.
    const { sdk, guard, limiter } = setup();
    await sdk.preToolUse({
      tool_name: "buy_credits",
      tool_input: { id: "t-1", amountMinor: 1_000 },
    });
    await sdk.postToolUse({
      tool_name: "buy_credits",
      tool_input: { amountMinor: 1_000, id: "t-1" },
      tool_response: {},
    });
    // Proof it truly settled, not merely that the amount is still held: a held
    // reservation and a committed spend show identical totals, so ask whether
    // it can still be released. A settled-executed spend cannot be.
    await guard.releaseSpend("t-1");
    const t = await limiter.totalsSince(policy.id, since(), "USD");
    expect(t.totalMinor).toBe(1_000);
  });

  it("settles through nested key reordering too", async () => {
    const { sdk, guard, limiter } = setup();
    const pre = { id: "t-1", amountMinor: 1_000, meta: { a: 1, b: [{ x: 1, y: 2 }] } };
    const post = { meta: { b: [{ y: 2, x: 1 }], a: 1 }, amountMinor: 1_000, id: "t-1" };
    await sdk.preToolUse({ tool_name: "buy_credits", tool_input: pre });
    await sdk.postToolUse({ tool_name: "buy_credits", tool_input: post, tool_response: {} });
    await guard.releaseSpend("t-1");
    const t = await limiter.totalsSince(policy.id, since(), "USD");
    expect(t.totalMinor).toBe(1_000);
  });

  it("does NOT match two genuinely different calls", async () => {
    const { sdk, limiter } = setup();
    await sdk.preToolUse({
      tool_name: "buy_credits",
      tool_input: { id: "t-1", amountMinor: 1_000 },
    });
    await sdk.postToolUse({
      tool_name: "buy_credits",
      tool_input: { id: "t-2", amountMinor: 1_000 },
      tool_response: {},
    });
    // t-1 stays held (unsettled), and nothing was invented for t-2.
    const t = await limiter.totalsSince(policy.id, since(), "USD");
    expect(t.count).toBe(1);
  });

  it("does not throw on a circular tool_input — the reservation is already held", async () => {
    // JSON.stringify throws here, and the throw would escape AFTER the budget
    // was reserved.
    const { sdk } = setup();
    const circular: Record<string, unknown> = { id: "t-1", amountMinor: 100 };
    circular.self = circular;
    const out = await sdk.preToolUse({ tool_name: "buy_credits", tool_input: circular });
    expect(decisionOf(out)).toBe("allow");
    await expect(
      sdk.postToolUse({ tool_name: "buy_credits", tool_input: circular, tool_response: {} }),
    ).resolves.toBeUndefined();
  });

  it("does not throw on a BigInt in tool_input", async () => {
    const { sdk } = setup();
    const input = { id: "t-1", amountMinor: 100, big: BigInt(9) };
    const out = await sdk.preToolUse({ tool_name: "buy_credits", tool_input: input });
    expect(decisionOf(out)).toBe("allow");
    await expect(
      sdk.postToolUse({ tool_name: "buy_credits", tool_input: input, tool_response: {} }),
    ).resolves.toBeUndefined();
  });
});

describe("the in-flight map", () => {
  it("hands back each entry once and then forgets it", async () => {
    const m = memoryInFlight();
    m.remember("k", "i-1");
    expect(m.take("k")).toEqual({ intentId: "i-1" });
    expect(m.take("k")).toBeNull();
  });

  it("is replaceable, so a long-lived host can supply its own storage", async () => {
    const seen: string[] = [];
    const sdk = bindClaudeAgentSdk(setup().hooks, {
      remember: (k) => {
        seen.push(k);
      },
      take: () => null,
    });
    await sdk.preToolUse({
      tool_name: "buy_credits",
      tool_input: { id: "t-1", amountMinor: 100 },
    });
    expect(seen).toHaveLength(1);
  });
});

describe("the contract OBSERVED against a live Claude Code session", () => {
  // These payloads are not invented. They were captured by a passive hook in a
  // real session (examples/cli-agent-hook) and reduced to the fields this
  // binding reads. Each test below pins a mismatch that shipped in 0.5.0.

  it("a non-payment tool yields NO OPINION, never an allow", async () => {
    // THE 0.5.0 BUG. `permissionDecision: "allow"` short-circuits the host's
    // own permission evaluation, so a `*`-matcher registration made this spend
    // firewall auto-approve every unrelated tool in the session — Bash, Write,
    // everything. An empty object is the only safe answer for "not my business".
    const { sdk } = setup();
    const out = await sdk.preToolUse({
      tool_name: "Bash",
      tool_input: { command: "ls -la" },
      tool_use_id: "toolu_01W7XaKA7CTj1wr4H1KBVkBh",
    });
    expect(out).toEqual({});
    expect("hookSpecificOutput" in out).toBe(false);
  });

  it("a payment tool still decides, and names the intent", async () => {
    const { sdk } = setup();
    const out = await sdk.preToolUse({
      tool_name: "buy_credits",
      tool_input: { id: "t-1", amountMinor: 900 },
      tool_use_id: "toolu_abc",
    });
    expect(decisionOf(out as never)).toBe("allow");
  });

  it("correlates on tool_use_id, so a re-serialized tool_input still settles", async () => {
    // Every observed event carries the host's own correlation id. Using it
    // removes the whole class of mismatch the input fingerprint had.
    const { sdk, guard, limiter } = setup();
    await sdk.preToolUse({
      tool_name: "buy_credits",
      tool_input: { id: "t-1", amountMinor: 1_000 },
      tool_use_id: "toolu_same",
    });
    await sdk.postToolUse({
      tool_name: "buy_credits",
      // Deliberately NOT the same object shape — only the id matches.
      tool_input: { totally: "different" },
      tool_use_id: "toolu_same",
      tool_response: { stdout: "ok", stderr: "", interrupted: false },
    });
    await guard.releaseSpend("t-1");
    const t = await limiter.totalsSince(policy.id, since(), "USD");
    expect(t.totalMinor).toBe(1_000);
  });

  it("SETTLES A FAILED TOOL from the separate failure event", async () => {
    // Observed: a failed tool produces NO PostToolUse — it raises a distinct
    // event carrying `error` and no `tool_response`. Before this handler
    // existed the authorization was never settled and held budget until its
    // window aged out.
    const { sdk, limiter } = setup();
    await sdk.preToolUse({
      tool_name: "buy_credits",
      tool_input: { id: "t-1", amountMinor: 1_000 },
      tool_use_id: "toolu_fail",
    });
    await sdk.postToolUseFailure({
      tool_name: "buy_credits",
      tool_input: { id: "t-1", amountMinor: 1_000 },
      tool_use_id: "toolu_fail",
      error: "Exit code 9",
    });
    // Burn on failure: the rail may have charged before the tool died.
    const t = await limiter.totalsSince(policy.id, since(), "USD");
    expect(t.totalMinor).toBe(1_000);
  });

  it("treats a user INTERRUPT as a failure too — it says nothing about the rail", async () => {
    const { sdk, limiter } = setup();
    await sdk.preToolUse({
      tool_name: "buy_credits",
      tool_input: { id: "t-1", amountMinor: 1_000 },
      tool_use_id: "toolu_int",
    });
    await sdk.postToolUseFailure({
      tool_name: "buy_credits",
      tool_input: { id: "t-1", amountMinor: 1_000 },
      tool_use_id: "toolu_int",
      is_interrupt: true,
    });
    const t = await limiter.totalsSince(policy.id, since(), "USD");
    expect(t.totalMinor).toBe(1_000);
  });

  it("a failure for a tool we never authorized settles nothing", async () => {
    const { sdk, limiter } = setup();
    await sdk.postToolUseFailure({
      tool_name: "Bash",
      tool_input: { command: "false" },
      tool_use_id: "toolu_unrelated",
      error: "Exit code 1",
    });
    const t = await limiter.totalsSince(policy.id, since(), "USD");
    expect(t.count).toBe(0);
  });
});
