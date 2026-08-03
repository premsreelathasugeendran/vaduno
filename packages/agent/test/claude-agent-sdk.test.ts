/**
 * The Claude Agent SDK binding.
 *
 * SCOPE: these tests prove the TRANSLATION is right — that a deny becomes a
 * deny, that only authorized calls get settled, that a crash reads as deny.
 * They cannot prove the hook wire shape matches a live SDK, because nothing
 * here has run against one. That gap is stated in the source and the README
 * rather than papered over with a mock that would just assert my own guess
 * back at me.
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
import { bindClaudeAgentSdk, memoryInFlight } from "../src/claude-agent-sdk.js";

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

const decisionOf = (out: { hookSpecificOutput: { permissionDecision: string } }) =>
  out.hookSpecificOutput.permissionDecision;

const since = () => new Date(Date.now() - 86_400_000).toISOString();

describe("PreToolUse translates the decision", () => {
  it("allows a non-payment tool", async () => {
    const { sdk } = setup();
    const out = await sdk.preToolUse({ tool_name: "read_file", tool_input: { p: "a" } });
    expect(decisionOf(out)).toBe("allow");
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

  it("tags the event name the SDK expects", async () => {
    const { sdk } = setup();
    const out = await sdk.preToolUse({ tool_name: "read_file", tool_input: {} });
    expect(out.hookSpecificOutput.hookEventName).toBe("PreToolUse");
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
