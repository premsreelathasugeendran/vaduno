/**
 * The framework-agnostic decision core.
 *
 * WHAT THIS HAS TO PROVE: an agent framework's hook is the ONLY place the guard
 * gets consulted on that path. If the hook can be made to say "allow" when the
 * policy says no — by a rotated tool name, a throwing resolver, a replayed
 * intent — then the firewall is decorative for every framework user.
 */
import { describe, expect, it } from "vitest";
import {
  AuditLedger,
  MemoryLedgerStore,
  MemorySpendLimiter,
  VadunoGuard,
} from "@vaduno/guard";
import type { PaymentIntent, SpendPolicy } from "@vaduno/guard";
import { createSpendHooks, replayReason } from "../src/hooks.js";
import type { SpendDecision } from "../src/hooks.js";

const CAP = 5_000;

const policy: SpendPolicy = {
  id: "agent-hooks",
  version: 1,
  currency: "USD",
  limits: { perTransactionMinor: 5_000, perDayMinor: CAP },
  merchants: { allow: ["openai.com"] },
};

function newGuard(limiter = new MemorySpendLimiter()) {
  const guard = new VadunoGuard({
    policy,
    ledger: new AuditLedger(new MemoryLedgerStore()),
    limiter,
  });
  return { guard, limiter };
}

function intentFor(id: string, amountMinor: number, host = "api.openai.com"): PaymentIntent {
  return {
    id,
    agentId: "agent-1",
    merchant: { id: "m", url: `https://${host}/v1/pay` },
    amount: { amountMinor, currency: "USD" },
    category: "api-credits",
    rail: "mock",
    requestedAt: new Date().toISOString(),
  };
}

/** The caller-supplied resolver: `buy_credits` spends, everything else doesn't. */
function standardResolve(call: { toolName: string; input: unknown }): PaymentIntent | null {
  if (call.toolName !== "buy_credits") return null;
  const i = call.input as { id: string; amountMinor: number; host?: string };
  return intentFor(i.id, i.amountMinor, i.host);
}

const since = () => new Date(Date.now() - 86_400_000).toISOString();

describe("tools that do not spend are left alone", () => {
  it("returns not-a-payment when the resolver returns null", async () => {
    const { guard } = newGuard();
    const hooks = createSpendHooks({ guard, resolve: standardResolve });
    const d = await hooks.decide({ toolName: "read_file", input: { path: "a.txt" } });
    expect(d.kind).toBe("not-a-payment");
  });

  it("records nothing against the budget for a non-payment tool", async () => {
    const { guard, limiter } = newGuard();
    const hooks = createSpendHooks({ guard, resolve: standardResolve });
    await hooks.decide({ toolName: "read_file", input: {} });
    const t = await limiter.totalsSince(policy.id, since(), "USD");
    expect(t.count).toBe(0);
  });
});

describe("a spending tool is decided by the policy, not the model", () => {
  it("allows a permitted spend and returns the settlement key", async () => {
    const { guard } = newGuard();
    const hooks = createSpendHooks({ guard, resolve: standardResolve });
    const d = await hooks.decide({
      toolName: "buy_credits",
      input: { id: "t-1", amountMinor: 900 },
    });
    expect(d).toMatchObject({ kind: "allow", intentId: "t-1" });
  });

  it("denies over the per-transaction limit, with the policy's own code", async () => {
    const { guard } = newGuard();
    const hooks = createSpendHooks({ guard, resolve: standardResolve });
    const d = await hooks.decide({
      toolName: "buy_credits",
      input: { id: "t-1", amountMinor: 999_999 },
    });
    expect(d.kind).toBe("deny");
    if (d.kind !== "deny") throw new Error("unreachable");
    expect(d.code).toMatch(/LIMIT|TRANSACTION/i);
  });

  it("denies a merchant outside the allowlist", async () => {
    const { guard } = newGuard();
    const hooks = createSpendHooks({ guard, resolve: standardResolve });
    const d = await hooks.decide({
      toolName: "buy_credits",
      input: { id: "t-1", amountMinor: 100, host: "evil-openai.com" },
    });
    expect(d.kind).toBe("deny");
  });
});

describe("an allow holds budget — otherwise the cap is advisory", () => {
  it("a second decide cannot pass the same cap the first one consumed", async () => {
    // If decide() only rendered an opinion without reserving, an agent making
    // two tool calls before either settles would be told yes twice.
    const { guard } = newGuard();
    const hooks = createSpendHooks({ guard, resolve: standardResolve });
    const a = await hooks.decide({
      toolName: "buy_credits",
      input: { id: "t-1", amountMinor: CAP },
    });
    const b = await hooks.decide({
      toolName: "buy_credits",
      input: { id: "t-2", amountMinor: CAP },
    });
    expect(a.kind).toBe("allow");
    expect(b.kind).toBe("deny");
  });

  it("CONCURRENCY: parallel tool calls never exceed the cap in total", async () => {
    const { guard } = newGuard();
    const hooks = createSpendHooks({ guard, resolve: standardResolve });
    const decisions = await Promise.all(
      Array.from({ length: 12 }, (_, i) =>
        hooks.decide({
          toolName: "buy_credits",
          input: { id: `t-${i}`, amountMinor: 1_000 },
        }),
      ),
    );
    expect(decisions.filter((d) => d.kind === "allow")).toHaveLength(CAP / 1_000);
  });

  it("holds across two hook instances sharing one guard-side limiter", async () => {
    // Two frameworks, or two sessions, in one process.
    const limiter = new MemorySpendLimiter();
    const one = createSpendHooks({
      guard: newGuard(limiter).guard,
      resolve: standardResolve,
    });
    const two = createSpendHooks({
      guard: newGuard(limiter).guard,
      resolve: standardResolve,
    });
    expect(
      (await one.decide({ toolName: "buy_credits", input: { id: "t-1", amountMinor: CAP } }))
        .kind,
    ).toBe("allow");
    expect(
      (await two.decide({ toolName: "buy_credits", input: { id: "t-2", amountMinor: CAP } }))
        .kind,
    ).toBe("deny");
  });
});

describe("the resolver is the caller's code, so it is treated as fallible", () => {
  it("DENIES when resolve throws — an unknown spend is never allowed", async () => {
    const { guard } = newGuard();
    const hooks = createSpendHooks({
      guard,
      resolve: () => {
        throw new Error("price lookup timed out");
      },
    });
    const d = await hooks.decide({ toolName: "buy_credits", input: {} });
    expect(d.kind).toBe("deny");
    if (d.kind !== "deny") throw new Error("unreachable");
    expect(d.code).toBe("INTENT_RESOLVE_FAILED");
    expect(d.reason).toContain("price lookup timed out");
  });

  it("DENIES when resolve rejects asynchronously", async () => {
    const { guard } = newGuard();
    const hooks = createSpendHooks({
      guard,
      resolve: async () => {
        throw new Error("network");
      },
    });
    expect((await hooks.decide({ toolName: "buy_credits", input: {} })).kind).toBe("deny");
  });

  it("lets the caller override the failure mode, and honours it", async () => {
    // Documented escape hatch. The test exists so the override is a real
    // decision point rather than an accident of the default path.
    const { guard } = newGuard();
    const allowAnyway: SpendDecision = { kind: "not-a-payment" };
    const hooks = createSpendHooks({
      guard,
      resolve: () => {
        throw new Error("x");
      },
      onResolveError: () => allowAnyway,
    });
    expect((await hooks.decide({ toolName: "buy_credits", input: {} })).kind).toBe(
      "not-a-payment",
    );
  });
});

describe("a replayed intent id is denied, not silently re-run", () => {
  it("denies the second decide on an already-settled intent id", async () => {
    // The rail already ran for this id. "Allow" here would run it twice, which
    // is exactly what consume-once exists to stop.
    const { guard } = newGuard();
    const hooks = createSpendHooks({ guard, resolve: standardResolve });
    await hooks.decide({ toolName: "buy_credits", input: { id: "t-1", amountMinor: 100 } });
    await hooks.settled("t-1", { ok: true });

    const again = await hooks.decide({
      toolName: "buy_credits",
      input: { id: "t-1", amountMinor: 100 },
    });
    expect(again.kind).toBe("deny");
    if (again.kind !== "deny") throw new Error("unreachable");
    expect(again.code).toBe("ALREADY_EXECUTED");
  });

  it("does NOT claim a payment executed when the first attempt is still outstanding", async () => {
    // An authorization that has not settled replays as "unresolved". Reporting
    // that to the model as "already executed" would invite it to tell the user
    // a charge succeeded when nobody knows whether it did.
    const { guard } = newGuard();
    const hooks = createSpendHooks({ guard, resolve: standardResolve });
    await hooks.decide({ toolName: "buy_credits", input: { id: "t-1", amountMinor: 100 } });
    const dup = await hooks.decide({
      toolName: "buy_credits",
      input: { id: "t-1", amountMinor: 100 },
    });
    expect(dup.kind).toBe("deny");
    if (dup.kind !== "deny") throw new Error("unreachable");
    expect(dup.code).toBe("INTENT_UNRESOLVED");
    expect(dup.reason).not.toMatch(/already paid|already executed/i);
  });

  it("still says UNRESOLVED after a failed settle — a failed rail may have charged", async () => {
    // Checked against the guard rather than assumed: settling "failed" leaves
    // the reservation held, and a duplicate replays as unresolved. That is the
    // honest answer, because a rail that threw may still have moved money.
    const { guard } = newGuard();
    const hooks = createSpendHooks({ guard, resolve: standardResolve });
    await hooks.decide({ toolName: "buy_credits", input: { id: "t-1", amountMinor: 100 } });
    await hooks.settled("t-1", { ok: false, error: "declined" });
    const dup = await hooks.decide({
      toolName: "buy_credits",
      input: { id: "t-1", amountMinor: 100 },
    });
    if (dup.kind !== "deny") throw new Error("expected deny");
    expect(dup.code).toBe("INTENT_UNRESOLVED");
  });

  it("the three replay states map to three distinct, non-contradictory messages", () => {
    // The "failed" branch comes only from a mandate's consume-once registry, so
    // it is asserted directly rather than left as the one untested string.
    const executed = replayReason("i", "executed");
    const failed = replayReason("i", "failed");
    const unresolved = replayReason("i", "unresolved");

    expect(new Set([executed.code, failed.code, unresolved.code]).size).toBe(3);
    expect(executed.reason).toMatch(/already paid/i);
    expect(failed.reason).toMatch(/failed/i);
    // Neither of the not-known-to-have-paid states may imply payment happened.
    expect(failed.reason).not.toMatch(/already paid/i);
    expect(unresolved.reason).not.toMatch(/already paid|failed/i);
    expect(unresolved.reason).toMatch(/unknown|reconcile/i);
  });

  it("does NOT double-count the budget on the replayed attempt", async () => {
    const { guard, limiter } = newGuard();
    const hooks = createSpendHooks({ guard, resolve: standardResolve });
    await hooks.decide({ toolName: "buy_credits", input: { id: "t-1", amountMinor: 100 } });
    await hooks.settled("t-1", { ok: true });
    await hooks.decide({ toolName: "buy_credits", input: { id: "t-1", amountMinor: 100 } });

    const t = await limiter.totalsSince(policy.id, since(), "USD");
    expect(t.totalMinor).toBe(100);
  });
});

describe("settled reports the outcome and money follows the same rules as execute()", () => {
  it("ok:true commits the spend", async () => {
    const { guard, limiter } = newGuard();
    const hooks = createSpendHooks({ guard, resolve: standardResolve });
    await hooks.decide({ toolName: "buy_credits", input: { id: "t-1", amountMinor: 1_000 } });
    await hooks.settled("t-1", { ok: true });
    const t = await limiter.totalsSince(policy.id, since(), "USD");
    expect(t.totalMinor).toBe(1_000);
  });

  it("ok:false KEEPS the spend counted — a failed tool may still have charged", async () => {
    const { guard } = newGuard();
    const hooks = createSpendHooks({ guard, resolve: standardResolve });
    await hooks.decide({ toolName: "buy_credits", input: { id: "t-1", amountMinor: CAP } });
    await hooks.settled("t-1", { ok: false, error: "timeout after charge" });
    const next = await hooks.decide({
      toolName: "buy_credits",
      input: { id: "t-2", amountMinor: CAP },
    });
    expect(next.kind).toBe("deny");
  });

  it("an UNSETTLED allow keeps holding budget", async () => {
    // A framework that never fires its post-hook starves its own cap rather
    // than leaking spend. Over-hold, never overspend.
    const { guard } = newGuard();
    const hooks = createSpendHooks({ guard, resolve: standardResolve });
    await hooks.decide({ toolName: "buy_credits", input: { id: "t-1", amountMinor: CAP } });
    expect(
      (await hooks.decide({ toolName: "buy_credits", input: { id: "t-2", amountMinor: 1 } }))
        .kind,
    ).toBe("deny");
  });

  it("settled is idempotent for a retrying framework", async () => {
    const { guard, limiter } = newGuard();
    const hooks = createSpendHooks({ guard, resolve: standardResolve });
    await hooks.decide({ toolName: "buy_credits", input: { id: "t-1", amountMinor: 1_000 } });
    await hooks.settled("t-1", { ok: true });
    await hooks.settled("t-1", { ok: true });
    const t = await limiter.totalsSince(policy.id, since(), "USD");
    expect(t.totalMinor).toBe(1_000);
  });
});

describe("THE ADVERSARIAL CASE: an agent looping on its own tool", () => {
  it("cannot spend past the daily cap however many times it calls the tool", async () => {
    // The scenario the whole project exists for: a model in a retry loop,
    // calling a paid tool over and over. Each call is a fresh intent id, so
    // consume-once does not help here — only the reservation does.
    const { guard, limiter } = newGuard();
    const hooks = createSpendHooks({ guard, resolve: standardResolve });

    let allowed = 0;
    for (let i = 0; i < 50; i += 1) {
      const d = await hooks.decide({
        toolName: "buy_credits",
        input: { id: `loop-${i}`, amountMinor: 500 },
      });
      if (d.kind === "allow") {
        allowed += 1;
        await hooks.settled(`loop-${i}`, { ok: true });
      }
    }

    expect(allowed).toBe(CAP / 500);
    const t = await limiter.totalsSince(policy.id, since(), "USD");
    expect(t.totalMinor).toBe(CAP);
  });

  it("cannot escape the cap by rotating the agent id it reports", async () => {
    // A model that controls its own tool arguments controls agentId too. The
    // reservation is scoped to the POLICY, so rotating it changes nothing.
    const { guard, limiter } = newGuard();
    const hooks = createSpendHooks({
      guard,
      resolve: (call) => {
        const i = call.input as { id: string; agentId: string };
        return { ...intentFor(i.id, 2_000), agentId: i.agentId };
      },
    });

    for (let i = 0; i < 10; i += 1) {
      const d = await hooks.decide({
        toolName: "buy_credits",
        input: { id: `r-${i}`, agentId: `agent-${i}` },
      });
      if (d.kind === "allow") await hooks.settled(`r-${i}`, { ok: true });
    }

    const t = await limiter.totalsSince(policy.id, since(), "USD");
    expect(t.totalMinor).toBeLessThanOrEqual(CAP);
  });
});
