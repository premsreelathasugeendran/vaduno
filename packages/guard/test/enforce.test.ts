import { describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLedger } from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import {
  MandateManager,
  generateMandateKeyPair,
  mandateContextHash,
} from "../src/mandate/mandate.js";
import { FileConsumeStore } from "../src/enforce/file-consume-store.js";
import { MemoryConsumeStore, intentDigest } from "../src/enforce/consume-store.js";
import { VadunoGuard } from "../src/guard.js";
import { makeIntent, makePolicy } from "./helpers.js";

const keys = generateMandateKeyPair();

function setup(opts: { maxUses?: number; contextHash?: string } = {}) {
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const mandates = new MandateManager(keys, ledger);
  const guard = new VadunoGuard({ policy: makePolicy(), ledger, mandates });
  return { ledger, mandates, guard, opts };
}

async function issueMandate(
  mandates: MandateManager,
  opts: { maxUses?: number; contextHash?: string } = {},
) {
  return mandates.issue({
    issuer: "prem",
    agentId: "agent-1",
    constraints: {
      maxAmountMinor: 10_000,
      currency: "USD",
      validFrom: new Date(Date.now() - 1000).toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      maxUses: opts.maxUses ?? 1,
      ...(opts.contextHash !== undefined ? { contextHash: opts.contextHash } : {}),
    },
  });
}

describe("runtime mandate enforcement — THE concurrency test", () => {
  it("two identical consume requests in parallel: exactly one executes, the other replays the original verdict", async () => {
    const { mandates, guard } = setup();
    const mandate = await issueMandate(mandates, { maxUses: 1 });
    const intent = makeIntent({ id: "retry-storm-1", mandateId: mandate.id });

    let executions = 0;
    const executor = async () => {
      executions += 1;
      return { charged: true };
    };

    const [a, b] = await Promise.all([
      guard.execute(intent, executor),
      guard.execute(intent, executor),
    ]);

    // Exactly one settles; the rail ran exactly once.
    expect(executions).toBe(1);
    const statuses = [a.status, b.status].sort();
    expect(statuses).toEqual(["executed", "replayed"]);

    // The replay reports the ORIGINAL outcome, not a fresh denial.
    const replay = a.status === "replayed" ? a : b;
    if (replay.status !== "replayed") throw new Error("unreachable");
    expect(replay.original.status).toBe("executed");
    expect(replay.mandateId).toBe(mandate.id);
  });

  it("a 10-way retry storm still executes exactly once", async () => {
    const { mandates, guard } = setup();
    const mandate = await issueMandate(mandates, { maxUses: 5 });
    const intent = makeIntent({ id: "storm", mandateId: mandate.id });
    let executions = 0;

    const results = await Promise.all(
      Array.from({ length: 10 }, () =>
        guard.execute(intent, async () => {
          executions += 1;
          return "ok";
        }),
      ),
    );
    expect(executions).toBe(1);
    expect(results.filter((r) => r.status === "executed")).toHaveLength(1);
    expect(results.filter((r) => r.status === "replayed")).toHaveLength(9);
  });

  it("two DIFFERENT intents racing a single-use mandate: one executes, one is denied USES_EXHAUSTED", async () => {
    const { mandates, guard } = setup();
    const mandate = await issueMandate(mandates, { maxUses: 1 });
    let executions = 0;
    const executor = async () => {
      executions += 1;
      return "ok";
    };

    const [a, b] = await Promise.all([
      guard.execute(makeIntent({ id: "race-a", mandateId: mandate.id }), executor),
      guard.execute(makeIntent({ id: "race-b", mandateId: mandate.id }), executor),
    ]);
    expect(executions).toBe(1);
    const statuses = [a.status, b.status].sort();
    expect(statuses).toEqual(["denied", "executed"]);
    const denied = a.status === "denied" ? a : b;
    if (denied.status !== "denied") throw new Error("unreachable");
    expect(denied.policyResult.reasons.some((r) => r.code === "MANDATE_USES_EXHAUSTED")).toBe(true);
  });
});

describe("idempotent replay semantics", () => {
  it("a sequential retry replays the executed outcome without re-running the rail", async () => {
    const { mandates, guard } = setup();
    const mandate = await issueMandate(mandates, { maxUses: 3 });
    const intent = makeIntent({ id: "retry-1", mandateId: mandate.id });
    let executions = 0;

    const first = await guard.execute(intent, async () => {
      executions += 1;
      return "paid";
    });
    expect(first.status).toBe("executed");

    const second = await guard.execute(intent, async () => {
      executions += 1;
      return "paid-again";
    });
    expect(executions).toBe(1);
    expect(second.status).toBe("replayed");
    if (second.status !== "replayed") throw new Error("unreachable");
    expect(second.original.status).toBe("executed");
  });

  it("a retry after executor failure replays 'failed' (burn-on-failure preserved)", async () => {
    const { mandates, guard } = setup();
    const mandate = await issueMandate(mandates, { maxUses: 3 });
    const intent = makeIntent({ id: "fail-then-retry", mandateId: mandate.id });

    const first = await guard.execute(intent, async () => {
      throw new Error("rail timeout");
    });
    expect(first.status).toBe("failed");

    let executions = 0;
    const second = await guard.execute(intent, async () => {
      executions += 1;
      return "should not run";
    });
    expect(executions).toBe(0);
    expect(second.status).toBe("replayed");
    if (second.status !== "replayed") throw new Error("unreachable");
    expect(second.original.status).toBe("failed");
    expect(second.original.error).toBe("rail timeout");
  });

  it("the same intent id with DIFFERENT money fields is denied, never replayed, never executed", async () => {
    const { mandates, guard } = setup();
    const mandate = await issueMandate(mandates, { maxUses: 5 });
    const intent = makeIntent({ id: "reuse-attack", mandateId: mandate.id });
    await guard.execute(intent, async () => "ok");

    let executions = 0;
    const attack = await guard.execute(
      makeIntent({
        id: "reuse-attack",
        mandateId: mandate.id,
        // Different amount — still inside policy, so only the digest check
        // stands between this and a replay/execution.
        amount: { amountMinor: 600, currency: "USD" },
      }),
      async () => {
        executions += 1;
        return "stolen";
      },
    );
    expect(executions).toBe(0);
    expect(attack.status).toBe("denied");
    if (attack.status !== "denied") throw new Error("unreachable");
    expect(
      attack.policyResult.reasons.some((r) => r.code === "MANDATE_REPLAY_MISMATCH"),
    ).toBe(true);
  });

  it("a claim that never settled (crash mid-execution) replays 'unresolved' and never re-executes", async () => {
    const store = new MemoryConsumeStore();
    const ledger = new AuditLedger(new MemoryLedgerStore());
    const mandates = new MandateManager(keys, ledger, () => new Date(), {
      consumeStore: store,
    });
    const guard = new VadunoGuard({ policy: makePolicy(), ledger, mandates });
    const mandate = await issueMandate(mandates, { maxUses: 2 });
    const intent = makeIntent({ id: "crashed-run", mandateId: mandate.id });

    // Simulate a prior process that claimed the use and crashed before settle.
    await store.claim(
      {
        mandateId: mandate.id,
        useKey: "crashed-run",
        intentDigest: intentDigest(intent),
        claimedAt: new Date().toISOString(),
        status: "pending",
      },
      2,
    );

    let executions = 0;
    const result = await guard.execute(intent, async () => {
      executions += 1;
      return "must not run";
    });
    expect(executions).toBe(0);
    expect(result.status).toBe("replayed");
    if (result.status !== "replayed") throw new Error("unreachable");
    expect(result.original.status).toBe("unresolved");
  });
});

describe("context binding (CONTEXT_MISMATCH)", () => {
  const context = {
    task: "trip-booking-2026-07-22-run3",
    agentId: "agent-1",
    merchantId: "openai",
  };

  async function boundSetup() {
    const s = setup();
    const mandate = await issueMandate(s.mandates, {
      maxUses: 3,
      contextHash: mandateContextHash(context),
    });
    return { ...s, mandate };
  }

  it("executes when the intent presents the exact bound context", async () => {
    const { guard, mandate } = await boundSetup();
    const result = await guard.execute(
      makeIntent({ id: "ctx-ok", mandateId: mandate.id, context }),
      async () => "ok",
    );
    expect(result.status).toBe("executed");
  });

  it("denies when the context is missing or different", async () => {
    const { guard, mandate } = await boundSetup();
    const missing = await guard.execute(
      makeIntent({ id: "ctx-missing", mandateId: mandate.id }),
      async () => "no",
    );
    expect(missing.status).toBe("denied");

    const different = await guard.execute(
      makeIntent({
        id: "ctx-diff",
        mandateId: mandate.id,
        context: { ...context, task: "some-other-task" },
      }),
      async () => "no",
    );
    expect(different.status).toBe("denied");
    if (different.status !== "denied") throw new Error("unreachable");
    expect(
      different.policyResult.reasons.some((r) => r.code === "MANDATE_CONTEXT_MISMATCH"),
    ).toBe(true);
  });

  it("a stolen context blob cannot be replayed at a different merchant", async () => {
    const { guard, mandate } = await boundSetup();
    // The attacker presents the EXACT blob (hash matches) but pays elsewhere.
    const result = await guard.execute(
      makeIntent({
        id: "ctx-steal",
        mandateId: mandate.id,
        merchant: { id: "evil-merchant" },
        context,
      }),
      async () => "no",
    );
    expect(result.status).toBe("denied");
    if (result.status !== "denied") throw new Error("unreachable");
    expect(
      result.policyResult.reasons.some((r) => r.code === "MANDATE_CONTEXT_MISMATCH"),
    ).toBe(true);
  });
});

describe("FileConsumeStore — cross-process atomicity", () => {
  function mkClaim(mandateId: string, useKey: string) {
    return {
      mandateId,
      useKey,
      intentDigest: "d".repeat(64),
      claimedAt: new Date().toISOString(),
      status: "pending" as const,
    };
  }

  it("two separate store instances racing the same use: exactly one winner", async () => {
    const dir = await mkdtemp(join(tmpdir(), "vaduno-consume-"));
    try {
      const file = join(dir, "consume.json");
      // Two instances simulate two processes sharing the registry file.
      const p1 = new FileConsumeStore(file);
      const p2 = new FileConsumeStore(file);
      const claim = mkClaim("m-1", "intent-1");
      const [a, b] = await Promise.all([p1.claim(claim, 1), p2.claim(claim, 1)]);
      expect([a.winner, b.winner].sort()).toEqual([false, true]);

      // The loser sees the winner's claim; counts agree across instances.
      expect(await p1.countClaims("m-1")).toBe(1);
      expect(await p2.countClaims("m-1")).toBe(1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("REGRESSION: two DIFFERENT intents racing a single-use budget across instances — exactly one wins", async () => {
    // The confirmed critical: a check-then-act maxUses gate let both win.
    // maxUses is now enforced INSIDE the locked claim, so the budget holds.
    const dir = await mkdtemp(join(tmpdir(), "vaduno-budget-"));
    try {
      const file = join(dir, "consume.json");
      const p1 = new FileConsumeStore(file);
      const p2 = new FileConsumeStore(file);
      const [a, b] = await Promise.all([
        p1.claim(mkClaim("m-1", "intent-A"), 1),
        p2.claim(mkClaim("m-1", "intent-B"), 1),
      ]);
      const winners = [a, b].filter((r) => r.winner).length;
      expect(winners).toBe(1);
      const loser = a.winner ? b : a;
      expect(loser.winner).toBe(false);
      if (!loser.winner) expect(loser.reason).toBe("exhausted");
      expect(await p1.countClaims("m-1")).toBe(1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("enforces a multi-use budget: N winners for maxUses=N under a racing storm", async () => {
    const dir = await mkdtemp(join(tmpdir(), "vaduno-budgetN-"));
    try {
      const file = join(dir, "consume.json");
      const stores = Array.from({ length: 8 }, () => new FileConsumeStore(file));
      const results = await Promise.all(
        stores.map((s, i) => s.claim(mkClaim("m-1", `intent-${i}`), 3)),
      );
      expect(results.filter((r) => r.winner)).toHaveLength(3);
      expect(await stores[0]!.countClaims("m-1")).toBe(3);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("no lost writes under a healthy lock: 12 distinct claims across 2 instances all land", async () => {
    // Exercises acquire/release heavily. With the owner-token release, an
    // instance never deletes the other's lock, so every distinct claim is
    // recorded exactly once (no lost update). Default lock window (~1s) so the
    // test is not racing the retry budget on a slow filesystem.
    const dir = await mkdtemp(join(tmpdir(), "vaduno-lock-"));
    try {
      const file = join(dir, "consume.json");
      const a = new FileConsumeStore(file);
      const b = new FileConsumeStore(file);
      const results = await Promise.all(
        Array.from({ length: 12 }, (_, i) =>
          (i % 2 === 0 ? a : b).claim(mkClaim("m-1", `use-${i}`), 100),
        ),
      );
      expect(results.every((r) => r.winner)).toBe(true);
      expect(await a.countClaims("m-1")).toBe(12);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("settle is first-write-wins and survives a second instance", async () => {
    const dir = await mkdtemp(join(tmpdir(), "vaduno-settle-"));
    try {
      const file = join(dir, "consume.json");
      const p1 = new FileConsumeStore(file);
      await p1.claim(mkClaim("m-1", "i-1"), 1);
      await p1.settle("m-1", "i-1", {
        status: "executed",
        settledAt: new Date().toISOString(),
      });
      await p1.settle("m-1", "i-1", {
        status: "failed",
        settledAt: new Date().toISOString(),
        error: "late overwrite attempt",
      });
      const p2 = new FileConsumeStore(file);
      const claim = await p2.get("m-1", "i-1");
      expect(claim?.status).toBe("settled");
      expect(claim?.outcome?.status).toBe("executed");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("two MandateManagers over one FileConsumeStore: a single-use mandate executes exactly once", async () => {
    // End-to-end version of the critical finding, through the guard.
    const dir = await mkdtemp(join(tmpdir(), "vaduno-mgr-"));
    try {
      const file = join(dir, "consume.json");
      const store1 = new FileConsumeStore(file);
      const store2 = new FileConsumeStore(file);
      const ledger1 = new AuditLedger(new MemoryLedgerStore());
      const ledger2 = new AuditLedger(new MemoryLedgerStore());
      const m1 = new MandateManager(keys, ledger1, () => new Date(), { consumeStore: store1 });
      const m2 = new MandateManager(keys, ledger2, () => new Date(), { consumeStore: store2 });
      const mandate = await m1.issue({
        issuer: "prem",
        agentId: "agent-1",
        constraints: {
          maxAmountMinor: 10_000,
          currency: "USD",
          validFrom: new Date(Date.now() - 1000).toISOString(),
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
          maxUses: 1,
        },
      });
      m2.register(mandate);
      const g1 = new VadunoGuard({ policy: makePolicy(), ledger: ledger1, mandates: m1 });
      const g2 = new VadunoGuard({ policy: makePolicy(), ledger: ledger2, mandates: m2 });

      let executions = 0;
      const exec = async () => {
        executions += 1;
        return "ok";
      };
      const [a, b] = await Promise.all([
        g1.execute(makeIntent({ id: "proc-a", mandateId: mandate.id }), exec),
        g2.execute(makeIntent({ id: "proc-b", mandateId: mandate.id }), exec),
      ]);
      expect(executions).toBe(1);
      expect([a.status, b.status].sort()).toEqual(["denied", "executed"]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("hydrateFromLedger rebuilds the consume registry", () => {
  it("a retry after restart replays instead of re-executing", async () => {
    const ledgerStore = new MemoryLedgerStore();
    const ledger = new AuditLedger(ledgerStore);
    const mandates = new MandateManager(keys, ledger);
    const guard = new VadunoGuard({ policy: makePolicy(), ledger, mandates });
    const mandate = await issueMandate(mandates, { maxUses: 3 });
    const intent = makeIntent({ id: "before-restart", mandateId: mandate.id });
    const first = await guard.execute(intent, async () => "ok");
    expect(first.status).toBe("executed");

    // "Restart": fresh manager + guard over the SAME persisted ledger.
    const ledger2 = new AuditLedger(ledgerStore);
    const mandates2 = new MandateManager(keys, ledger2);
    await mandates2.hydrateFromLedger();
    const guard2 = new VadunoGuard({ policy: makePolicy(), ledger: ledger2, mandates: mandates2 });

    let executions = 0;
    const retry = await guard2.execute(intent, async () => {
      executions += 1;
      return "must not run";
    });
    expect(executions).toBe(0);
    expect(retry.status).toBe("replayed");
    if (retry.status !== "replayed") throw new Error("unreachable");
    expect(retry.original.status).toBe("executed");

    // And the use count survived: two more uses left, a third intent works.
    const fresh = await guard2.execute(
      makeIntent({ id: "after-restart", mandateId: mandate.id }),
      async () => "ok",
    );
    expect(fresh.status).toBe("executed");
  });
});
