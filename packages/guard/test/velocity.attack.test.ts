/**
 * Velocity controls under ATTACK, end to end through the guard.
 *
 * Each test here is a named abuse pattern from the card networks' own
 * playbook — card-testing bursts, runaway retry loops, merchant rotation,
 * budget minting via id rotation, config poisoning — and each asserts the
 * exact number of times the rail ran. "Denied" is not enough; the executor
 * call count is the ground truth the caps exist to bound.
 */
import { describe, expect, it } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLedger } from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import { VadunoGuard, ledgerSpendHistory } from "../src/guard.js";
import { FileSpendLimiter } from "../src/enforce/file-spend-limiter.js";
import { MandateManager, generateMandateKeyPair } from "../src/mandate/mandate.js";
import { makeIntent, makePolicy } from "./helpers.js";
import type { GuardResult, PaymentIntent } from "../src/types.js";

function deniedCodes(results: Array<GuardResult<unknown>>): string[] {
  return results.flatMap((r) =>
    r.status === "denied" ? r.policyResult.reasons.map((x) => x.code) : [],
  );
}

describe("card-testing burst: one merchant, many small charges", () => {
  it("50 x 100-minor at one merchant under a $6k day cap + per-merchant 5/hour: exactly 5 reach the rail", async () => {
    const ledger = new AuditLedger(new MemoryLedgerStore());
    const guard = new VadunoGuard({
      policy: makePolicy({
        limits: { perDayMinor: 600_000 },
        velocity: { maxTransactionsPerMerchant: { count: 5, perSeconds: 3_600 } },
      }),
      ledger,
    });

    let railCalls = 0;
    const results: Array<GuardResult<unknown>> = [];
    for (let i = 0; i < 50; i += 1) {
      results.push(
        await guard.execute(
          makeIntent({
            id: `burst-${i}`,
            merchant: { id: "victim", url: "https://pay.victim.example/charge" },
            amount: { amountMinor: 100, currency: "USD" },
          }),
          async () => {
            railCalls += 1;
            return { ok: true };
          },
        ),
      );
    }

    expect(results.filter((r) => r.status === "executed")).toHaveLength(5);
    expect(railCalls).toBe(5);
    const denied = results.filter((r) => r.status === "denied");
    expect(denied).toHaveLength(45);
    const codes = deniedCodes(results);
    expect(codes).toContain("MERCHANT_VELOCITY_EXCEEDED");
    // The burst never came NEAR the amount caps — the count window is what
    // catches card testing, and no amount code may take the credit.
    expect(codes.filter((c) => c.includes("LIMIT_EXCEEDED"))).toHaveLength(0);
  });
});

describe("runaway loop: fresh ids forever", () => {
  it("500 one-cent intents under a global 20/day: 20 executed, 480 denied before the rail", async () => {
    const guard = new VadunoGuard({
      policy: makePolicy({
        limits: {},
        velocity: { maxTransactions: { count: 20, perSeconds: 86_400 } },
      }),
      ledger: new AuditLedger(new MemoryLedgerStore()),
    });

    let railCalls = 0;
    const results: Array<GuardResult<unknown>> = [];
    for (let i = 0; i < 500; i += 1) {
      results.push(
        await guard.execute(
          makeIntent({ id: `loop-${i}`, amount: { amountMinor: 1, currency: "USD" } }),
          async () => {
            railCalls += 1;
            return { ok: true };
          },
        ),
      );
    }

    expect(results.filter((r) => r.status === "executed")).toHaveLength(20);
    expect(railCalls).toBe(20);
    expect(results.filter((r) => r.status === "denied")).toHaveLength(480);
    expect(new Set(deniedCodes(results))).toEqual(new Set(["VELOCITY_EXCEEDED"]));
  });

  it("an always-THROWING executor still halts at 20 rail invocations (a failed slot is burned, not freed)", async () => {
    // Burn-on-failure is what makes the count window crash-loop-proof: if a
    // failure freed its slot, a retry loop with a broken rail would hammer
    // the rail without bound.
    const guard = new VadunoGuard({
      policy: makePolicy({
        limits: {},
        velocity: { maxTransactions: { count: 20, perSeconds: 86_400 } },
      }),
      ledger: new AuditLedger(new MemoryLedgerStore()),
    });

    let railCalls = 0;
    const results: Array<GuardResult<unknown>> = [];
    for (let i = 0; i < 100; i += 1) {
      results.push(
        await guard.execute(
          makeIntent({ id: `crash-${i}`, amount: { amountMinor: 1, currency: "USD" } }),
          async () => {
            railCalls += 1;
            throw new Error("rail down");
          },
        ),
      );
    }

    expect(railCalls).toBe(20);
    expect(results.filter((r) => r.status === "failed")).toHaveLength(20);
    expect(results.filter((r) => r.status === "denied")).toHaveLength(80);
  });
});

describe("merchant rotation: minting per-merchant budgets", () => {
  it("rotating id+host past a per-merchant 3/hour is stopped by the global 10/hour at exactly 10", async () => {
    // The layering claim, PROVED: per-merchant velocity alone is not a
    // security boundary (the attacker mints a fresh merchant each time), so
    // the rotation-proof global window underneath must be what holds.
    const guard = new VadunoGuard({
      policy: makePolicy({
        limits: {},
        velocity: {
          maxTransactions: { count: 10, perSeconds: 3_600 },
          maxTransactionsPerMerchant: { count: 3, perSeconds: 3_600 },
        },
      }),
      ledger: new AuditLedger(new MemoryLedgerStore()),
    });

    let railCalls = 0;
    const results: Array<GuardResult<unknown>> = [];
    for (let i = 0; i < 30; i += 1) {
      results.push(
        await guard.execute(
          makeIntent({
            id: `rot-${i}`,
            merchant: { id: `shop-${i}`, url: `https://shop-${i}.example/pay` },
            amount: { amountMinor: 100, currency: "USD" },
          }),
          async () => {
            railCalls += 1;
            return { ok: true };
          },
        ),
      );
    }

    expect(results.filter((r) => r.status === "executed")).toHaveLength(10);
    expect(railCalls).toBe(10);
    const codes = deniedCodes(results);
    // Every denial is the GLOBAL window: the per-merchant window never
    // trips (no merchant ever sees a second transaction).
    expect(new Set(codes)).toEqual(new Set(["VELOCITY_EXCEEDED"]));
  });
});

describe("agentId rotation: no count budget for a new name", () => {
  it("two guards, one shared FileSpendLimiter, alternating agentIds: a scope maxCount of 4 admits exactly 4 total", async () => {
    const dir = await mkdtemp(join(tmpdir(), "vaduno-velocity-"));
    try {
      const file = join(dir, "spend.json");
      const policy = makePolicy({
        limits: {},
        velocity: { maxTransactions: { count: 4, perSeconds: 3_600 } },
      });
      const mk = () =>
        new VadunoGuard({
          policy,
          ledger: new AuditLedger(new MemoryLedgerStore()),
          limiter: new FileSpendLimiter(file),
        });
      const guards = [mk(), mk()];

      let railCalls = 0;
      const results: Array<GuardResult<unknown>> = [];
      for (let i = 0; i < 12; i += 1) {
        results.push(
          await guards[i % 2]!.execute(
            makeIntent({
              id: `agent-rot-${i}`,
              agentId: `agent-${i % 2}`,
              amount: { amountMinor: 100, currency: "USD" },
            }),
            async () => {
              railCalls += 1;
              return { ok: true };
            },
          ),
        );
      }

      // The count budget is scoped to policy.id: neither the rotated agentId
      // nor the second process mints a fresh one.
      expect(results.filter((r) => r.status === "executed")).toHaveLength(4);
      expect(railCalls).toBe(4);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("config poisoning: corruption is a DoS, never an uncapped budget", () => {
  it("velocity {count: NaN} denies EVERYTHING with SPEND_WINDOW_INVALID and the rail never runs", async () => {
    const guard = new VadunoGuard({
      policy: makePolicy({
        velocity: { maxTransactions: { count: Number.NaN, perSeconds: 60 } },
      }),
      ledger: new AuditLedger(new MemoryLedgerStore()),
    });

    let railCalls = 0;
    const results: Array<GuardResult<unknown>> = [];
    for (let i = 0; i < 3; i += 1) {
      results.push(
        await guard.execute(makeIntent({ id: `poison-${i}` }), async () => {
          railCalls += 1;
          return { ok: true };
        }),
      );
    }

    expect(railCalls).toBe(0);
    for (const r of results) {
      expect(r.status).toBe("denied");
      if (r.status === "denied") {
        expect(r.policyResult.reasons.map((x) => x.code)).toContain("SPEND_WINDOW_INVALID");
      }
    }
  });
});

describe("pre-upgrade records: no velocity-free upgrade interval", () => {
  it("a 0.3.0-format spend file (records without merchantKey) counts toward every merchant window", async () => {
    const dir = await mkdtemp(join(tmpdir(), "vaduno-velocity-"));
    try {
      const file = join(dir, "spend.json");
      const T0 = Date.now();
      // EXACTLY what FileSpendLimiter 0.3.0 wrote: no merchantKey field.
      await writeFile(
        file,
        JSON.stringify({
          reservations: {
            "legacy-1": {
              reservationId: "legacy-1",
              scope: "s",
              currency: "USD",
              amountMinor: 100,
              ms: T0,
              state: "committed",
            },
            "legacy-2": {
              reservationId: "legacy-2",
              scope: "s",
              currency: "USD",
              amountMinor: 100,
              ms: T0,
              state: "reserved",
            },
          },
        }),
        "utf8",
      );

      const limiter = new FileSpendLimiter(file);
      const refused = await limiter.reserve({
        scope: "s",
        currency: "USD",
        amountMinor: 100,
        reservationId: "new-1",
        windows: [
          {
            code: "MERCHANT_VELOCITY_EXCEEDED",
            windowMs: 3_600_000,
            maxCount: 2,
            dimension: "merchant",
          },
        ],
        merchantKey: "host:never-seen-before.example",
        nowMs: T0 + 1,
      });
      expect(refused.ok).toBe(false);
      if (!refused.ok) expect(refused.code).toBe("MERCHANT_VELOCITY_EXCEEDED");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("hydrateFromLedger: 0.3.0-format execution_result rows (no merchantKey) count toward every merchant", async () => {
    const store = new MemoryLedgerStore();
    const ledger = new AuditLedger(store);
    // EXACTLY what execute() 0.3.0 recorded: success + economics, no
    // merchantKey.
    await ledger.append(
      "execution_result",
      { success: true, amountMinor: 100, currency: "USD", merchantId: "old", rail: "mock" },
      { intentId: "old-1", agentId: "a" },
    );

    const guard = new VadunoGuard({
      policy: makePolicy({
        limits: {},
        velocity: { maxTransactionsPerMerchant: { count: 1, perSeconds: 86_400 } },
      }),
      ledger,
      requireHydration: true,
    });
    const report = await guard.hydrateFromLedger();
    expect(report.restoredSpendRows).toBe(1);

    let railCalls = 0;
    const result = await guard.execute(
      makeIntent({
        id: "post-upgrade-1",
        merchant: { id: "fresh", url: "https://fresh.example/pay" },
        amount: { amountMinor: 100, currency: "USD" },
      }),
      async () => {
        railCalls += 1;
        return { ok: true };
      },
    );
    expect(result.status).toBe("denied");
    expect(railCalls).toBe(0);
    if (result.status === "denied") {
      expect(result.policyResult.reasons.map((x) => x.code)).toContain(
        "MERCHANT_VELOCITY_EXCEEDED",
      );
    }
  });
});

describe("restart: merchant counts survive hydrateFromLedger", () => {
  it("keyed rows restore per-merchant counts: the saturated merchant is denied, another is not", async () => {
    const store = new MemoryLedgerStore();
    const ledger = new AuditLedger(store);
    const permissive = makePolicy({ limits: {} });
    const g1 = new VadunoGuard({ policy: permissive, ledger });
    for (let i = 0; i < 2; i += 1) {
      const r = await g1.execute(
        makeIntent({
          id: `warm-${i}`,
          merchant: { id: "openai", url: "https://api.openai.com/v1" },
          amount: { amountMinor: 100, currency: "USD" },
        }),
        async () => ({ ok: true }),
      );
      expect(r.status).toBe("executed");
    }

    // Restart over the same ledger, now with a per-merchant window.
    const g2 = new VadunoGuard({
      policy: makePolicy({
        limits: {},
        velocity: { maxTransactionsPerMerchant: { count: 2, perSeconds: 86_400 } },
      }),
      ledger: new AuditLedger(store),
      requireHydration: true,
    });
    const report = await g2.hydrateFromLedger();
    expect(report.restoredSpendRows).toBe(2);

    const saturated = await g2.execute(
      makeIntent({
        id: "after-restart-1",
        merchant: { id: "openai", url: "https://api.openai.com/v1" },
        amount: { amountMinor: 100, currency: "USD" },
      }),
      async () => ({ ok: true }),
    );
    expect(saturated.status).toBe("denied");
    if (saturated.status === "denied") {
      expect(saturated.policyResult.reasons.map((x) => x.code)).toContain(
        "MERCHANT_VELOCITY_EXCEEDED",
      );
    }

    const other = await g2.execute(
      makeIntent({
        id: "after-restart-2",
        merchant: { id: "aws", url: "https://aws.amazon.com/pay" },
        amount: { amountMinor: 100, currency: "USD" },
      }),
      async () => ({ ok: true }),
    );
    expect(other.status).toBe("executed");
  });

  it("the two-phase settle row carries the merchantKey, so a restart counts it too", async () => {
    const store = new MemoryLedgerStore();
    const ledger = new AuditLedger(store);
    const g1 = new VadunoGuard({ policy: makePolicy({ limits: {} }), ledger });
    const auth = await g1.authorize(
      makeIntent({
        id: "tp-1",
        merchant: { id: "openai", url: "https://api.openai.com/v1" },
        amount: { amountMinor: 100, currency: "USD" },
      }),
    );
    expect(auth.status).toBe("authorized");
    await g1.settle("tp-1", { status: "executed" });

    const g2 = new VadunoGuard({
      policy: makePolicy({
        limits: {},
        velocity: { maxTransactionsPerMerchant: { count: 1, perSeconds: 86_400 } },
      }),
      ledger: new AuditLedger(store),
      requireHydration: true,
    });
    const report = await g2.hydrateFromLedger();
    expect(report.restoredSpendRows).toBe(1);
    expect(report.skippedUnparseableSpendRows).toBe(0);

    const saturated = await g2.execute(
      makeIntent({
        id: "tp-2",
        merchant: { id: "openai", url: "https://api.openai.com/v1" },
        amount: { amountMinor: 100, currency: "USD" },
      }),
      async () => ({ ok: true }),
    );
    expect(saturated.status).toBe("denied");
    if (saturated.status === "denied") {
      expect(saturated.policyResult.reasons.map((x) => x.code)).toContain(
        "MERCHANT_VELOCITY_EXCEEDED",
      );
    }
    // A DIFFERENT merchant is untouched — the restored count is keyed, not
    // guard-wide.
    const other = await g2.execute(
      makeIntent({
        id: "tp-3",
        merchant: { id: "aws", url: "https://aws.amazon.com/pay" },
        amount: { amountMinor: 100, currency: "USD" },
      }),
      async () => ({ ok: true }),
    );
    expect(other.status).toBe("executed");
  });
});

describe("a velocity denial never burns a mandate use", () => {
  it("MERCHANT_VELOCITY_EXCEEDED between two executions leaves the second use spendable", async () => {
    const keys = generateMandateKeyPair();
    const ledger = new AuditLedger(new MemoryLedgerStore());
    const mandates = new MandateManager(keys, ledger);
    const mandate = await mandates.issue({
      issuer: "prem",
      agentId: "agent-1",
      constraints: {
        maxAmountMinor: 10_000,
        currency: "USD",
        validFrom: new Date(Date.now() - 1_000).toISOString(),
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        maxUses: 2,
      },
    });
    const guard = new VadunoGuard({
      policy: makePolicy({
        limits: {},
        velocity: { maxTransactionsPerMerchant: { count: 1, perSeconds: 3_600 } },
      }),
      ledger,
      mandates,
    });

    const at = (id: string, host: string): PaymentIntent =>
      makeIntent({
        id,
        mandateId: mandate.id,
        merchant: { id: host, url: `https://${host}.example/pay` },
        amount: { amountMinor: 100, currency: "USD" },
      });

    expect((await guard.execute(at("m-1", "a"), async () => 1)).status).toBe("executed");
    // Same merchant again: denied by velocity — the reserve is refused BEFORE
    // consumeOnce, so this must not cost a use.
    const denied = await guard.execute(at("m-2", "a"), async () => 1);
    expect(denied.status).toBe("denied");
    // The second (and last) use is still there for a different merchant.
    expect((await guard.execute(at("m-3", "b"), async () => 1)).status).toBe("executed");
  });
});

describe("ledgerSpendHistory.merchantCountSince", () => {
  it("counts keyed rows per merchant and keyless rows toward every merchant", async () => {
    const ledger = new AuditLedger(new MemoryLedgerStore());
    const since = new Date(Date.now() - 60_000).toISOString();
    await ledger.append(
      "execution_result",
      { success: true, amountMinor: 1, currency: "USD", merchantKey: "host:a.example" },
      { intentId: "i1", agentId: "g" },
    );
    await ledger.append(
      "execution_result",
      { success: true, amountMinor: 1, currency: "USD", merchantKey: "host:b.example" },
      { intentId: "i2", agentId: "g" },
    );
    // Keyless (pre-velocity) success row: counts toward BOTH merchants.
    await ledger.append(
      "execution_result",
      { success: true, amountMinor: 1, currency: "USD" },
      { intentId: "i3", agentId: "g" },
    );
    // A failure is not spend for any merchant.
    await ledger.append(
      "execution_result",
      { success: false, amountMinor: 1, currency: "USD", merchantKey: "host:a.example" },
      { intentId: "i4", agentId: "g" },
    );

    const history = ledgerSpendHistory(ledger);
    expect((await history.merchantCountSince!("g", "host:a.example", since, "USD")).count).toBe(2);
    expect((await history.merchantCountSince!("g", "host:b.example", since, "USD")).count).toBe(2);
    expect((await history.merchantCountSince!("g", "host:c.example", since, "USD")).count).toBe(1);
  });
});
