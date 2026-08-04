/**
 * The risk scorecard under ATTACK, end to end through the guard.
 *
 * The invariants a naive implementation gets wrong, each pinned by a test
 * that fails against it:
 *  - scoring AFTER the reservation burns budget (and mandate uses) on a
 *    risk deny — here a risk deny must leave both untouched;
 *  - letting an approval override a high-tier deny — approval answers a
 *    step-up, never a deny, and the handler must not even be invoked;
 *  - a non-monotone merge that lets a low risk score loosen a policy
 *    decision — risk only tightens;
 *  - replaying an assessment against "the ledger now" instead of the
 *    recorded anchor — concurrent traffic interleaves entries and the
 *    reproducibility claim silently dies.
 */
import { describe, expect, it } from "vitest";
import { AuditLedger, GENESIS_HASH } from "../src/ledger/ledger.js";
import type { ExpectedTip, LedgerAppendResult, LedgerEntry } from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import { VadunoGuard } from "../src/guard.js";
import { MandateManager, generateMandateKeyPair } from "../src/mandate/mandate.js";
import { anchoredPrefix, RiskScorecard } from "../src/risk/scorecard.js";
import type { RiskAssessment } from "../src/risk/scorecard.js";
import { makeIntent, makePolicy } from "./helpers.js";
import type { PaymentIntent, SpendPolicy } from "../src/types.js";

const NOON = Date.parse("2026-01-05T12:00:00.000Z");
const NIGHT = Date.parse("2026-01-05T03:00:00.000Z");
const HOUR = 3_600_000;
const BUSINESS_HOURS = [{ startMinute: 9 * 60, endMinute: 17 * 60 }];

/** OUT_OF_HOURS-only scorecard: high tier (deny) whenever now() is at night. */
function nightDeniesCard(over: { autoFreeze?: { atScore: number } } = {}): RiskScorecard {
  return new RiskScorecard({
    lookbackMs: 30 * 24 * HOUR,
    stepUpAt: 10,
    denyAt: 10,
    ...over,
    signals: { OUT_OF_HOURS: { weight: 10, allowedWindowsUtc: BUSINESS_HOURS } },
  });
}

function deniedCodes(r: { status: string; policyResult?: { reasons: Array<{ code: string }> } }): string[] {
  return r.status === "denied" && r.policyResult ? r.policyResult.reasons.map((x) => x.code) : [];
}

async function issueMandate(
  mandates: MandateManager,
  maxUses: number,
  nowMs: number,
): Promise<string> {
  const m = await mandates.issue({
    issuer: "prem",
    agentId: "agent-1",
    constraints: {
      maxAmountMinor: 1_000_000,
      currency: "USD",
      validFrom: new Date(nowMs - 1_000).toISOString(),
      expiresAt: new Date(nowMs + 24 * HOUR).toISOString(),
      maxUses,
    },
  });
  return m.id;
}

describe("a risk deny burns neither budget nor a mandate use (scoring is BEFORE reserve/consume)", () => {
  it("after a RISK_DENY, the full day cap and the mandate's only use are still spendable", async () => {
    let nowMs = NIGHT;
    const now = () => new Date(nowMs);
    const keys = generateMandateKeyPair();
    const store = new MemoryLedgerStore();
    const ledger = new AuditLedger(store, now);
    const mandates = new MandateManager(keys, ledger, now);
    const mandateId = await issueMandate(mandates, 1, nowMs);
    const guard = new VadunoGuard({
      policy: makePolicy({ limits: { perDayMinor: 1_000 } }),
      ledger,
      mandates,
      risk: nightDeniesCard(),
      now,
    });

    let railCalls = 0;
    // 03:00 UTC: OUT_OF_HOURS -> high tier -> deny. A naive pipeline that
    // reserved first would leave 900 of the 1000 cap held, and one that
    // consumed first would burn the mandate's ONLY use.
    const denied = await guard.execute(
      makeIntent({ id: "night-1", amount: { amountMinor: 900, currency: "USD" }, mandateId }),
      async () => {
        railCalls += 1;
        return 1;
      },
    );
    expect(denied.status).toBe("denied");
    expect(deniedCodes(denied)).toContain("RISK_DENY");
    expect(deniedCodes(denied)).toContain("OUT_OF_HOURS"); // the fired signal rides the reasons
    expect(railCalls).toBe(0);

    // Noon: same amount, same mandate. If the risk deny had reserved
    // (900 + 900 > 1000) or consumed the single use, this would deny.
    nowMs = NOON;
    const executed = await guard.execute(
      makeIntent({ id: "day-1", amount: { amountMinor: 900, currency: "USD" }, mandateId }),
      async () => {
        railCalls += 1;
        return 1;
      },
    );
    expect(executed.status).toBe("executed");
    expect(railCalls).toBe(1);
  });
});

describe("approval never overrides a high-tier deny", () => {
  it("with approval.always and an auto-approving handler, a high-risk intent is denied and the handler is NEVER invoked", async () => {
    let nowMs = NIGHT;
    const now = () => new Date(nowMs);
    let handlerCalls = 0;
    const guard = new VadunoGuard({
      policy: makePolicy({ approval: { always: true } }),
      ledger: new AuditLedger(new MemoryLedgerStore(), now),
      approvalHandler: async () => {
        handlerCalls += 1;
        return { approved: true, approver: "eager-human" };
      },
      risk: nightDeniesCard(),
      now,
    });

    let railCalls = 0;
    const denied = await guard.execute(makeIntent({ id: "override-1" }), async () => {
      railCalls += 1;
      return 1;
    });
    // A pipeline that routed the high tier through the approval branch would
    // have executed this: the handler approves everything.
    expect(denied.status).toBe("denied");
    expect(deniedCodes(denied)).toContain("RISK_DENY");
    expect(handlerCalls).toBe(0);
    expect(railCalls).toBe(0);

    // Sanity: in business hours the SAME policy routes through approval.
    nowMs = NOON;
    const ok = await guard.execute(makeIntent({ id: "override-2" }), async () => {
      railCalls += 1;
      return 1;
    });
    expect(ok.status).toBe("executed");
    expect(handlerCalls).toBe(1);
  });
});

describe("elevated tier routes through the EXISTING approval branch", () => {
  const stepUpCard = () =>
    new RiskScorecard({
      lookbackMs: 30 * 24 * HOUR,
      stepUpAt: 5,
      denyAt: 100,
      signals: { OUT_OF_HOURS: { weight: 5, allowedWindowsUtc: BUSINESS_HOURS } },
    });

  it("the handler sees RISK_STEPUP plus the fired signals, and its approval clears the payment", async () => {
    const now = () => new Date(NIGHT);
    const store = new MemoryLedgerStore();
    let seen: string[] = [];
    const guard = new VadunoGuard({
      policy: makePolicy(),
      ledger: new AuditLedger(store, now),
      approvalHandler: async (req) => {
        seen = req.policyResult.reasons.map((r) => r.code);
        return { approved: true };
      },
      risk: stepUpCard(),
      now,
    });
    const r = await guard.execute(makeIntent({ id: "stepup-1" }), async () => 1);
    expect(r.status).toBe("executed");
    expect(seen).toContain("RISK_STEPUP");
    expect(seen).toContain("OUT_OF_HOURS");
    const types = (await store.all()).filter((e) => e.intentId === "stepup-1").map((e) => e.type);
    expect(types).toContain("approval_requested");
  });

  it("a human can still say no: rejection is approval_rejected, not executed", async () => {
    const now = () => new Date(NIGHT);
    const guard = new VadunoGuard({
      policy: makePolicy(),
      ledger: new AuditLedger(new MemoryLedgerStore(), now),
      approvalHandler: async () => ({ approved: false }),
      risk: stepUpCard(),
      now,
    });
    let railCalls = 0;
    const r = await guard.execute(makeIntent({ id: "stepup-2" }), async () => {
      railCalls += 1;
      return 1;
    });
    expect(r.status).toBe("approval_rejected");
    expect(railCalls).toBe(0);
  });

  it("no approvalHandler configured -> NO_APPROVAL_HANDLER deny (fail closed), with the risk reasons attached", async () => {
    const now = () => new Date(NIGHT);
    const guard = new VadunoGuard({
      policy: makePolicy(),
      ledger: new AuditLedger(new MemoryLedgerStore(), now),
      risk: stepUpCard(),
      now,
    });
    const r = await guard.execute(makeIntent({ id: "stepup-3" }), async () => 1);
    expect(r.status).toBe("denied");
    expect(deniedCodes(r)).toEqual(
      expect.arrayContaining(["NO_APPROVAL_HANDLER", "RISK_STEPUP", "OUT_OF_HOURS"]),
    );
  });
});

describe("FIRST_USE_OF_MANDATE is derivable from the ledger (the mandate_consumed join)", () => {
  it("the FIRST spend under a mandate steps up; the SECOND does not — the signal must stop firing once a use is recorded", async () => {
    const now = () => new Date(NOON);
    const keys = generateMandateKeyPair();
    const store = new MemoryLedgerStore();
    const ledger = new AuditLedger(store, now);
    const mandates = new MandateManager(keys, ledger, now);
    const mandateId = await issueMandate(mandates, 3, NOON);
    let handlerCalls = 0;
    const guard = new VadunoGuard({
      policy: makePolicy(),
      ledger,
      mandates,
      approvalHandler: async () => {
        handlerCalls += 1;
        return { approved: true };
      },
      risk: new RiskScorecard({
        lookbackMs: 30 * 24 * HOUR,
        stepUpAt: 5,
        denyAt: 100,
        signals: { FIRST_USE_OF_MANDATE: { weight: 5 } },
      }),
      now,
    });

    const first = await guard.execute(makeIntent({ id: "fu-1", mandateId }), async () => 1);
    expect(first.status).toBe("executed");
    expect(handlerCalls).toBe(1); // stepped up: no prior use of this mandate

    // The consume of fu-1 is now in the ledger. Were the signal not
    // ledger-derivable (execution_result carries NO mandateId), it would
    // fire on every mandate-bearing intent forever and this stays 2.
    const second = await guard.execute(makeIntent({ id: "fu-2", mandateId }), async () => 1);
    expect(second.status).toBe("executed");
    expect(handlerCalls).toBe(1); // NOT stepped up again

    // Carve-out sanity: a mandate-less intent never fires the signal.
    const third = await guard.execute(makeIntent({ id: "fu-3" }), async () => 1);
    expect(third.status).toBe("executed");
    expect(handlerCalls).toBe(1);
  });
});

describe("risk rose mid-wait: RISK_STEPUP_UNAPPROVED (mirrors APPROVAL_REQUIRED_AFTER_POLICY_CHANGE)", () => {
  it("a deny landing between an intent's prelim and its critical section trips DENY_STREAK at the final pass and denies unapproved", async () => {
    const now = () => new Date(NOON);
    const guard = new VadunoGuard({
      policy: makePolicy(), // perTransactionMinor 5000 — D below exceeds it
      ledger: new AuditLedger(new MemoryLedgerStore(), now),
      risk: new RiskScorecard({
        lookbackMs: 30 * 24 * HOUR,
        stepUpAt: 5,
        denyAt: 100,
        signals: { DENY_STREAK: { weight: 5, minDenies: 1, windowMs: HOUR } },
      }),
      now,
    });

    // B holds the critical section open in its executor.
    let releaseB!: () => void;
    const bGate = new Promise<void>((r) => (releaseB = r));
    let bStarted!: () => void;
    const bEntered = new Promise<void>((r) => (bStarted = r));
    const bPromise = guard.execute(
      makeIntent({ id: "slow-B", amount: { amountMinor: 100, currency: "USD" } }),
      async () => {
        bStarted();
        await bGate;
        return "b";
      },
    );
    await bEntered;

    // A: prelim scores LOW (zero denies so far), then queues on the mutex.
    let aRail = 0;
    const aPromise = guard.execute(
      makeIntent({ id: "victim-A", amount: { amountMinor: 100, currency: "USD" } }),
      async () => {
        aRail += 1;
        return "a";
      },
    );
    await new Promise((r) => setTimeout(r, 50)); // let A's prelim + risk_scored land

    // D: policy-denied at ITS prelim (outside the mutex) — the deny row A's
    // FINAL pass will see. This is exactly why the final pass re-evaluates.
    const d = await guard.execute(
      makeIntent({ id: "probe-D", amount: { amountMinor: 6_000, currency: "USD" } }),
      async () => "d",
    );
    expect(d.status).toBe("denied");
    expect(deniedCodes(d)).toContain("PER_TXN_LIMIT_EXCEEDED");

    releaseB();
    const b = await bPromise;
    expect(b.status).toBe("executed");

    const a = await aPromise;
    // A held no approval; risk reached step-up between prelim and final.
    // Executing anyway would be a step-up nobody answered.
    expect(a.status).toBe("denied");
    expect(deniedCodes(a)).toEqual(
      expect.arrayContaining(["RISK_STEPUP_UNAPPROVED", "RISK_STEPUP", "DENY_STREAK"]),
    );
    expect(aRail).toBe(0);
  });
});

describe("auto-freeze: deny the intent, then stop the guard (manual unfreeze only)", () => {
  it("a score at autoFreeze.atScore denies AND freezes; the guard_frozen record names the trigger; unfreeze() is the only way back", async () => {
    let nowMs = NIGHT;
    const now = () => new Date(nowMs);
    const store = new MemoryLedgerStore();
    const guard = new VadunoGuard({
      policy: makePolicy(),
      ledger: new AuditLedger(store, now),
      risk: nightDeniesCard({ autoFreeze: { atScore: 10 } }),
      now,
    });

    const trigger = await guard.execute(makeIntent({ id: "af-1" }), async () => 1);
    expect(trigger.status).toBe("denied");
    expect(deniedCodes(trigger)).toContain("RISK_DENY");
    expect(guard.isFrozen()).toBe(true);

    // The evidence names the trigger, not just a reason string.
    const frozenRows = (await store.all()).filter((e) => e.type === "guard_frozen");
    expect(frozenRows).toHaveLength(1);
    expect((frozenRows[0]!.data as { autoFreeze?: unknown }).autoFreeze).toEqual({
      intentId: "af-1",
      score: 10,
      atScore: 10,
    });

    // A benign daytime intent is still denied: the freeze does not thaw on
    // its own — auto-freeze is a stop, not a rate limit.
    nowMs = NOON;
    const blocked = await guard.execute(makeIntent({ id: "af-2" }), async () => 1);
    expect(blocked.status).toBe("denied");
    expect(deniedCodes(blocked)).toContain("GUARD_FROZEN");

    await guard.unfreeze();
    const after = await guard.execute(makeIntent({ id: "af-3" }), async () => 1);
    expect(after.status).toBe("executed");
  });
});

describe("fail-closed: unscorable and broken risk paths deny before anything is touched", () => {
  it("CAP_APPROACH configured while the policy has no perDayMinor: RISK_UNSCORABLE deny; the approval handler is never consulted", async () => {
    const now = () => new Date(NOON);
    let handlerCalls = 0;
    const guard = new VadunoGuard({
      policy: makePolicy({ limits: {}, approval: { aboveMinor: 1 } }),
      ledger: new AuditLedger(new MemoryLedgerStore(), now),
      approvalHandler: async () => {
        handlerCalls += 1;
        return { approved: true };
      },
      risk: new RiskScorecard({
        lookbackMs: 30 * 24 * HOUR,
        stepUpAt: 5,
        denyAt: 10,
        signals: { CAP_APPROACH: { weight: 5, thresholdBps: 8_000 } },
      }),
      now,
    });
    let railCalls = 0;
    const r = await guard.execute(makeIntent({ id: "unscorable-1" }), async () => {
      railCalls += 1;
      return 1;
    });
    expect(r.status).toBe("denied");
    expect(deniedCodes(r)).toContain("RISK_UNSCORABLE");
    expect(railCalls).toBe(0);
    expect(handlerCalls).toBe(0);
  });

  it("the history source (ledger.all) throwing is RISK_UNSCORABLE, never score-0-allow", async () => {
    class BrokenAllStore extends MemoryLedgerStore {
      override all(): Promise<LedgerEntry[]> {
        return Promise.reject(new Error("disk gone"));
      }
    }
    const now = () => new Date(NOON);
    const guard = new VadunoGuard({
      policy: makePolicy(),
      ledger: new AuditLedger(new BrokenAllStore(), now),
      risk: nightDeniesCard(),
      now,
    });
    let railCalls = 0;
    const r = await guard.execute(makeIntent({ id: "broken-1" }), async () => {
      railCalls += 1;
      return 1;
    });
    expect(r.status).toBe("denied");
    expect(deniedCodes(r)).toContain("RISK_UNSCORABLE");
    expect(railCalls).toBe(0);
  });

  it("a scorer BUG (unexpected throw) is a GUARD_INTERNAL_ERROR deny, not a pass", async () => {
    const now = () => new Date(NOON);
    const card = nightDeniesCard();
    // Simulate an internal defect, not a config problem.
    (card as unknown as { assess: () => never }).assess = () => {
      throw new Error("scorer exploded");
    };
    const guard = new VadunoGuard({
      policy: makePolicy(),
      ledger: new AuditLedger(new MemoryLedgerStore(), now),
      risk: card,
      now,
    });
    let railCalls = 0;
    const r = await guard.execute(makeIntent({ id: "bug-1" }), async () => {
      railCalls += 1;
      return 1;
    });
    expect(r.status).toBe("denied");
    expect(deniedCodes(r)).toContain("GUARD_INTERNAL_ERROR");
    expect(railCalls).toBe(0);
  });

  it("the risk_scored append is HARD: an assessment that cannot be recorded denies the payment", async () => {
    class RiskAppendRefusedStore extends MemoryLedgerStore {
      override append(entry: LedgerEntry, expected: ExpectedTip): Promise<LedgerAppendResult> {
        if (entry.type === "risk_scored") {
          return Promise.reject(new Error("store refuses risk rows"));
        }
        return super.append(entry, expected);
      }
    }
    const now = () => new Date(NOON);
    const guard = new VadunoGuard({
      policy: makePolicy(),
      ledger: new AuditLedger(new RiskAppendRefusedStore(), now),
      risk: nightDeniesCard(),
      now,
    });
    let railCalls = 0;
    const r = await guard.execute(makeIntent({ id: "hard-append-1" }), async () => {
      railCalls += 1;
      return 1;
    });
    expect(r.status).toBe("denied");
    expect(deniedCodes(r)).toContain("GUARD_INTERNAL_ERROR");
    expect(railCalls).toBe(0);
  });
});

describe("no risk option -> the pipeline is unchanged", () => {
  it("a guard without `risk` writes no risk_scored rows and keeps the exact pre-risk trail shape", async () => {
    const store = new MemoryLedgerStore();
    const guard = new VadunoGuard({
      policy: makePolicy(),
      ledger: new AuditLedger(store),
    });
    const r = await guard.execute(makeIntent({ id: "plain-1" }), async () => 1);
    expect(r.status).toBe("executed");
    const types = (await store.all()).map((e) => e.type);
    expect(types).toEqual([
      "intent_received",
      "policy_decision",
      "execution_started",
      "execution_result",
    ]);
  });
});

describe("two-phase authorize()/settle() inherits risk via the shared pipeline", () => {
  it("a high-risk authorize is denied before any budget is reserved; a low-risk one authorizes and settles", async () => {
    let nowMs = NIGHT;
    const now = () => new Date(nowMs);
    const guard = new VadunoGuard({
      policy: makePolicy({ limits: { perDayMinor: 1_000 } }),
      ledger: new AuditLedger(new MemoryLedgerStore(), now),
      risk: nightDeniesCard(),
      now,
    });
    const denied = await guard.authorize(
      makeIntent({ id: "tp-risk-1", amount: { amountMinor: 900, currency: "USD" } }),
    );
    expect(denied.status).toBe("denied");
    expect(deniedCodes(denied)).toContain("RISK_DENY");

    nowMs = NOON;
    // The full cap is still free: the denied authorize reserved nothing.
    const authorized = await guard.authorize(
      makeIntent({ id: "tp-risk-2", amount: { amountMinor: 900, currency: "USD" } }),
    );
    expect(authorized.status).toBe("authorized");
    await guard.settle("tp-risk-2", { status: "executed" });
  });
});

describe("evidence: both phases land as hard risk_scored rows", () => {
  it("one executed intent leaves prelim + final assessments, each anchored and config-hashed", async () => {
    const now = () => new Date(NOON);
    const store = new MemoryLedgerStore();
    const card = nightDeniesCard();
    const guard = new VadunoGuard({
      policy: makePolicy(),
      ledger: new AuditLedger(store, now),
      risk: card,
      now,
    });
    await guard.execute(makeIntent({ id: "ev-1" }), async () => 1);
    const rows = (await store.all()).filter(
      (e) => e.type === "risk_scored" && e.intentId === "ev-1",
    );
    expect(rows.map((e) => (e.data as { phase: string }).phase)).toEqual(["prelim", "final"]);
    for (const row of rows) {
      const a = (row.data as { assessment: RiskAssessment }).assessment;
      expect(a.configHash).toBe(card.configHash);
      expect(a.tier).toBe("low");
      expect(typeof a.anchor.seq).toBe("number");
      expect(typeof a.anchor.hash).toBe("string");
    }
    // The final pass anchors LATER than the prelim: entries landed between.
    const [prelim, final] = rows.map((r) => (r.data as { assessment: RiskAssessment }).assessment);
    expect(final!.anchor.seq).toBeGreaterThan(prelim!.anchor.seq);
  });
});

describe("reproducibility: every recorded assessment replays bit-for-bit against its anchor", () => {
  function replayAll(
    entries: LedgerEntry[],
    card: RiskScorecard,
    policy: SpendPolicy,
  ): Array<{ recorded: RiskAssessment; replayed: RiskAssessment }> {
    const out: Array<{ recorded: RiskAssessment; replayed: RiskAssessment }> = [];
    for (const row of entries) {
      if (row.type !== "risk_scored") continue;
      const recorded = (row.data as { assessment: RiskAssessment }).assessment;
      const intentRow = entries.find(
        (e) => e.type === "intent_received" && e.intentId === row.intentId,
      )!;
      const intent = (intentRow.data as { intent: PaymentIntent }).intent;
      const replayed = card.assess({
        intent,
        policy,
        entries: anchoredPrefix(entries, recorded.anchor),
        nowMs: recorded.atMs,
      });
      out.push({ recorded, replayed });
    }
    return out;
  }

  const trafficCard = () =>
    new RiskScorecard({
      lookbackMs: 30 * 24 * HOUR,
      stepUpAt: 50,
      denyAt: 100,
      signals: {
        FIRST_SEEN_MERCHANT: { weight: 1 },
        VELOCITY_BURST: { weight: 1, maxCount: 2, windowMs: HOUR },
        AMOUNT_ABOVE_GLOBAL_TYPICAL: { weight: 1, multiplierBps: 15_000, minHistory: 2 },
      },
    });

  it("sequential traffic: each risk_scored row re-derives identically from its anchored prefix", async () => {
    const now = () => new Date(NOON);
    const store = new MemoryLedgerStore();
    const card = trafficCard();
    const policy = makePolicy({ limits: {} });
    const guard = new VadunoGuard({ policy, ledger: new AuditLedger(store, now), risk: card, now });

    const merchants = ["a", "b", "a", "c", "a"];
    for (let i = 0; i < merchants.length; i += 1) {
      const r = await guard.execute(
        makeIntent({
          id: `seq-${i}`,
          merchant: { id: merchants[i]!, url: `https://${merchants[i]}.example/pay` },
          amount: { amountMinor: 100 * (i + 1), currency: "USD" },
        }),
        async () => 1,
      );
      expect(r.status).toBe("executed");
    }

    const entries = await store.all();
    const pairs = replayAll(entries, card, policy);
    expect(pairs.length).toBe(10); // 5 intents x (prelim + final)
    for (const { recorded, replayed } of pairs) {
      expect(replayed).toEqual(recorded);
    }
  });

  it("CONCURRENT traffic: interleaved commits between read and append are exactly why replay is anchored, and every row still replays", async () => {
    const now = () => new Date(NOON);
    const store = new MemoryLedgerStore();
    const card = trafficCard();
    const policy = makePolicy({ limits: {} });
    const guard = new VadunoGuard({ policy, ledger: new AuditLedger(store, now), risk: card, now });

    // Same merchant on purpose: later assessments see earlier commits, so a
    // replay against "the ledger now" (instead of the anchor) would score
    // FIRST_SEEN_MERCHANT and VELOCITY_BURST differently for the early rows.
    const results = await Promise.all(
      Array.from({ length: 8 }, (_, i) =>
        guard.execute(
          makeIntent({
            id: `conc-${i}`,
            merchant: { id: "hot", url: "https://hot.example/pay" },
            amount: { amountMinor: 50 + i, currency: "USD" },
          }),
          async () => 1,
        ),
      ),
    );
    for (const r of results) expect(r.status).toBe("executed");

    const entries = await store.all();
    const pairs = replayAll(entries, card, policy);
    expect(pairs.length).toBe(16); // 8 intents x (prelim + final)
    for (const { recorded, replayed } of pairs) {
      expect(replayed).toEqual(recorded);
    }
    // The traffic genuinely interleaved: not every assessment saw the same
    // prefix, so an unanchored replay would have had different data to score.
    const anchors = new Set(pairs.map((p) => p.recorded.anchor.seq));
    expect(anchors.size).toBeGreaterThan(1);
  });
});
