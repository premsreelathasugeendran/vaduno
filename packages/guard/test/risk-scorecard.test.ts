/**
 * Unit tests for the deterministic risk scorecard: constructor validation
 * (every violation reported, typos rejected), each of the eight signals'
 * firing rule and its edges, tier thresholds, the monotone tighten-only
 * merge, agentId-invariance, and the ledger-head anchor that makes an
 * assessment replayable bit-for-bit.
 */
import { describe, expect, it } from "vitest";
import {
  anchoredPrefix,
  applyRiskTier,
  RiskConfigError,
  RiskScorecard,
  RiskUnscorableError,
  type RiskAssessment,
  type RiskScorecardConfig,
} from "../src/risk/scorecard.js";
import { GENESIS_HASH, type LedgerEntry, type LedgerEntryType } from "../src/ledger/ledger.js";
import type { PolicyResult } from "../src/types.js";
import { makeIntent, makePolicy } from "./helpers.js";

/** Monday 2026-01-05 12:00 UTC — inside a 09:00–17:00 allowed window. */
const T0 = Date.parse("2026-01-05T12:00:00.000Z");
const HOUR = 3_600_000;
const BUSINESS_HOURS = [{ startMinute: 9 * 60, endMinute: 17 * 60 }];

/** Hand-crafted entries: assess() reads seq/type/timestamp/data/intentId. */
function makeEntries(
  rows: Array<{ type: LedgerEntryType; data: unknown; msAgo: number; intentId?: string }>,
): LedgerEntry[] {
  return rows.map((r, i) => ({
    seq: i,
    timestamp: new Date(T0 - r.msAgo).toISOString(),
    type: r.type,
    data: r.data,
    ...(r.intentId !== undefined ? { intentId: r.intentId } : {}),
    prevHash: i === 0 ? GENESIS_HASH : `hash-${i - 1}`,
    hash: `hash-${i}`,
  }));
}

function spendRow(
  amountMinor: number,
  msAgo: number,
  merchantKey?: string,
): { type: LedgerEntryType; data: unknown; msAgo: number } {
  return {
    type: "execution_result",
    data: {
      success: true,
      amountMinor,
      currency: "USD",
      ...(merchantKey !== undefined ? { merchantKey } : {}),
    },
    msAgo,
  };
}

function baseConfig(over: Partial<RiskScorecardConfig> = {}): RiskScorecardConfig {
  return {
    lookbackMs: 30 * 24 * HOUR,
    stepUpAt: 5,
    denyAt: 10,
    signals: { FIRST_SEEN_MERCHANT: { weight: 5 } },
    ...over,
  };
}

describe("constructor validation", () => {
  it("throws RiskConfigError listing EVERY violation in one throw", () => {
    // Four distinct problems at once — a validator that stops at the first
    // would train the operator to fix config one error message at a time.
    let caught: unknown;
    try {
      new RiskScorecard({
        lookbackMs: 30 * 24 * HOUR,
        stepUpAt: 20,
        denyAt: 10,
        autoFreeze: { atScore: 3 },
        signals: {
          FIRST_SEEN_MERCHENT: { weight: 5 }, // typo
          VELOCITY_BURST: { weight: 0, maxCount: 3, windowMs: HOUR }, // zero weight
        },
      } as unknown as RiskScorecardConfig);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(RiskConfigError);
    const v = (caught as RiskConfigError).violations.join("\n");
    expect(v).toContain('unknown signal key "FIRST_SEEN_MERCHENT"');
    expect(v).toContain("VELOCITY_BURST.weight 0");
    expect(v).toContain("stepUpAt 20 > denyAt 10");
    expect(v).toContain("autoFreeze.atScore 3 < denyAt 10");
  });

  it("a typo'd signal key must not silently no-op", () => {
    expect(
      () =>
        new RiskScorecard(
          baseConfig({
            signals: { OUT_OF_HOUR: { weight: 5 } } as never,
          }),
        ),
    ).toThrowError(/unknown signal key "OUT_OF_HOUR"/);
  });

  it("a typo'd option key inside a signal is rejected too", () => {
    expect(
      () =>
        new RiskScorecard(
          baseConfig({
            signals: {
              AMOUNT_ABOVE_MERCHANT_TYPICAL: {
                weight: 3,
                multipilerBps: 20000, // typo — the real option stays undefined
                minHistory: 3,
              } as never,
            },
          }),
        ),
    ).toThrowError(RiskConfigError);
  });

  it("negative and non-integer weights are rejected — a signal must never subtract", () => {
    for (const weight of [-1, 0, 1.5, Number.NaN]) {
      expect(
        () => new RiskScorecard(baseConfig({ signals: { FIRST_SEEN_MERCHANT: { weight } } })),
      ).toThrowError(RiskConfigError);
    }
  });

  it("an empty signals object enforces nothing and is refused", () => {
    expect(() => new RiskScorecard(baseConfig({ signals: {} }))).toThrowError(
      /no known signal/,
    );
  });

  it("OUT_OF_HOURS: empty window list, out-of-range minutes, and start>=end are refused", () => {
    const mk = (allowedWindowsUtc: Array<{ startMinute: number; endMinute: number }>) =>
      new RiskScorecard(
        baseConfig({ signals: { OUT_OF_HOURS: { weight: 5, allowedWindowsUtc } } }),
      );
    expect(() => mk([])).toThrowError(RiskConfigError);
    expect(() => mk([{ startMinute: -1, endMinute: 60 }])).toThrowError(RiskConfigError);
    expect(() => mk([{ startMinute: 0, endMinute: 1441 }])).toThrowError(RiskConfigError);
    expect(() => mk([{ startMinute: 600, endMinute: 600 }])).toThrowError(RiskConfigError);
  });

  it("a burst/streak window wider than the lookback would silently see less history than configured", () => {
    expect(
      () =>
        new RiskScorecard(
          baseConfig({
            lookbackMs: HOUR,
            signals: { VELOCITY_BURST: { weight: 2, maxCount: 3, windowMs: 2 * HOUR } },
          }),
        ),
    ).toThrowError(/exceeds lookbackMs/);
    expect(
      () =>
        new RiskScorecard(
          baseConfig({
            lookbackMs: HOUR,
            signals: { DENY_STREAK: { weight: 2, minDenies: 2, windowMs: 2 * HOUR } },
          }),
        ),
    ).toThrowError(/exceeds lookbackMs/);
  });

  it("CAP_APPROACH with a lookback shorter than the perDay window undercounts the day total and is refused", () => {
    expect(
      () =>
        new RiskScorecard(
          baseConfig({
            lookbackMs: HOUR,
            signals: { CAP_APPROACH: { weight: 3, thresholdBps: 8000 } },
          }),
        ),
    ).toThrowError(/requires lookbackMs/);
  });

  it("later mutation of the caller's config object cannot diverge behavior from the stamped configHash", () => {
    const cfg = baseConfig({ signals: { FIRST_SEEN_MERCHANT: { weight: 5 } } });
    const card = new RiskScorecard(cfg);
    const before = card.configHash;
    cfg.signals.FIRST_SEEN_MERCHANT!.weight = 999; // hostile/late mutation
    const a = card.assess({
      intent: makeIntent(),
      policy: makePolicy(),
      entries: [],
      nowMs: T0,
    });
    expect(card.configHash).toBe(before);
    expect(a.signals[0]!.weight).toBe(5); // the pinned copy, not the mutated one
  });
});

describe("FIRST_SEEN_MERCHANT", () => {
  const card = new RiskScorecard(
    baseConfig({ signals: { FIRST_SEEN_MERCHANT: { weight: 5 } } }),
  );
  const intent = makeIntent({ merchant: { id: "openai", url: "https://api.openai.com/v1" } });

  it("fires when the merchant has no successful spend in the lookback", () => {
    const a = card.assess({ intent, policy: makePolicy(), entries: [], nowMs: T0 });
    expect(a.signals.map((s) => s.signal)).toEqual(["FIRST_SEEN_MERCHANT"]);
    expect(a.score).toBe(5);
  });

  it("does not fire when a keyed spend for the same merchant exists", () => {
    const entries = makeEntries([spendRow(100, HOUR, "host:api.openai.com")]);
    const a = card.assess({ intent, policy: makePolicy(), entries, nowMs: T0 });
    expect(a.signals).toEqual([]);
  });

  it("a KEYLESS history row does not establish familiarity — an unattributable spend must not vouch for any merchant", () => {
    const entries = makeEntries([spendRow(100, HOUR)]);
    const a = card.assess({ intent, policy: makePolicy(), entries, nowMs: T0 });
    expect(a.signals.map((s) => s.signal)).toEqual(["FIRST_SEEN_MERCHANT"]);
  });

  it("a spend outside the lookback does not count as familiarity", () => {
    const card2 = new RiskScorecard(
      baseConfig({ lookbackMs: HOUR, signals: { FIRST_SEEN_MERCHANT: { weight: 5 } } }),
    );
    const entries = makeEntries([spendRow(100, 2 * HOUR, "host:api.openai.com")]);
    const a = card2.assess({ intent, policy: makePolicy(), entries, nowMs: T0 });
    expect(a.signals.map((s) => s.signal)).toEqual(["FIRST_SEEN_MERCHANT"]);
  });
});

describe("AMOUNT_ABOVE_MERCHANT_TYPICAL (BigInt, lower-median, minHistory-gated)", () => {
  const card = new RiskScorecard(
    baseConfig({
      signals: {
        AMOUNT_ABOVE_MERCHANT_TYPICAL: { weight: 4, multiplierBps: 20_000, minHistory: 3 },
      },
    }),
  );
  const key = "host:api.openai.com";
  const intent = (amountMinor: number) =>
    makeIntent({
      merchant: { id: "openai", url: "https://api.openai.com/v1" },
      amount: { amountMinor, currency: "USD" },
    });

  it("stays SILENT below minHistory even for a huge amount — no baseline means no 'typical'", () => {
    const entries = makeEntries([spendRow(100, HOUR, key), spendRow(100, HOUR, key)]);
    const a = card.assess({
      intent: intent(1_000_000),
      policy: makePolicy(),
      entries,
      nowMs: T0,
    });
    expect(a.signals).toEqual([]);
  });

  it("fires strictly above lowerMedian x multiplier and not at it (exact boundary)", () => {
    // History 100, 200, 300 -> lower median 200; 2x multiplier -> boundary 400.
    const entries = makeEntries([
      spendRow(300, HOUR, key),
      spendRow(100, HOUR, key),
      spendRow(200, HOUR, key),
    ]);
    const at = card.assess({ intent: intent(400), policy: makePolicy(), entries, nowMs: T0 });
    expect(at.signals).toEqual([]); // 400 * 10000 == 200 * 20000 — not above
    const above = card.assess({ intent: intent(401), policy: makePolicy(), entries, nowMs: T0 });
    expect(above.signals.map((s) => s.signal)).toEqual(["AMOUNT_ABOVE_MERCHANT_TYPICAL"]);
  });

  it("even-count history uses the LOWER median (element floor((n-1)/2))", () => {
    // 100, 200, 300, 400 -> lower median 200, boundary 400.
    const entries = makeEntries([
      spendRow(400, HOUR, key),
      spendRow(100, HOUR, key),
      spendRow(300, HOUR, key),
      spendRow(200, HOUR, key),
    ]);
    expect(
      card.assess({ intent: intent(400), policy: makePolicy(), entries, nowMs: T0 }).signals,
    ).toEqual([]);
    expect(
      card
        .assess({ intent: intent(401), policy: makePolicy(), entries, nowMs: T0 })
        .signals.map((s) => s.signal),
    ).toEqual(["AMOUNT_ABOVE_MERCHANT_TYPICAL"]);
  });

  it("the comparison stays exact where median x multiplierBps overflows Number precision", () => {
    // median * multiplierBps = 9_000_000_000_000_000 * 100_000 = 9e20 — far
    // beyond 2^53. The exact boundary amount is MAX for a safe integer times
    // ten thousand; only integer (BigInt) math can place it correctly.
    const big = 9_000_000_000_000_000;
    const bigCard = new RiskScorecard(
      baseConfig({
        signals: {
          AMOUNT_ABOVE_MERCHANT_TYPICAL: { weight: 4, multiplierBps: 100_000, minHistory: 1 },
        },
      }),
    );
    const entries = makeEntries([spendRow(big, HOUR, key)]);
    // amount * 10000 = 9.007e19 < 9e20 — must NOT fire despite float fog.
    const a = bigCard.assess({
      intent: intent(Number.MAX_SAFE_INTEGER),
      policy: makePolicy(),
      entries,
      nowMs: T0,
    });
    expect(a.signals).toEqual([]);
  });

  it("another merchant's spends are not this merchant's baseline", () => {
    const entries = makeEntries([
      spendRow(1, HOUR, "host:other.example"),
      spendRow(1, HOUR, "host:other.example"),
      spendRow(1, HOUR, "host:other.example"),
    ]);
    const a = card.assess({
      intent: intent(1_000_000),
      policy: makePolicy(),
      entries,
      nowMs: T0,
    });
    // Cheap history at a DIFFERENT merchant must not brand this amount
    // atypical here (minHistory for THIS merchant is unmet).
    expect(a.signals).toEqual([]);
  });
});

describe("AMOUNT_ABOVE_GLOBAL_TYPICAL", () => {
  it("uses all policy-currency spends regardless of merchant, and other currencies never count", () => {
    const card = new RiskScorecard(
      baseConfig({
        signals: {
          AMOUNT_ABOVE_GLOBAL_TYPICAL: { weight: 3, multiplierBps: 20_000, minHistory: 2 },
        },
      }),
    );
    const entries = makeEntries([
      spendRow(100, HOUR, "host:a.example"),
      spendRow(200, HOUR, "host:b.example"),
      // An EUR row must not enter a USD policy's baseline.
      { type: "execution_result", data: { success: true, amountMinor: 1, currency: "EUR" }, msAgo: HOUR },
    ]);
    // Lower median of {100, 200} = 100; boundary 200.
    const at = card.assess({
      intent: makeIntent({ amount: { amountMinor: 200, currency: "USD" } }),
      policy: makePolicy(),
      entries,
      nowMs: T0,
    });
    expect(at.signals).toEqual([]);
    const above = card.assess({
      intent: makeIntent({ amount: { amountMinor: 201, currency: "USD" } }),
      policy: makePolicy(),
      entries,
      nowMs: T0,
    });
    expect(above.signals.map((s) => s.signal)).toEqual(["AMOUNT_ABOVE_GLOBAL_TYPICAL"]);
  });
});

describe("OUT_OF_HOURS (declared half-open UTC windows, never learned)", () => {
  const card = new RiskScorecard(
    baseConfig({
      signals: { OUT_OF_HOURS: { weight: 5, allowedWindowsUtc: BUSINESS_HOURS } },
    }),
  );
  const at = (iso: string) =>
    card.assess({
      intent: makeIntent(),
      policy: makePolicy(),
      entries: [],
      nowMs: Date.parse(iso),
    });

  it("does not fire inside the window", () => {
    expect(at("2026-01-05T12:00:00.000Z").signals).toEqual([]);
  });

  it("startMinute is INCLUSIVE: exactly 09:00 is in hours", () => {
    expect(at("2026-01-05T09:00:00.000Z").signals).toEqual([]);
  });

  it("endMinute is EXCLUSIVE: exactly 17:00 is out of hours", () => {
    expect(at("2026-01-05T17:00:00.000Z").signals.map((s) => s.signal)).toEqual([
      "OUT_OF_HOURS",
    ]);
  });

  it("fires at 03:00 — the classic compromised-agent shopping hour", () => {
    expect(at("2026-01-05T03:00:00.000Z").signals.map((s) => s.signal)).toEqual([
      "OUT_OF_HOURS",
    ]);
  });
});

describe("VELOCITY_BURST", () => {
  const card = new RiskScorecard(
    baseConfig({
      signals: { VELOCITY_BURST: { weight: 3, maxCount: 3, windowMs: HOUR } },
    }),
  );

  it("fires once the window already holds maxCount successful spends", () => {
    const entries = makeEntries([
      spendRow(1, HOUR / 2, "host:a.example"),
      spendRow(1, HOUR / 2, "host:a.example"),
      spendRow(1, HOUR / 2, "host:a.example"),
    ]);
    const a = card.assess({ intent: makeIntent(), policy: makePolicy(), entries, nowMs: T0 });
    expect(a.signals.map((s) => s.signal)).toEqual(["VELOCITY_BURST"]);
  });

  it("stays silent below maxCount, and spends outside the window do not count", () => {
    const entries = makeEntries([
      spendRow(1, HOUR / 2, "host:a.example"),
      spendRow(1, HOUR / 2, "host:a.example"),
      spendRow(1, 2 * HOUR, "host:a.example"), // aged out of the burst window
    ]);
    const a = card.assess({ intent: makeIntent(), policy: makePolicy(), entries, nowMs: T0 });
    expect(a.signals).toEqual([]);
  });

  it("failed attempts are not spend and do not count toward a burst", () => {
    const entries = makeEntries([
      spendRow(1, HOUR / 2, "host:a.example"),
      spendRow(1, HOUR / 2, "host:a.example"),
      { type: "execution_result", data: { success: false, amountMinor: 1, currency: "USD" }, msAgo: HOUR / 2 },
    ]);
    const a = card.assess({ intent: makeIntent(), policy: makePolicy(), entries, nowMs: T0 });
    expect(a.signals).toEqual([]);
  });
});

describe("DENY_STREAK", () => {
  const card = new RiskScorecard(
    baseConfig({
      signals: { DENY_STREAK: { weight: 4, minDenies: 2, windowMs: HOUR } },
    }),
  );
  const deny = (msAgo: number) => ({
    type: "policy_decision" as LedgerEntryType,
    data: { policyResult: { decision: "deny", reasons: [], policyId: "p", policyVersion: 1 } },
    msAgo,
  });
  const allow = (msAgo: number) => ({
    type: "policy_decision" as LedgerEntryType,
    data: { policyResult: { decision: "allow", reasons: [], policyId: "p", policyVersion: 1 } },
    msAgo,
  });

  it("fires at minDenies denials within the window — a policy-probing agent leaves exactly this trail", () => {
    const entries = makeEntries([deny(HOUR / 2), deny(HOUR / 3)]);
    const a = card.assess({ intent: makeIntent(), policy: makePolicy(), entries, nowMs: T0 });
    expect(a.signals.map((s) => s.signal)).toEqual(["DENY_STREAK"]);
  });

  it("allow decisions and out-of-window denials do not count", () => {
    const entries = makeEntries([allow(HOUR / 2), deny(HOUR / 2), deny(2 * HOUR)]);
    const a = card.assess({ intent: makeIntent(), policy: makePolicy(), entries, nowMs: T0 });
    expect(a.signals).toEqual([]);
  });
});

describe("FIRST_USE_OF_MANDATE (joined from mandate_consumed — execution_result carries no mandateId)", () => {
  const card = new RiskScorecard(
    baseConfig({ signals: { FIRST_USE_OF_MANDATE: { weight: 6 } } }),
  );

  it("fires on the first spend under a mandate", () => {
    const a = card.assess({
      intent: makeIntent({ mandateId: "m-1" }),
      policy: makePolicy(),
      entries: [],
      nowMs: T0,
    });
    expect(a.signals.map((s) => s.signal)).toEqual(["FIRST_USE_OF_MANDATE"]);
  });

  it("does NOT fire when the ledger holds a prior consumed use of this mandate", () => {
    // THE test revision 1 demanded: without the mandate_consumed join, the
    // default history would fire this signal on EVERY mandate-bearing intent
    // forever (execution_result rows carry no mandateId to look at).
    const entries = makeEntries([
      { type: "mandate_consumed", data: { mandateId: "m-1", use: 1 }, msAgo: HOUR, intentId: "earlier-intent" },
    ]);
    const a = card.assess({
      intent: makeIntent({ mandateId: "m-1" }),
      policy: makePolicy(),
      entries,
      nowMs: T0,
    });
    expect(a.signals).toEqual([]);
  });

  it("a DIFFERENT mandate's consumption is not this mandate's history", () => {
    const entries = makeEntries([
      { type: "mandate_consumed", data: { mandateId: "m-OTHER", use: 1 }, msAgo: HOUR, intentId: "x" },
    ]);
    const a = card.assess({
      intent: makeIntent({ mandateId: "m-1" }),
      policy: makePolicy(),
      entries,
      nowMs: T0,
    });
    expect(a.signals.map((s) => s.signal)).toEqual(["FIRST_USE_OF_MANDATE"]);
  });

  it("a retry scores like its original: the intent's OWN consume row is not history against itself", () => {
    const intent = makeIntent({ mandateId: "m-1" });
    const entries = makeEntries([
      { type: "mandate_consumed", data: { mandateId: "m-1", use: 1 }, msAgo: HOUR, intentId: intent.id },
    ]);
    const a = card.assess({ intent, policy: makePolicy(), entries, nowMs: T0 });
    expect(a.signals.map((s) => s.signal)).toEqual(["FIRST_USE_OF_MANDATE"]);
  });

  it("the carve-out: no mandateId, no signal — attacker-controlled omission suppresses exactly this weight", () => {
    const a = card.assess({
      intent: makeIntent(),
      policy: makePolicy(),
      entries: [],
      nowMs: T0,
    });
    expect(a.signals).toEqual([]);
  });
});

describe("CAP_APPROACH", () => {
  const card = new RiskScorecard(
    baseConfig({ signals: { CAP_APPROACH: { weight: 4, thresholdBps: 8_000 } } }),
  );
  const policy = makePolicy({ limits: { perDayMinor: 10_000 } });

  it("fires when day spend + amount reaches thresholdBps of perDayMinor (inclusive boundary)", () => {
    const entries = makeEntries([spendRow(7_000, HOUR, "host:a.example")]);
    const at = card.assess({
      intent: makeIntent({ amount: { amountMinor: 1_000, currency: "USD" } }),
      policy,
      entries,
      nowMs: T0,
    }); // 8000/10000 == 8000 bps — at the threshold, fires
    expect(at.signals.map((s) => s.signal)).toEqual(["CAP_APPROACH"]);
    const below = card.assess({
      intent: makeIntent({ amount: { amountMinor: 999, currency: "USD" } }),
      policy,
      entries,
      nowMs: T0,
    });
    expect(below.signals).toEqual([]);
  });

  it("counts only the rolling 24h, not the whole lookback", () => {
    const entries = makeEntries([spendRow(7_000, 25 * HOUR, "host:a.example")]);
    const a = card.assess({
      intent: makeIntent({ amount: { amountMinor: 1_000, currency: "USD" } }),
      policy,
      entries,
      nowMs: T0,
    });
    expect(a.signals).toEqual([]);
  });

  it("CONFIGURED but no perDayMinor on the active policy throws RiskUnscorableError — incoherence is unscorable, not ignorable", () => {
    expect(() =>
      card.assess({
        intent: makeIntent(),
        policy: makePolicy({ limits: {} }),
        entries: [],
        nowMs: T0,
      }),
    ).toThrowError(RiskUnscorableError);
  });
});

describe("tiers and thresholds", () => {
  const card = new RiskScorecard(
    baseConfig({
      stepUpAt: 5,
      denyAt: 10,
      signals: {
        FIRST_SEEN_MERCHANT: { weight: 5 },
        OUT_OF_HOURS: { weight: 5, allowedWindowsUtc: BUSINESS_HOURS },
      },
    }),
  );
  const seen = makeEntries([spendRow(100, HOUR, "host:api.openai.com")]);
  const intent = makeIntent({ merchant: { id: "openai", url: "https://api.openai.com/v1" } });

  it("score 0 -> low", () => {
    const a = card.assess({ intent, policy: makePolicy(), entries: seen, nowMs: T0 });
    expect(a).toMatchObject({ score: 0, tier: "low" });
  });

  it("score == stepUpAt -> elevated (inclusive)", () => {
    const a = card.assess({ intent, policy: makePolicy(), entries: [], nowMs: T0 });
    expect(a).toMatchObject({ score: 5, tier: "elevated" });
  });

  it("score == denyAt -> high (inclusive)", () => {
    const night = Date.parse("2026-01-05T03:00:00.000Z");
    const a = card.assess({ intent, policy: makePolicy(), entries: [], nowMs: night });
    expect(a).toMatchObject({ score: 10, tier: "high" });
  });
});

describe("invariance properties", () => {
  const card = new RiskScorecard(
    baseConfig({
      signals: {
        FIRST_SEEN_MERCHANT: { weight: 2 },
        OUT_OF_HOURS: { weight: 2, allowedWindowsUtc: BUSINESS_HOURS },
        VELOCITY_BURST: { weight: 2, maxCount: 1, windowMs: HOUR },
        FIRST_USE_OF_MANDATE: { weight: 3 },
      },
    }),
  );
  const entries = makeEntries([spendRow(100, HOUR / 2, "host:api.openai.com")]);

  it("the assessment is agentId-INVARIANT — a rotated agentId must not move the score", () => {
    const a = card.assess({
      intent: makeIntent({ id: "same", agentId: "agent-A", mandateId: "m-1" }),
      policy: makePolicy(),
      entries,
      nowMs: T0,
    });
    const b = card.assess({
      intent: makeIntent({ id: "same", agentId: "agent-TOTALLY-DIFFERENT", mandateId: "m-1" }),
      policy: makePolicy(),
      entries,
      nowMs: T0,
    });
    expect(b).toEqual(a);
  });

  it("signals key on exactly (merchant identity, amount, mandateId): every other intent field is inert", () => {
    const base = card.assess({
      intent: makeIntent({ id: "same", mandateId: "m-1" }),
      policy: makePolicy(),
      entries,
      nowMs: T0,
    });
    const decorated = card.assess({
      intent: makeIntent({
        id: "same",
        mandateId: "m-1",
        category: "totally-different",
        rail: "different-rail",
        description: "innocent-looking description",
        metadata: { anything: "at all" },
        context: { taskId: "t-1" },
        requestedAt: "1999-01-01T00:00:00.000Z",
      }),
      policy: makePolicy(),
      entries,
      nowMs: T0,
    });
    expect(decorated).toEqual(base);
  });

  it("the mandateId carve-out, quantified: omitting it lowers the score by exactly FIRST_USE_OF_MANDATE's weight", () => {
    // mandateId is attacker-controlled and DELIBERATELY excluded from the
    // invariance property above — this is the one omission that suppresses
    // weight, and it is documented rather than implicit.
    const withMandate = card.assess({
      intent: makeIntent({ id: "same", mandateId: "m-1" }),
      policy: makePolicy(),
      entries,
      nowMs: T0,
    });
    const withoutMandate = card.assess({
      intent: makeIntent({ id: "same" }),
      policy: makePolicy(),
      entries,
      nowMs: T0,
    });
    expect(withMandate.score - withoutMandate.score).toBe(3);
  });

  it("score is monotone non-decreasing in the amount — a bigger ask can never look safer", () => {
    const amountCard = new RiskScorecard(
      baseConfig({
        signals: {
          AMOUNT_ABOVE_MERCHANT_TYPICAL: { weight: 2, multiplierBps: 20_000, minHistory: 1 },
          AMOUNT_ABOVE_GLOBAL_TYPICAL: { weight: 2, multiplierBps: 30_000, minHistory: 1 },
          CAP_APPROACH: { weight: 2, thresholdBps: 8_000 },
        },
      }),
    );
    const policy = makePolicy({ limits: { perDayMinor: 100_000 } });
    const history = makeEntries([spendRow(1_000, HOUR, "host:api.openai.com")]);
    let prev = -1;
    for (const amountMinor of [1, 1_000, 2_001, 3_001, 50_000, 90_000]) {
      const a = amountCard.assess({
        intent: makeIntent({
          merchant: { id: "openai", url: "https://api.openai.com/v1" },
          amount: { amountMinor, currency: "USD" },
        }),
        policy,
        entries: history,
        nowMs: T0,
      });
      expect(a.score).toBeGreaterThanOrEqual(prev);
      prev = a.score;
    }
    expect(prev).toBeGreaterThan(0); // the ladder actually climbed
  });
});

describe("applyRiskTier: MONOTONE, TIGHTEN-ONLY merge", () => {
  const RANK: Record<PolicyResult["decision"], number> = {
    allow: 0,
    require_approval: 1,
    deny: 2,
  };
  const TIER_RANK = { low: 0, elevated: 1, high: 2 } as const;
  const mkBase = (decision: PolicyResult["decision"]): PolicyResult => ({
    decision,
    reasons: [{ code: "BASE", message: "base reason" }],
    policyId: "p",
    policyVersion: 1,
  });
  const mkAssessment = (tier: "low" | "elevated" | "high"): RiskAssessment => ({
    score: tier === "low" ? 0 : tier === "elevated" ? 5 : 10,
    tier,
    signals: [{ signal: "OUT_OF_HOURS", weight: 5, detail: "d" }],
    anchor: { seq: -1, hash: GENESIS_HASH },
    atMs: T0,
    configHash: "c",
  });

  it("for every (base, tier) pair the merged decision is exactly max(base, tier) — never looser than either", () => {
    for (const decision of ["allow", "require_approval", "deny"] as const) {
      for (const tier of ["low", "elevated", "high"] as const) {
        const merged = applyRiskTier(mkBase(decision), mkAssessment(tier));
        expect(RANK[merged.decision]).toBe(Math.max(RANK[decision], TIER_RANK[tier]));
        // The base reasons are never dropped — evidence accumulates.
        expect(merged.reasons.some((r) => r.code === "BASE")).toBe(true);
      }
    }
  });

  it("elevated appends RISK_STEPUP plus the fired signals; high appends RISK_DENY plus the fired signals", () => {
    const stepUp = applyRiskTier(mkBase("allow"), mkAssessment("elevated"));
    expect(stepUp.reasons.map((r) => r.code)).toEqual(["BASE", "RISK_STEPUP", "OUT_OF_HOURS"]);
    const deny = applyRiskTier(mkBase("allow"), mkAssessment("high"));
    expect(deny.reasons.map((r) => r.code)).toEqual(["BASE", "RISK_DENY", "OUT_OF_HOURS"]);
  });

  it("low leaves the base result untouched", () => {
    const base = mkBase("require_approval");
    expect(applyRiskTier(base, mkAssessment("low"))).toBe(base);
  });
});

describe("the anchor and anchoredPrefix (replay is against the SCORED prefix, not 'the ledger now')", () => {
  const card = new RiskScorecard(
    baseConfig({ signals: { VELOCITY_BURST: { weight: 5, maxCount: 2, windowMs: HOUR } } }),
  );

  it("the anchor is the last entry seen; an empty ledger anchors at seq -1 / genesis", () => {
    const entries = makeEntries([spendRow(1, HOUR / 2, "host:a.example")]);
    const a = card.assess({ intent: makeIntent(), policy: makePolicy(), entries, nowMs: T0 });
    expect(a.anchor).toEqual({ seq: 0, hash: "hash-0" });
    const empty = card.assess({ intent: makeIntent(), policy: makePolicy(), entries: [], nowMs: T0 });
    expect(empty.anchor).toEqual({ seq: -1, hash: GENESIS_HASH });
  });

  it("replaying the anchored prefix reproduces the assessment even after MORE entries landed", () => {
    // Two spends -> burst fires. Score, then let a third spend land: a naive
    // replay over the grown ledger would see a different burst count.
    const scored = makeEntries([
      spendRow(1, HOUR / 2, "host:a.example"),
      spendRow(1, HOUR / 3, "host:a.example"),
    ]);
    const intent = makeIntent();
    const a = card.assess({ intent, policy: makePolicy(), entries: scored, nowMs: T0 });
    expect(a.signals.map((s) => s.signal)).toEqual(["VELOCITY_BURST"]);

    const grown = [
      ...scored,
      ...makeEntries([spendRow(1, HOUR / 4, "host:a.example")]).map((e) => ({
        ...e,
        seq: 2,
      })),
    ];
    const replay = card.assess({
      intent,
      policy: makePolicy(),
      entries: anchoredPrefix(grown, a.anchor),
      nowMs: a.atMs,
    });
    expect(replay).toEqual(a);
  });

  it("anchoredPrefix REFUSES a ledger whose anchored entry does not match (rewritten history)", () => {
    const entries = makeEntries([spendRow(1, HOUR / 2, "host:a.example")]);
    expect(() => anchoredPrefix(entries, { seq: 0, hash: "not-the-hash" })).toThrowError(
      /not satisfiable/,
    );
    expect(() => anchoredPrefix([], { seq: 3, hash: "whatever" })).toThrowError(
      /not satisfiable/,
    );
  });
});

describe("unscorable inputs fail closed, never score 0", () => {
  const card = new RiskScorecard(baseConfig());
  it("a non-finite clock is unscorable", () => {
    expect(() =>
      card.assess({ intent: makeIntent(), policy: makePolicy(), entries: [], nowMs: Number.NaN }),
    ).toThrowError(RiskUnscorableError);
  });
  it("an unusable amount is unscorable", () => {
    expect(() =>
      card.assess({
        intent: makeIntent({ amount: { amountMinor: Number.NaN, currency: "USD" } }),
        policy: makePolicy(),
        entries: [],
        nowMs: T0,
      }),
    ).toThrowError(RiskUnscorableError);
  });
});
