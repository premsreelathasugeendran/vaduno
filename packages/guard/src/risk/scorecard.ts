import { GENESIS_HASH, type LedgerEntry } from "../ledger/ledger.js";
import { canonicalJson, sha256Hex } from "../ledger/hash.js";
import { merchantKeyOf } from "../enforce/spend-limiter.js";
import type { PaymentIntent, PolicyResult, SpendPolicy } from "../types.js";

/**
 * Deterministic risk scorecard: ledger-derived tiers, step-up routing, and
 * auto-freeze — the analogue of 3DS2 risk-based authentication ROUTING
 * (frictionless → allow unchanged, challenge → the existing approvalHandler)
 * and of the SIGNALS behind Visa Advanced Authorization / Mastercard Decision
 * Intelligence, computed deterministically at ONE deployment and reproducible
 * from its ledger. Deliberately not black-box ML: every fired signal names its
 * rule, and the whole assessment can be replayed bit-for-bit against the
 * ledger prefix it was scored over (see `RiskAssessment.anchor`).
 *
 * MECHANISM-ONLY comparison, stated so nobody infers more: real 3DS2 in the
 * card networks carries an ISSUER LIABILITY SHIFT. Vaduno's scorecard shifts
 * liability to NO ONE — it only routes a payment to allow / step-up / deny at
 * this deployment.
 *
 * HONEST BOUNDARY: the scorer sees ONE deployment's ledger, never
 * network-scale data. Merchant identity authority remains the policy
 * allowlist. Risk is defense-in-depth layered ON TOP of policy — it can only
 * TIGHTEN a decision (see `applyRiskTier`), NEVER allow one, so it is never
 * an allow authority.
 */

const DAY_MS = 24 * 60 * 60 * 1000;

/** Domain tag for `RiskAssessment.configHash` (see `canonicalJson` docs). */
const CONFIG_HASH_DOMAIN = "vaduno-risk-scorecard/v1\n";

/**
 * The eight signal keys, in the FIXED order they are evaluated and reported —
 * a deterministic assessment must not depend on object-key enumeration order.
 */
export const RISK_SIGNAL_KEYS = [
  "FIRST_SEEN_MERCHANT",
  "AMOUNT_ABOVE_MERCHANT_TYPICAL",
  "AMOUNT_ABOVE_GLOBAL_TYPICAL",
  "OUT_OF_HOURS",
  "VELOCITY_BURST",
  "DENY_STREAK",
  "FIRST_USE_OF_MANDATE",
  "CAP_APPROACH",
] as const;

export type RiskSignalKey = (typeof RISK_SIGNAL_KEYS)[number];

/** Half-open [startMinute, endMinute) window of allowed UTC minutes-of-day. */
export interface UtcMinuteWindow {
  /** Inclusive, 0..1439. */
  startMinute: number;
  /** Exclusive, 1..1440. */
  endMinute: number;
}

/**
 * Per-signal configuration. Every weight is a POSITIVE safe integer: a fired
 * signal can only ADD score, never subtract. What an attacker influences is
 * WHICH signals fire, and each lever points the safe way — an unfamiliar
 * merchant, a larger amount, a fresh mandate all RAISE the score. The one
 * score-LOWERING omission is `intent.mandateId`: omitting it un-fires
 * FIRST_USE_OF_MANDATE when the guard does not `requireMandate` — the
 * documented carve-out on that signal's docblock.
 */
export interface RiskSignalsConfig {
  /**
   * Fires when no successful spend for this merchant (its `merchantKeyOf()`
   * key) exists within the lookback. History rows recorded WITHOUT a
   * merchantKey (pre-velocity ledgers) deliberately do NOT establish
   * familiarity — an unattributable row must not vouch for any merchant.
   */
  FIRST_SEEN_MERCHANT?: { weight: number };
  /**
   * Fires when `amountMinor × 10000 > lowerMedian × multiplierBps`, where
   * lowerMedian is over this merchant's successful spends in the lookback —
   * BigInt math, no floats. Gated: fewer than `minHistory` records means no
   * baseline, and NO baseline means the signal stays silent (a rotated
   * merchant with no history is FIRST_SEEN_MERCHANT's job, not this one's).
   */
  AMOUNT_ABOVE_MERCHANT_TYPICAL?: {
    weight: number;
    /** Basis points of the lower-median that the amount must exceed to fire. */
    multiplierBps: number;
    /** Minimum records before a "typical" exists at all. */
    minHistory: number;
  };
  /** Same rule as AMOUNT_ABOVE_MERCHANT_TYPICAL over ALL lookback spends. */
  AMOUNT_ABOVE_GLOBAL_TYPICAL?: {
    weight: number;
    multiplierBps: number;
    minHistory: number;
  };
  /**
   * Fires when now() falls outside EVERY declared window. The windows are
   * config-DECLARED, never learned from traffic — a learned schedule is an
   * attacker-trainable one.
   */
  OUT_OF_HOURS?: { weight: number; allowedWindowsUtc: UtcMinuteWindow[] };
  /**
   * Fires when the count of successful spends within `windowMs` has already
   * reached `maxCount` — this intent would extend a burst. Distinct from the
   * limiter's velocity DENY: this is a score contribution that can route to
   * step-up below the hard cap.
   */
  VELOCITY_BURST?: { weight: number; maxCount: number; windowMs: number };
  /**
   * Fires when at least `minDenies` denial decisions landed within
   * `windowMs` — a compromised agent probing the policy leaves exactly this
   * trail. Counted guard-wide (never per agentId: agentId is
   * attacker-controlled, and a per-agent streak would reset by rotation).
   *
   * SELF-AMPLIFYING, deliberately: the streak counts EVERY `policy_decision`
   * deny, including denies this scorecard itself produced (`RISK_DENY`,
   * `RISK_UNSCORABLE`, `RISK_STEPUP_UNAPPROVED`). Scoring high therefore makes
   * the next intent score higher. The direction is always tighten, never
   * loosen — but with `autoFreeze` configured, a run of unrelated policy
   * denials (a misconfigured merchant allowlist, a currency mismatch) can
   * cascade into freezing the process. Tune `minDenies` against your ordinary
   * denial rate, not against the attack you are imagining.
   */
  DENY_STREAK?: { weight: number; minDenies: number; windowMs: number };
  /**
   * Fires when the intent carries a mandateId with NO prior consumed use in
   * the anchored ledger — the first spend under a fresh permission slip is
   * the one a stolen or injected mandate makes. Derived by joining
   * `mandate_consumed` entries (which carry the mandateId; `execution_result`
   * rows do not), excluding rows whose intentId is THIS intent (a retry must
   * score like its original, not see its own first attempt as history).
   *
   * THE DOCUMENTED CARVE-OUT: `intent.mandateId` is attacker-controlled, and
   * omitting it suppresses exactly this signal's weight when the guard does
   * not `requireMandate` (with `requireMandate: true` a mandate-less intent
   * is denied before risk ever runs). The field-invariance property test
   * deliberately excludes mandateId for this reason.
   */
  FIRST_USE_OF_MANDATE?: { weight: number };
  /**
   * Fires when day spend + this amount reaches `thresholdBps` of the
   * policy's `limits.perDayMinor` (rolling 24h, matching the policy window).
   * Configured while the active policy has NO perDayMinor →
   * `RiskUnscorableError`: config incoherence is unscorable, not ignorable.
   */
  CAP_APPROACH?: { weight: number; thresholdBps: number };
}

export interface RiskScorecardConfig {
  /** How far back (ms) spend/deny history is read. Positive finite. */
  lookbackMs: number;
  /** score >= stepUpAt → tier "elevated" (require_approval). */
  stepUpAt: number;
  /** score >= denyAt → tier "high" (deny; approval can never override). */
  denyAt: number;
  /**
   * score >= atScore → deny this intent AND freeze the guard (manual
   * unfreeze only). Validated >= denyAt: an auto-freeze below the deny tier
   * would freeze on payments the scorecard itself considers passable.
   * Inherits guard.freeze()'s PER-PROCESS scope — it does not stop a peer
   * process; wire the separate cross-process FreezeStore for that.
   */
  autoFreeze?: { atScore: number };
  signals: RiskSignalsConfig;
}

export type RiskTier = "low" | "elevated" | "high";

export interface RiskFiredSignal {
  signal: RiskSignalKey;
  weight: number;
  detail: string;
}

/**
 * The ledger position an assessment was scored against. `seq`/`hash` are the
 * LAST entry the scorer saw (`seq: -1` + the genesis hash for an empty
 * ledger). Replay is defined against THIS anchor, not against "the ledger
 * now": the history read and the risk_scored append are not atomic w.r.t.
 * the append queue, so concurrent intents interleave entries between them —
 * replaying over the full ledger would feed the signals different data and
 * the reproducibility claim would be quietly false. `anchoredPrefix()`
 * reconstructs the exact scored prefix.
 */
export interface RiskAnchor {
  seq: number;
  hash: string;
}

export interface RiskAssessment {
  /** Sum of fired signal weights. Integer. */
  score: number;
  tier: RiskTier;
  /** Fired signals only, in RISK_SIGNAL_KEYS order. */
  signals: RiskFiredSignal[];
  anchor: RiskAnchor;
  /** The injected now() the assessment was scored at (epoch ms). */
  atMs: number;
  /** Hash of the scorecard config, so a replay can prove it used the same one. */
  configHash: string;
}

export interface RiskAssessInput {
  intent: PaymentIntent;
  policy: SpendPolicy;
  /** Ledger prefix to score over; its LAST entry becomes the anchor. */
  entries: readonly LedgerEntry[];
  /** Injected clock reading (epoch ms). */
  nowMs: number;
}

/** Constructor-time config rejection. `violations` lists EVERY problem found. */
export class RiskConfigError extends Error {
  readonly violations: string[];
  constructor(violations: string[]) {
    super(
      `invalid RiskScorecard config (${violations.length} violation(s)):\n - ` +
        violations.join("\n - "),
    );
    this.name = "RiskConfigError";
    this.violations = violations;
  }
}

/**
 * "This intent cannot be scored" — which the guard turns into a DENY
 * (RISK_UNSCORABLE), never into a skip. Config incoherence discovered at
 * assess time (e.g. CAP_APPROACH with no perDayMinor on the active policy)
 * and unusable inputs land here.
 */
export class RiskUnscorableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RiskUnscorableError";
  }
}

/**
 * Reconstruct the exact prefix an assessment was scored over, verifying the
 * anchor still matches. Throws if the ledger no longer contains an entry with
 * the anchored seq and hash — a replay against different bytes would be a
 * reproducibility claim about nothing.
 */
export function anchoredPrefix(
  entries: readonly LedgerEntry[],
  anchor: RiskAnchor,
): LedgerEntry[] {
  if (anchor.seq < 0) return [];
  const prefix = entries.filter((e) => e.seq <= anchor.seq);
  const last = prefix.length > 0 ? prefix[prefix.length - 1]! : null;
  if (!last || last.seq !== anchor.seq || last.hash !== anchor.hash) {
    throw new Error(
      `risk anchor (seq ${anchor.seq}) is not satisfiable against this ledger: ` +
        (last
          ? `entry at seq ${last.seq} has hash ${last.hash.slice(0, 12)}…, anchor expects ${anchor.hash.slice(0, 12)}…`
          : "no entries at or before the anchored seq"),
    );
  }
  return prefix;
}

const RANK: Record<PolicyResult["decision"], number> = {
  allow: 0,
  require_approval: 1,
  deny: 2,
};

/**
 * Merge a risk tier into a policy result. MONOTONE, TIGHTEN-ONLY
 * (allow < require_approval < deny):
 *  - low       → the base result, unchanged;
 *  - elevated  → at least require_approval (a base deny stays a deny), with
 *                RISK_STEPUP plus every fired signal appended to reasons;
 *  - high      → deny, with RISK_DENY plus every fired signal appended.
 *
 * A merge that could ever LOWER the base decision would make the risk layer
 * an allow authority, which it must never be.
 */
export function applyRiskTier(
  base: PolicyResult,
  assessment: RiskAssessment,
): PolicyResult {
  if (assessment.tier === "low") return base;
  const signalReasons = assessment.signals.map((s) => ({
    code: s.signal,
    message: s.detail,
  }));
  if (assessment.tier === "high") {
    return {
      ...base,
      decision: "deny",
      reasons: [
        ...base.reasons,
        {
          code: "RISK_DENY",
          message: `risk score ${assessment.score} reached the deny tier`,
        },
        ...signalReasons,
      ],
    };
  }
  // elevated: never loosen a base deny.
  const decision = RANK[base.decision] >= RANK.require_approval ? base.decision : "require_approval";
  return {
    ...base,
    decision,
    reasons: [
      ...base.reasons,
      {
        code: "RISK_STEPUP",
        message: `risk score ${assessment.score} reached the step-up tier`,
      },
      ...signalReasons,
    ],
  };
}

/** Allowed option keys per signal, for typo rejection. */
const SIGNAL_OPTION_KEYS: Record<RiskSignalKey, readonly string[]> = {
  FIRST_SEEN_MERCHANT: ["weight"],
  AMOUNT_ABOVE_MERCHANT_TYPICAL: ["weight", "multiplierBps", "minHistory"],
  AMOUNT_ABOVE_GLOBAL_TYPICAL: ["weight", "multiplierBps", "minHistory"],
  OUT_OF_HOURS: ["weight", "allowedWindowsUtc"],
  VELOCITY_BURST: ["weight", "maxCount", "windowMs"],
  DENY_STREAK: ["weight", "minDenies", "windowMs"],
  FIRST_USE_OF_MANDATE: ["weight"],
  CAP_APPROACH: ["weight", "thresholdBps"],
};

const TOP_KEYS = new Set(["lookbackMs", "stepUpAt", "denyAt", "autoFreeze", "signals"]);

function isPlainObject(x: unknown): x is Record<string, unknown> {
  return x !== null && typeof x === "object" && !Array.isArray(x);
}

function isPosSafeInt(x: unknown): x is number {
  return typeof x === "number" && Number.isSafeInteger(x) && x > 0;
}

function isPosFinite(x: unknown): x is number {
  return typeof x === "number" && Number.isFinite(x) && x > 0;
}

/**
 * Collect EVERY violation — the constructor throws them all at once, because
 * a validator that stops at the first problem trains the operator to fix
 * config one error message at a time.
 */
function violationsOf(config: unknown): string[] {
  const v: string[] = [];
  if (!isPlainObject(config)) return ["config must be a plain object"];

  for (const k of Object.keys(config)) {
    if (!TOP_KEYS.has(k)) v.push(`unknown config key "${k}"`);
  }

  const lookbackMs = config.lookbackMs;
  const lookbackOk = isPosFinite(lookbackMs);
  if (!lookbackOk) {
    v.push(`lookbackMs ${String(lookbackMs)} is not a positive finite number`);
  }

  const stepUpOk = isPosSafeInt(config.stepUpAt);
  if (!stepUpOk) v.push(`stepUpAt ${String(config.stepUpAt)} is not a positive safe integer`);
  const denyOk = isPosSafeInt(config.denyAt);
  if (!denyOk) v.push(`denyAt ${String(config.denyAt)} is not a positive safe integer`);
  if (stepUpOk && denyOk && (config.stepUpAt as number) > (config.denyAt as number)) {
    v.push(
      `stepUpAt ${String(config.stepUpAt)} > denyAt ${String(config.denyAt)} — the step-up tier would sit above the deny tier`,
    );
  }

  if (config.autoFreeze !== undefined) {
    if (!isPlainObject(config.autoFreeze)) {
      v.push("autoFreeze must be a plain object { atScore }");
    } else {
      for (const k of Object.keys(config.autoFreeze)) {
        if (k !== "atScore") v.push(`unknown autoFreeze key "${k}"`);
      }
      const atScore = config.autoFreeze.atScore;
      if (!isPosSafeInt(atScore)) {
        v.push(`autoFreeze.atScore ${String(atScore)} is not a positive safe integer`);
      } else if (denyOk && atScore < (config.denyAt as number)) {
        // An auto-freeze below the deny tier would freeze the guard on
        // payments the scorecard itself would let through.
        v.push(
          `autoFreeze.atScore ${String(atScore)} < denyAt ${String(config.denyAt)} — auto-freeze must sit at or above the deny tier`,
        );
      }
    }
  }

  const signals = config.signals;
  if (!isPlainObject(signals)) {
    v.push("signals must be a plain object mapping signal keys to configs");
    return v;
  }

  let knownSignals = 0;
  let totalWeight = 0;
  const requireOpts = (key: string, opts: Record<string, unknown>): void => {
    for (const k of Object.keys(opts)) {
      if (!SIGNAL_OPTION_KEYS[key as RiskSignalKey].includes(k)) {
        v.push(`unknown option "${k}" on signal ${key}`);
      }
    }
    if (!isPosSafeInt(opts.weight)) {
      // Positive is load-bearing, not stylistic: a zero or negative weight
      // would let a fired signal LOWER or no-op the score, breaking the
      // raise-or-preserve invariant.
      v.push(`${key}.weight ${String(opts.weight)} is not a positive safe integer`);
    } else {
      totalWeight += opts.weight as number;
    }
  };

  const windowedRule = (key: string, windowMs: unknown): void => {
    if (!isPosFinite(windowMs)) {
      v.push(`${key}.windowMs ${String(windowMs)} is not a positive finite number`);
    } else if (lookbackOk && (windowMs as number) > (lookbackMs as number)) {
      // History is only read within lookbackMs; a wider window would
      // silently count over less history than it claims.
      v.push(
        `${key}.windowMs ${String(windowMs)} exceeds lookbackMs ${String(lookbackMs)} — the window would silently see less history than configured`,
      );
    }
  };

  for (const key of Object.keys(signals)) {
    if (!(RISK_SIGNAL_KEYS as readonly string[]).includes(key)) {
      // A typo must not silently no-op: an operator who configured
      // "FIRST_SEEN_MERCHENT" believes a control exists that does not.
      v.push(`unknown signal key "${key}"`);
      continue;
    }
    knownSignals += 1;
    const opts = signals[key];
    if (!isPlainObject(opts)) {
      v.push(`signal ${key} must be a plain config object`);
      continue;
    }
    requireOpts(key, opts);
    switch (key as RiskSignalKey) {
      case "AMOUNT_ABOVE_MERCHANT_TYPICAL":
      case "AMOUNT_ABOVE_GLOBAL_TYPICAL": {
        if (!isPosSafeInt(opts.multiplierBps)) {
          v.push(`${key}.multiplierBps ${String(opts.multiplierBps)} is not a positive safe integer`);
        }
        if (!isPosSafeInt(opts.minHistory)) {
          v.push(`${key}.minHistory ${String(opts.minHistory)} is not a positive safe integer`);
        }
        break;
      }
      case "OUT_OF_HOURS": {
        const windows = opts.allowedWindowsUtc;
        if (!Array.isArray(windows) || windows.length === 0) {
          // An empty allowed list fires on EVERYTHING, which is almost
          // certainly a truncated config rather than a decision.
          v.push(`${key}.allowedWindowsUtc must be a non-empty array of {startMinute, endMinute}`);
        } else {
          windows.forEach((w, i) => {
            if (!isPlainObject(w)) {
              v.push(`${key}.allowedWindowsUtc[${i}] must be a plain object`);
              return;
            }
            for (const k of Object.keys(w)) {
              if (k !== "startMinute" && k !== "endMinute") {
                v.push(`unknown option "${k}" on ${key}.allowedWindowsUtc[${i}]`);
              }
            }
            const s = w.startMinute;
            const e = w.endMinute;
            const sOk = typeof s === "number" && Number.isSafeInteger(s) && s >= 0 && s < 1440;
            const eOk = typeof e === "number" && Number.isSafeInteger(e) && e >= 1 && e <= 1440;
            if (!sOk) v.push(`${key}.allowedWindowsUtc[${i}].startMinute ${String(s)} is not an integer in 0..1439`);
            if (!eOk) v.push(`${key}.allowedWindowsUtc[${i}].endMinute ${String(e)} is not an integer in 1..1440`);
            if (sOk && eOk && (s as number) >= (e as number)) {
              v.push(`${key}.allowedWindowsUtc[${i}] is empty (startMinute ${String(s)} >= endMinute ${String(e)}); windows are half-open [start, end) and do not wrap midnight — declare two`);
            }
          });
        }
        break;
      }
      case "VELOCITY_BURST": {
        if (!isPosSafeInt(opts.maxCount)) {
          v.push(`${key}.maxCount ${String(opts.maxCount)} is not a positive safe integer`);
        }
        windowedRule(key, opts.windowMs);
        break;
      }
      case "DENY_STREAK": {
        if (!isPosSafeInt(opts.minDenies)) {
          v.push(`${key}.minDenies ${String(opts.minDenies)} is not a positive safe integer`);
        }
        windowedRule(key, opts.windowMs);
        break;
      }
      case "CAP_APPROACH": {
        const t = opts.thresholdBps;
        if (!isPosSafeInt(t) || (t as number) > 10_000) {
          v.push(`${key}.thresholdBps ${String(t)} is not an integer in 1..10000`);
        }
        if (lookbackOk && (lookbackMs as number) < DAY_MS) {
          v.push(
            `${key} requires lookbackMs >= ${DAY_MS} (the rolling perDay window) — a shorter lookback would silently undercount the day total`,
          );
        }
        break;
      }
      default:
        break;
    }
  }
  if (knownSignals === 0) {
    v.push("signals configures no known signal — a scorecard that can never fire enforces nothing");
  }
  if (!Number.isSafeInteger(totalWeight)) {
    v.push("total signal weight overflows the safe-integer range");
  }
  return v;
}

/** Lower median: element at index floor((n-1)/2) of the ascending sort. */
function lowerMedian(values: bigint[]): bigint {
  const sorted = [...values].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return sorted[Math.floor((sorted.length - 1) / 2)]!;
}

interface SpendRow {
  ms: number;
  amountMinor: bigint;
  merchantKey?: string;
}

/**
 * Deterministic risk scorer over a ledger prefix.
 *
 * `assess()` is a PURE function of (intent, policy, entries, nowMs) and the
 * validated config: same inputs, same assessment, bit for bit. That is the
 * whole point — an operator can take any `risk_scored` ledger row, rebuild
 * the anchored prefix with `anchoredPrefix()`, and re-derive the identical
 * assessment. No signal reads `intent.agentId` (attacker-controlled;
 * a per-agent signal would reset by rotation), so the assessment is
 * agentId-invariant by construction.
 *
 * History counted: successful `execution_result` rows (the same rows every
 * other spend consumer counts) in the policy currency within `lookbackMs`;
 * `policy_decision` deny rows for DENY_STREAK; `mandate_consumed` rows for
 * FIRST_USE_OF_MANDATE. Rows the scorer cannot parse are skipped, which only
 * shrinks history — and thin history fires the unfamiliarity signals MORE,
 * not less.
 */
export class RiskScorecard {
  private readonly config: RiskScorecardConfig;
  /** sha256 over a domain tag + the canonical JSON of the validated config. */
  readonly configHash: string;

  constructor(config: RiskScorecardConfig) {
    const violations = violationsOf(config);
    if (violations.length > 0) throw new RiskConfigError(violations);
    // Pinned to a private copy so later caller-side mutation cannot diverge
    // the live behavior from the configHash already stamped on assessments.
    this.config = structuredClone(config);
    this.configHash = sha256Hex(CONFIG_HASH_DOMAIN + canonicalJson(this.config));
  }

  /** `autoFreeze.atScore`, or null when auto-freeze is not configured. */
  get autoFreezeAtScore(): number | null {
    return this.config.autoFreeze?.atScore ?? null;
  }

  assess(input: RiskAssessInput): RiskAssessment {
    const { intent, policy, entries, nowMs } = input;
    // Unusable inputs are UNSCORABLE, never "score 0": zero is the most
    // permissive score there is.
    if (!Number.isSafeInteger(nowMs)) {
      throw new RiskUnscorableError(`nowMs ${String(nowMs)} is not a safe integer (fail closed)`);
    }
    const amount = intent.amount.amountMinor;
    if (!Number.isSafeInteger(amount) || amount < 0) {
      throw new RiskUnscorableError(
        `amountMinor ${String(amount)} is not a non-negative safe integer (fail closed)`,
      );
    }

    const cfg = this.config;
    const last = entries.length > 0 ? entries[entries.length - 1]! : null;
    const anchor: RiskAnchor = last
      ? { seq: last.seq, hash: last.hash }
      : { seq: -1, hash: GENESIS_HASH };

    const lookbackSince = nowMs - cfg.lookbackMs;
    const wantCurrency = policy.currency.toUpperCase();
    const merchantKey = merchantKeyOf(intent.merchant);
    const mandateId =
      typeof intent.mandateId === "string" && intent.mandateId.length > 0
        ? intent.mandateId
        : null;

    // One pass over the prefix: policy-currency spend rows and deny rows
    // within the lookback, plus prior uses of this intent's mandate (the
    // mandate join is over the WHOLE prefix — "first use" is defined against
    // the anchored history, and lookback-limiting it would re-fire the
    // signal on every long-lived mandate).
    const spends: SpendRow[] = [];
    const denyMs: number[] = [];
    let mandatePriorUse = false;
    for (const e of entries) {
      if (e.type === "execution_result") {
        const d = e.data;
        if (d === null || typeof d !== "object") continue;
        const row = d as {
          success?: unknown;
          amountMinor?: unknown;
          currency?: unknown;
          merchantKey?: unknown;
        };
        if (row.success !== true) continue;
        if (!Number.isSafeInteger(row.amountMinor)) continue;
        if (typeof row.currency !== "string" || row.currency.toUpperCase() !== wantCurrency) {
          continue;
        }
        const ms = Date.parse(e.timestamp);
        if (Number.isNaN(ms) || ms <= lookbackSince) continue;
        spends.push({
          ms,
          amountMinor: BigInt(row.amountMinor as number),
          ...(typeof row.merchantKey === "string" ? { merchantKey: row.merchantKey } : {}),
        });
      } else if (e.type === "policy_decision") {
        const d = e.data;
        if (d === null || typeof d !== "object") continue;
        const pr = (d as { policyResult?: unknown }).policyResult;
        if (pr === null || typeof pr !== "object") continue;
        if ((pr as { decision?: unknown }).decision !== "deny") continue;
        const ms = Date.parse(e.timestamp);
        if (Number.isNaN(ms) || ms <= lookbackSince) continue;
        denyMs.push(ms);
      } else if (mandateId !== null && e.type === "mandate_consumed") {
        const d = e.data;
        if (d === null || typeof d !== "object") continue;
        if ((d as { mandateId?: unknown }).mandateId !== mandateId) continue;
        // A retry of THIS intent must score like its original attempt — its
        // own consume row is not history against itself.
        if (e.intentId === intent.id) continue;
        mandatePriorUse = true;
      }
    }

    const fired: RiskFiredSignal[] = [];
    const s = cfg.signals;

    if (s.FIRST_SEEN_MERCHANT) {
      // Keyless rows do not establish familiarity: an unattributable spend
      // must not vouch for a merchant it cannot be attributed to.
      const seen = spends.some((r) => r.merchantKey === merchantKey);
      if (!seen) {
        fired.push({
          signal: "FIRST_SEEN_MERCHANT",
          weight: s.FIRST_SEEN_MERCHANT.weight,
          detail: `no successful spend recorded for merchant ${merchantKey} within the lookback`,
        });
      }
    }

    if (s.AMOUNT_ABOVE_MERCHANT_TYPICAL) {
      const c = s.AMOUNT_ABOVE_MERCHANT_TYPICAL;
      const amounts = spends
        .filter((r) => r.merchantKey === merchantKey)
        .map((r) => r.amountMinor);
      if (amounts.length >= c.minHistory) {
        const median = lowerMedian(amounts);
        // BigInt on both sides: median × multiplierBps overflows Number for
        // large minor-unit amounts, and a float comparison here would round
        // exactly where the money is largest.
        if (BigInt(amount) * 10_000n > median * BigInt(c.multiplierBps)) {
          fired.push({
            signal: "AMOUNT_ABOVE_MERCHANT_TYPICAL",
            weight: c.weight,
            detail: `amount ${amount} exceeds ${c.multiplierBps} bps of this merchant's lower-median ${String(median)} over ${amounts.length} records`,
          });
        }
      }
    }

    if (s.AMOUNT_ABOVE_GLOBAL_TYPICAL) {
      const c = s.AMOUNT_ABOVE_GLOBAL_TYPICAL;
      if (spends.length >= c.minHistory) {
        const median = lowerMedian(spends.map((r) => r.amountMinor));
        if (BigInt(amount) * 10_000n > median * BigInt(c.multiplierBps)) {
          fired.push({
            signal: "AMOUNT_ABOVE_GLOBAL_TYPICAL",
            weight: c.weight,
            detail: `amount ${amount} exceeds ${c.multiplierBps} bps of the global lower-median ${String(median)} over ${spends.length} records`,
          });
        }
      }
    }

    if (s.OUT_OF_HOURS) {
      const d = new Date(nowMs);
      const minute = d.getUTCHours() * 60 + d.getUTCMinutes();
      const inWindow = s.OUT_OF_HOURS.allowedWindowsUtc.some(
        (w) => minute >= w.startMinute && minute < w.endMinute,
      );
      if (!inWindow) {
        fired.push({
          signal: "OUT_OF_HOURS",
          weight: s.OUT_OF_HOURS.weight,
          detail: `UTC minute-of-day ${minute} is outside every declared allowed window`,
        });
      }
    }

    if (s.VELOCITY_BURST) {
      const c = s.VELOCITY_BURST;
      const since = nowMs - c.windowMs;
      const count = spends.filter((r) => r.ms > since).length;
      if (count >= c.maxCount) {
        fired.push({
          signal: "VELOCITY_BURST",
          weight: c.weight,
          detail: `${count} successful spends within ${c.windowMs}ms (threshold ${c.maxCount})`,
        });
      }
    }

    if (s.DENY_STREAK) {
      const c = s.DENY_STREAK;
      const since = nowMs - c.windowMs;
      const count = denyMs.filter((ms) => ms > since).length;
      if (count >= c.minDenies) {
        fired.push({
          signal: "DENY_STREAK",
          weight: c.weight,
          detail: `${count} denial decisions within ${c.windowMs}ms (threshold ${c.minDenies})`,
        });
      }
    }

    if (s.FIRST_USE_OF_MANDATE && mandateId !== null && !mandatePriorUse) {
      fired.push({
        signal: "FIRST_USE_OF_MANDATE",
        weight: s.FIRST_USE_OF_MANDATE.weight,
        detail: `no prior consumed use of mandate ${mandateId} in the anchored ledger`,
      });
    }

    if (s.CAP_APPROACH) {
      const c = s.CAP_APPROACH;
      const perDay = policy.limits?.perDayMinor;
      if (perDay === undefined) {
        // Config incoherence is UNSCORABLE, not ignorable: silently skipping
        // would leave the operator believing a cap-approach control exists.
        throw new RiskUnscorableError(
          "CAP_APPROACH is configured but the active policy has no limits.perDayMinor — config incoherence is unscorable, not ignorable (fail closed)",
        );
      }
      if (!Number.isSafeInteger(perDay) || perDay <= 0) {
        throw new RiskUnscorableError(
          `CAP_APPROACH cannot score against perDayMinor ${String(perDay)} (not a positive safe integer)`,
        );
      }
      const since = nowMs - DAY_MS;
      let dayTotal = 0n;
      for (const r of spends) {
        if (r.ms > since) dayTotal += r.amountMinor;
      }
      const projected = dayTotal + BigInt(amount);
      if (projected * 10_000n >= BigInt(perDay) * BigInt(c.thresholdBps)) {
        fired.push({
          signal: "CAP_APPROACH",
          weight: c.weight,
          detail: `day spend ${String(dayTotal)} + amount ${amount} reaches ${c.thresholdBps} bps of perDayMinor ${perDay}`,
        });
      }
    }

    let score = 0;
    for (const f of fired) score += f.weight;
    const tier: RiskTier =
      score >= cfg.denyAt ? "high" : score >= cfg.stepUpAt ? "elevated" : "low";
    return { score, tier, signals: fired, anchor, atMs: nowMs, configHash: this.configHash };
  }
}
