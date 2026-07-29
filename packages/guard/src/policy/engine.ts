import { parseMs } from "../util/time.js";
import type {
  PaymentIntent,
  PolicyReason,
  PolicyResult,
  SpendHistory,
  SpendPolicy,
  SpendWindow,
} from "../types.js";

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * The rolling constraints a policy implies, in ONE place.
 *
 * Both the advisory pre-check (this file) and the authoritative atomic reserve
 * (`SpendLimiter`) derive their windows from here. If these were written twice,
 * the fast-fail and the real gate could disagree about a cap — and the one that
 * disagreed silently would be the one holding the money.
 */
export function policyWindows(policy: SpendPolicy): SpendWindow[] {
  const limits = policy.limits ?? {};
  const windows: SpendWindow[] = [];
  const amountWindows: Array<[number | undefined, number, string]> = [
    [limits.perDayMinor, DAY_MS, "PER_DAY_LIMIT_EXCEEDED"],
    [limits.perWeekMinor, 7 * DAY_MS, "PER_WEEK_LIMIT_EXCEEDED"],
    [limits.perMonthMinor, 30 * DAY_MS, "PER_MONTH_LIMIT_EXCEEDED"],
  ];
  for (const [capMinor, windowMs, code] of amountWindows) {
    if (capMinor === undefined) continue;
    windows.push({ code, windowMs, capMinor });
  }
  const v = policy.velocity?.maxTransactions;
  if (v) {
    windows.push({
      code: "VELOCITY_EXCEEDED",
      windowMs: v.perSeconds * 1000,
      maxCount: v.count,
    });
  }
  return windows;
}

/**
 * Deterministic policy evaluation. No model in the loop: this function is
 * the last line of defense and must stay pure decision logic.
 *
 * Deny reasons are collected exhaustively (not short-circuited) so the audit
 * trail shows every rule an intent violated.
 */
export async function evaluatePolicy(
  intent: PaymentIntent,
  policy: SpendPolicy,
  history: SpendHistory,
  now: () => Date = () => new Date(),
): Promise<PolicyResult> {
  const reasons: PolicyReason[] = [];
  const nowDate = now();
  const nowMs = nowDate.getTime();

  // Structural validity — malformed amounts are denied, never coerced.
  // isSafeInteger guards against precision loss when summing windows.
  if (
    !Number.isSafeInteger(intent.amount.amountMinor) ||
    intent.amount.amountMinor <= 0
  ) {
    reasons.push({
      code: "INVALID_AMOUNT",
      message: `amountMinor must be a positive safe integer, got ${intent.amount.amountMinor}`,
    });
  }

  if (policy.expiresAt !== undefined) {
    const expMs = parseMs(policy.expiresAt);
    if (Number.isNaN(expMs)) {
      reasons.push({
        code: "POLICY_EXPIRY_UNPARSEABLE",
        message: `policy.expiresAt "${policy.expiresAt}" is not a parseable timestamp`,
      });
    } else if (nowMs >= expMs) {
      reasons.push({
        code: "POLICY_EXPIRED",
        message: `policy ${policy.id} expired at ${policy.expiresAt}`,
      });
    }
  }

  if (intent.amount.currency.toUpperCase() !== policy.currency.toUpperCase()) {
    reasons.push({
      code: "CURRENCY_MISMATCH",
      message: `policy currency is ${policy.currency}, intent is ${intent.amount.currency}`,
    });
  }

  if (
    policy.rails?.allow &&
    !policy.rails.allow.map(lc).includes(lc(intent.rail))
  ) {
    reasons.push({
      code: "RAIL_NOT_ALLOWED",
      message: `rail "${intent.rail}" is not in the allowed rails list`,
    });
  }

  // Merchant rules: block always wins; then allowlist (if present) must match.
  if (policy.merchants?.block?.some((m) => merchantMatches(intent, m))) {
    reasons.push({
      code: "MERCHANT_BLOCKED",
      message: `merchant "${intent.merchant.id}" (${intent.merchant.url ?? "no url"}) is blocklisted`,
    });
  }
  if (
    policy.merchants?.allow &&
    !policy.merchants.allow.some((m) => merchantMatches(intent, m))
  ) {
    reasons.push({
      code: "MERCHANT_NOT_ALLOWED",
      message: `merchant "${intent.merchant.id}" (${intent.merchant.url ?? "no url"}) is not on the allowlist`,
    });
  }

  const category = intent.category ? lc(intent.category) : undefined;
  if (category && policy.categories?.block?.map(lc).includes(category)) {
    reasons.push({
      code: "CATEGORY_BLOCKED",
      message: `category "${intent.category}" is blocklisted`,
    });
  }
  if (policy.categories?.allow) {
    const allowed = policy.categories.allow.map(lc);
    if (!category || !allowed.includes(category)) {
      reasons.push({
        code: "CATEGORY_NOT_ALLOWED",
        message: `category "${intent.category ?? "(none)"}" is not on the allowlist`,
      });
    }
  }

  const amountValid =
    Number.isSafeInteger(intent.amount.amountMinor) &&
    intent.amount.amountMinor > 0;

  const limits = policy.limits ?? {};
  if (
    amountValid &&
    limits.perTransactionMinor !== undefined &&
    intent.amount.amountMinor > limits.perTransactionMinor
  ) {
    reasons.push({
      code: "PER_TXN_LIMIT_EXCEEDED",
      message: `${intent.amount.amountMinor} exceeds per-transaction limit ${limits.perTransactionMinor}`,
    });
  }

  // Rolling windows over executed spend. Only evaluated for a valid amount.
  //
  // NOTE: this is the ADVISORY check — it reads totals and is therefore
  // check-then-act by construction. It exists to fail fast and to give a
  // useful reason before a human approval is requested. The AUTHORITATIVE
  // check is the guard's atomic `SpendLimiter.reserve()` immediately before
  // execution. Both derive their windows from `policyWindows()` so the two can
  // never disagree about what the caps are.
  for (const w of policyWindows(policy)) {
    if (w.capMinor !== undefined && !amountValid) continue;
    const since = new Date(nowMs - w.windowMs).toISOString();
    const { totalMinor, count } = await history.totalsSince(
      intent.agentId,
      since,
      policy.currency,
    );
    if (w.capMinor !== undefined) {
      // Fail closed if the history total isn't a usable safe integer, so a
      // corrupt/NaN total can never satisfy `total + amount > limit` as false.
      if (
        !Number.isSafeInteger(totalMinor) ||
        totalMinor + intent.amount.amountMinor > w.capMinor
      ) {
        reasons.push({
          code: w.code,
          message: `spent ${totalMinor} in window; +${intent.amount.amountMinor} would exceed limit ${w.capMinor}`,
        });
      }
    }
    if (w.maxCount !== undefined && count + 1 > w.maxCount) {
      reasons.push({
        code: w.code,
        message: `${count} transactions in window; limit is ${w.maxCount}`,
      });
    }
  }

  if (reasons.length > 0) {
    return {
      decision: "deny",
      reasons,
      policyId: policy.id,
      policyVersion: policy.version,
    };
  }

  const approval = policy.approval ?? {};
  if (
    approval.always === true ||
    (approval.aboveMinor !== undefined &&
      intent.amount.amountMinor >= approval.aboveMinor)
  ) {
    return {
      decision: "require_approval",
      reasons: [
        {
          code: approval.always ? "APPROVAL_ALWAYS" : "APPROVAL_THRESHOLD",
          message: approval.always
            ? "policy requires approval for every transaction"
            : `amount ${intent.amount.amountMinor} >= approval threshold ${approval.aboveMinor}`,
        },
      ],
      policyId: policy.id,
      policyVersion: policy.version,
    };
  }

  return {
    decision: "allow",
    reasons: [],
    policyId: policy.id,
    policyVersion: policy.version,
  };
}

function lc(s: string): string {
  return s.toLowerCase();
}

/**
 * Merchant pattern matching. The destination the executor actually pays is the
 * URL host, so host patterns are matched ONLY against `merchant.url`, never
 * against the free-text `merchant.id` (which is attacker-controlled).
 *
 * Pattern forms:
 *   "amazon.com"        host pattern (contains a dot) — matches the URL host
 *                       exactly or at a dot boundary (sub.amazon.com), never
 *                       a lookalike like evil-amazon.com. Requires a URL.
 *   "host:example"      explicit host pattern (matches even without a dot).
 *   "id:openai"         explicit id pattern — matches merchant.id exactly.
 *                       WEAK: merchant.id is not verified; use only for
 *                       trusted, integrator-controlled ids.
 *   "openai"            bare token without a dot — treated as an id pattern
 *                       (same weakness as "id:").
 *
 * Fails closed: a host pattern with no usable URL does not match.
 */
export function merchantMatches(
  intent: PaymentIntent,
  pattern: string,
): boolean {
  const raw = pattern.trim();
  const lower = raw.toLowerCase();
  // merchant.id is attacker-controlled; normalize it the same way as the
  // pattern so surrounding whitespace can't evade an allow/block match.
  const merchantId = lc(intent.merchant.id.trim());

  if (lower.startsWith("id:")) {
    return merchantId === lower.slice(3).trim();
  }

  let hostPattern = raw;
  let forceHost = false;
  if (lower.startsWith("host:")) {
    hostPattern = raw.slice(5).trim();
    forceHost = true;
  }

  const isHostPattern = forceHost || hostPattern.includes(".");
  if (!isHostPattern) {
    // Bare token, no dot: id match (documented weak path).
    return merchantId === lc(hostPattern);
  }

  if (!intent.merchant.url) return false;
  let host: string;
  try {
    host = normalizeHost(new URL(intent.merchant.url).hostname);
  } catch {
    return false;
  }
  const p = normalizeHost(hostPattern);
  if (p.length === 0) return false;
  return host === p || host.endsWith("." + p);
}

/** Lowercase and strip a single trailing dot (FQDN form). */
function normalizeHost(host: string): string {
  return host.toLowerCase().replace(/\.$/, "");
}
