import { parseMs } from "../util/time.js";
import { merchantKeyOf, windowConfigError } from "../enforce/spend-limiter.js";
import type {
  CountLimit,
  PaymentIntent,
  PolicyReason,
  PolicyResult,
  SpendHistory,
  SpendPolicy,
  SpendWindow,
} from "../types.js";

const DAY_MS = 24 * 60 * 60 * 1000;

/** One limit or several — every listed limit is a window of its own. */
function countLimits(v: CountLimit | CountLimit[] | undefined | null): CountLimit[] {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

/**
 * Non-numbers become NaN, NEVER coerced (a string "5" from a JSON config is
 * config corruption, not five) — the NaN then fails windowConfigError and the
 * whole policy refuses, which is the fail-closed path for poisoned config.
 */
function numOrNaN(x: unknown): number {
  return typeof x === "number" ? x : Number.NaN;
}

function countWindow(limit: CountLimit, code: string): SpendWindow {
  const l = limit as { count?: unknown; perSeconds?: unknown } | null;
  return {
    code,
    windowMs: numOrNaN(l?.perSeconds) * 1000,
    maxCount: numOrNaN(l?.count),
  };
}

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
  const velocity = policy.velocity ?? {};
  for (const limit of countLimits(velocity.maxTransactions)) {
    windows.push(countWindow(limit, "VELOCITY_EXCEEDED"));
  }
  for (const limit of countLimits(velocity.maxTransactionsPerMerchant)) {
    windows.push({
      ...countWindow(limit, "MERCHANT_VELOCITY_EXCEEDED"),
      dimension: "merchant",
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

  // Settlement network. Evaluated only when the policy declares a constraint;
  // see SpendPolicy.networks for why the default is additive and what changes
  // the moment an operator opts in.
  const networkPolicy = policy.networks;
  if (networkPolicy && (networkPolicy.allow !== undefined || networkPolicy.block !== undefined)) {
    const configured = [...(networkPolicy.allow ?? []), ...(networkPolicy.block ?? [])];
    const unusable = configured.filter((n) => normNetwork(n) === null);
    if (unusable.length > 0) {
      // ANY entry that cannot be canonicalized (blank, non-string, malformed
      // CAIP-2 like a hex chain id) poisons the whole constraint. A block
      // entry that silently never matches is a blocklist with a hole the
      // operator cannot see; refuse loudly instead — the same stance
      // windowConfigError takes on poisoned limits.
      reasons.push({
        code: "NETWORK_POLICY_INVALID",
        message:
          `policy.networks contains ${unusable.length} entr${unusable.length === 1 ? "y" : "ies"} ` +
          `that cannot canonically identify a network ` +
          `(${unusable.map((n) => JSON.stringify(n ?? null)).join(", ")}); refusing everything ` +
          `under this policy rather than enforcing a constraint with holes`,
      });
    } else {
      const network = normNetwork(intent.network);
      const rawNetwork =
        typeof intent.network === "string" ? intent.network.trim() : "";
      if (network === null && rawNetwork.length > 0) {
        // The intent NAMED a network, but in a form that does not canonically
        // identify one (malformed CAIP-2: hex chain id, internal whitespace,
        // empty reference, extra colon). The id comes from an untrusted
        // counterparty, and an unparseable spelling used to sail past a
        // blocklist as "did not match, therefore not blocked" — refuse it
        // instead, never pass it through.
        reasons.push({
          code: "NETWORK_UNPARSEABLE",
          message:
            `policy ${policy.id} constrains the settlement network but the intent's ` +
            `network id ${JSON.stringify(intent.network)} does not parse as a canonical ` +
            `chain id (CAIP-2) or a bare network name; refusing rather than passing an ` +
            `id no list entry can match`,
        });
      } else if (network === null) {
        // Missing is a denial, never a skip — MERCHANT_KEY_MISSING's rule. An
        // intent that declines to say which chain it settles on, under a
        // policy that cares, is exactly the case this rule exists for.
        reasons.push({
          code: "NETWORK_MISSING",
          message:
            `policy ${policy.id} constrains the settlement network but the intent ` +
            `states none (got ${JSON.stringify(intent.network ?? null)})`,
        });
      } else {
        if (networkPolicy.block?.some((n) => normNetwork(n) === network)) {
          reasons.push({
            code: "NETWORK_BLOCKED",
            message: `network "${intent.network}" is blocklisted`,
          });
        }
        if (
          networkPolicy.allow &&
          !networkPolicy.allow.some((n) => normNetwork(n) === network)
        ) {
          reasons.push({
            code: "NETWORK_NOT_ALLOWED",
            message: `network "${intent.network}" is not on the allowlist`,
          });
        }
      }
    }
  }

  // Merchant rules: block always wins; then allowlist (if present) must match.
  //
  // A host-form BLOCK pattern is unevaluable without a parseable
  // `merchant.url`, and unevaluable must not read as "not blocked" — that let
  // an agent drop one optional field and walk past the entire blocklist.
  if (
    policy.merchants?.block?.some((m) => isHostForm(m)) &&
    parsedHost(intent.merchant.url) === null
  ) {
    reasons.push({
      code: "MERCHANT_URL_UNVERIFIABLE",
      message:
        `merchants.block contains a host pattern but the intent carries no parseable ` +
        `merchant.url (${JSON.stringify(intent.merchant.url ?? null)}); a blocklist that ` +
        `cannot be evaluated denies rather than passes`,
    });
  }
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
  const windows = policyWindows(policy);
  // Config validity comes BEFORE any window arithmetic, here exactly as in
  // the limiter: a malformed window makes its comparisons silently false, so
  // it must refuse the whole policy instead of enforcing nothing.
  const misconfigured = windows
    .map((w) => ({ w, problem: windowConfigError(w) }))
    .find((x): x is { w: SpendWindow; problem: string } => x.problem !== null);
  if (misconfigured) {
    reasons.push({
      code: "SPEND_WINDOW_INVALID",
      message: `window "${misconfigured.w.code}" is misconfigured (${misconfigured.problem}); refusing everything under this policy rather than enforcing nothing`,
    });
  }
  for (const w of misconfigured ? [] : windows) {
    if (w.capMinor !== undefined && !amountValid) continue;
    const since = new Date(nowMs - w.windowMs).toISOString();
    if (w.dimension === "merchant") {
      // Advisory-only skip when the history cannot attribute spend to a
      // merchant: the atomic limiter still enforces this window at reserve
      // time, with MERCHANT_KEY_MISSING as the deny for an unkeyed request.
      if (!history.merchantCountSince) continue;
      const { count } = await history.merchantCountSince(
        intent.agentId,
        merchantKeyOf(intent.merchant),
        since,
        policy.currency,
      );
      if (w.maxCount !== undefined && count + 1 > w.maxCount) {
        reasons.push({
          code: w.code,
          message: `${count} transactions for this merchant in window; limit is ${w.maxCount}`,
        });
      }
      continue;
    }
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
 * Merchant pattern matching.
 *
 * NEITHER FORM VERIFIES THE PAYEE. This function compares a policy pattern
 * against fields of the intent, and every field of the intent is set by the
 * caller — `merchant.url` exactly as much as `merchant.id`. The guard never
 * contacts the URL, never resolves it, and has no independent knowledge of who
 * receives the money. Anything stronger would require the library to observe
 * the settlement itself, which it deliberately cannot do: it holds no funds and
 * never sits on the wire.
 *
 * WHAT HOST PATTERNS ACTUALLY BUY, then, is MATCHING PRECISION, not trust:
 * the value is parsed as a URL and compared on the hostname at a dot boundary,
 * so `evil-amazon.com` and `amazon.com.evil.net` cannot pass as `amazon.com`,
 * and case / trailing-dot FQDN variants normalize out. An `id:` pattern is an
 * exact string compare over free text, which offers none of that. Use host
 * patterns where a URL exists — but understand what they police.
 *
 * WHAT MAKES A HOST PATTERN MEANINGFUL is therefore entirely on the caller:
 * `merchant.url` must be derived PER INTENT from the destination this payment
 * is actually about to reach. A `merchant.url` fixed once at construction
 * makes every host pattern in the policy match for every recipient — the
 * pattern is then policing a constant. That is not hypothetical: in a
 * signer-level integration the guard sees `merchant.id` = the payee address
 * extracted from the bytes about to be signed (the strongest fact available
 * anywhere in the intent) and `merchant.url` = the request URL fixed at wrap
 * time, so a policy of `merchants.allow: ["host:x402.org"]` authorizes a
 * transfer to an arbitrary address. In that deployment the `id:` form is the
 * stronger control, and the ranking implied by an earlier version of this
 * comment was backwards.
 *
 * A HOST PATTERN IN `allow` CAN ONLY WIDEN, NEVER NARROW. `merchants.allow`
 * is DISJUNCTIVE: an intent passes if ANY entry matches. So adding a host
 * entry beside an `id:` entry does not mean "this host AND this recipient" —
 * it means "this recipient OR anyone that host names". There is no way to
 * express the conjunction here. On a rail where the URL does not determine
 * the recipient (x402: `payTo` is an arbitrary address the server names, and
 * it, not the URL, is what the EIP-712 authorization commits to), that makes
 * a host entry in `allow` a recipient bypass wearing the shape of a control.
 * @vaduno/x402 therefore REFUSES host-form `allow` entries by default
 * (RECIPIENT_UNGATED) — a rail that knows its own commitment structure can
 * enforce what this rail-agnostic function cannot. Host patterns in
 * `merchants.block` are unaffected: on the block side a match always denies,
 * so disjunction only tightens.
 *
 * Pattern forms:
 *   "amazon.com"        host pattern (contains a dot) — matches the URL host
 *                       exactly or at a dot boundary (sub.amazon.com), never
 *                       a lookalike like evil-amazon.com. Requires a URL.
 *   "host:example"      explicit host pattern (matches even without a dot).
 *   "id:openai"         explicit id pattern — exact match on merchant.id.
 *   "openai"            bare token without a dot — treated as an id pattern.
 *
 * Fails closed: a host pattern with no usable URL does not match — which on
 * the ALLOW side means denied. On the BLOCK side "does not match" would mean
 * "not blocked", so `evaluatePolicy` refuses that case outright
 * (MERCHANT_URL_UNVERIFIABLE) instead of relying on this function's answer.
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

  const host = parsedHost(intent.merchant.url);
  if (host === null) return false;
  const p = normalizeHost(hostPattern);
  if (p.length === 0) return false;
  return host === p || host.endsWith("." + p);
}

/**
 * True if `pattern` is a HOST-form pattern — the forms that need a URL to be
 * evaluable at all. Shares the classification with merchantMatches so the
 * blocklist's "can this even be checked?" question and the match itself can
 * never disagree about which family a pattern belongs to.
 */
function isHostForm(pattern: string): boolean {
  const raw = pattern.trim();
  const lower = raw.toLowerCase();
  if (lower.startsWith("id:")) return false;
  if (lower.startsWith("host:")) return true;
  return raw.includes(".");
}

/** The normalized hostname of `url`, or null when there isn't a usable one. */
function parsedHost(url: string | undefined): string | null {
  if (!url) return null;
  try {
    const host = normalizeHost(new URL(url).hostname);
    return host.length > 0 ? host : null;
  } catch {
    return null;
  }
}

/** Lowercase and strip a single trailing dot (FQDN form). */
function normalizeHost(host: string): string {
  return host.toLowerCase().replace(/\.$/, "");
}

/** CAIP-2 grammar, matched after case-folding: namespace ":" reference. */
const CAIP2_RE = /^([a-z0-9-]{3,8}):([a-z0-9_-]{1,32})$/;

/**
 * Curated x402-v1-name -> CAIP-2 aliases: BOTH wire spellings of one chain
 * must canonicalize to ONE comparison key.
 *
 * THE HOLE THIS CLOSES. x402 v1 names the settlement network with a bare
 * name ("base-sepolia"); x402 v2 names the SAME chain with a CAIP-2 id
 * ("eip155:84532"). Treating the two families as disjoint key spaces meant
 * `block: ["eip155:84532"]` did not block an intent whose network was
 * "base-sepolia" — measured end to end: with an allow list carrying both
 * spellings (the natural configuration, since one adapter speaks both
 * protocol versions) and a block naming only one, a hostile 402 server
 * answering in the OTHER spelling was PAID. The rationale that drove the
 * structural CAIP-2 parse applies verbatim: a blocklist a counterparty can
 * spell around is not a control.
 *
 * CURATED, NOT INFERRED — and EVM-only. Each entry is a chain identity fact
 * (the x402 registry's v1 name and its numeric eip155 chain id); a wrong
 * entry would forge an equivalence between two DIFFERENT chains, which is
 * worse than the spell-around it prevents. Non-EVM v1 names ("solana",
 * "solana-devnet") are deliberately NOT aliased here: their CAIP-2
 * references are genesis-hash prefixes this table will not vouch for. A
 * policy constraining a non-EVM chain must name BOTH spellings itself —
 * stated in SpendPolicy.networks' docs, not silently absorbed.
 *
 * Null prototype: keys are compared against attacker-influenced network
 * strings, and "constructor" must not alias to a function.
 */
const V1_NETWORK_ALIASES: Record<string, string> = Object.assign(
  Object.create(null) as Record<string, string>,
  {
    "base": "eip155:8453",
    "base-sepolia": "eip155:84532",
    "avalanche": "eip155:43114",
    "avalanche-fuji": "eip155:43113",
    "polygon": "eip155:137",
    "polygon-amoy": "eip155:80002",
    "iotex": "eip155:4689",
    "sei": "eip155:1329",
    "sei-testnet": "eip155:1328",
  },
);

/**
 * A network identifier reduced to its CANONICAL comparison form, or null when
 * the value cannot canonically identify a network (absent, not a string,
 * blank, or a colon-bearing id that does not parse as CAIP-2).
 *
 * Two families, told apart by the presence of ":":
 *
 *  - BARE rail-native names ("base-sepolia", "stripe-live", "upi"): trimmed
 *    and lowercased — and, when the name is a curated x402 v1 chain name,
 *    canonicalized to its CAIP-2 id (V1_NETWORK_ALIASES) so the v1 and v2
 *    wire spellings of one chain cannot be played against each other.
 *
 *  - CAIP-2 chain ids ("eip155:84532"): parsed STRUCTURALLY. The id arrives
 *    in a 402 from an UNTRUSTED counterparty, and a comparison that is merely
 *    textual lets that counterparty spell the same chain a way the blocklist
 *    does not — "eip155:084532" for "eip155:84532" — and a block entry a
 *    seller can spell around is not a control. So: exactly one colon,
 *    namespace and reference must match the CAIP-2 shape, and an eip155
 *    reference (a decimal chain id) is canonicalized numerically so leading
 *    zeros cannot alias it. A colon-bearing id that does not parse (hex chain
 *    id, internal whitespace, empty reference, extra colon) returns null and
 *    is REFUSED by the engine, never passed through.
 *
 * Still no wildcard expansion and no namespace prefixes: a policy that says
 * `eip155:84532` means that chain and no other, because the hole this rule
 * closes was caused by an implicit "any chain will do".
 */
function normNetwork(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const v = value.trim().toLowerCase();
  if (v.length === 0) return null;
  // Bare rail-native name. A curated x402 v1 chain name canonicalizes to its
  // CAIP-2 id so the two wire spellings of one chain are one comparison key
  // (see V1_NETWORK_ALIASES); anything else keeps trim+lowercase semantics.
  if (!v.includes(":")) return V1_NETWORK_ALIASES[v] ?? v;
  const m = CAIP2_RE.exec(v);
  if (m === null) return null;
  const namespace = m[1]!;
  const reference = m[2]!;
  if (namespace === "eip155") {
    // eip155 references are decimal chain ids; compare numerically so
    // "084532" cannot pose as a chain distinct from "84532".
    if (!/^[0-9]+$/.test(reference)) return null;
    return `eip155:${BigInt(reference).toString(10)}`;
  }
  return `${namespace}:${reference}`;
}
