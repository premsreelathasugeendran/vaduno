import type { GuardResult, VadunoGuard } from "@vaduno/guard";
import { randomUUID } from "node:crypto";
import {
  PAYMENT_REQUIRED_HEADER,
  PAYMENT_RESPONSE_HEADER,
  PAYMENT_SIGNATURE_HEADER,
  X_PAYMENT_HEADER,
  X_PAYMENT_RESPONSE_HEADER,
  X402ProtocolError,
  decodeSettlementResponse,
  parsePaymentRequired,
  parsePaymentRequiredHeader,
} from "./parse.js";
import { requirementToIntent, requirementToIntentV2 } from "./intent.js";
import {
  X402PaymentBlockedError,
  X402PaymentFailedError,
  X402RequirementRefusedError,
} from "./errors.js";
import type {
  PaymentRequirements,
  PaymentRequirementsV2,
  ResourceInfo,
  SettlementResponse,
  X402Extension,
} from "./types.js";

export type FetchLike = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

/** Hard cap on the untrusted 402 body we will read (DoS guard). */
const MAX_402_BYTES = 64 * 1024;

/**
 * A v2 payTo "role constant" shape (e.g. "merchant"): a short bare lowercase
 * word. No address on any specced chain matches it — EVM/Sui/Aptos addresses
 * are 0x-hex, Solana/Stellar/Algorand addresses are longer and mixed-case or
 * digit-bearing, Hedera ids contain dots and digits. Used to REFUSE
 * unresolvable recipients by default: a role constant cannot be allowlisted,
 * so money policed by `id:<payTo>` patterns would flow to whatever the
 * facilitator resolves it to.
 */
const PAYTO_ROLE_RE = /^[a-z]{1,16}$/;

/** A trusted (network, asset) -> token identity. Binds spend to a real token. */
export interface AssetInfo {
  /**
   * v1: the v1 network name ("base", "base-sepolia"). v2: the CAIP-2 chain id
   * ("eip155:8453"). These are DIFFERENT key spaces — an entry for "base" does
   * NOT trust "eip155:8453"; author v2 entries explicitly.
   */
  network: string;
  /**
   * Token contract address. v1 compares case-insensitively. v2 compares
   * case-insensitively only on eip155 (EVM hex) networks and EXACTLY
   * everywhere else — Solana mints etc. are case-sensitive base58, where
   * case-folding would let a distinct token alias a trusted entry.
   */
  asset: string;
  symbol: string;
  decimals: number;
}

/** What the v2 payer receives beside the requirement it must sign for. */
export interface X402V2PayContext {
  /** The validated body-level ResourceInfo (server's claim; audit/display). */
  resource: ResourceInfo;
  /**
   * Validated, size-capped extensions from the PAYMENT-REQUIRED payload. The
   * v2 spec obliges the CLIENT to echo each extension's `info` back in the
   * PaymentPayload; since YOUR payer builds that payload, the echo is your
   * responsibility — echo at least `info`, append if you wish, never delete
   * or overwrite. Vaduno bounds and validates this data so the reflection is
   * capped before it reaches you.
   */
  extensions?: Record<string, X402Extension>;
}

/**
 * v2 support is OPT-IN: without this option a v2 402 (PAYMENT-REQUIRED
 * header) is refused with V2_NOT_CONFIGURED and no payment is attempted. A
 * spend firewall must not silently start paying a protocol version the
 * deployment never configured a signer for.
 */
export interface X402V2Options {
  /**
   * Produce the `PAYMENT-SIGNATURE` header value (base64 PaymentPayload) for
   * the selected v2 requirement. THIS is where your wallet/signer lives —
   * Vaduno never sees keys. It MUST sign for exactly the requirement it is
   * given and MUST echo exactly that requirement as the payload's `accepted`
   * field: the facilitator parameter-matches the authorization against it,
   * and Vaduno's policy decision covered THIS object and no other.
   */
  pay: (req: PaymentRequirementsV2, ctx: X402V2PayContext) => Promise<string>;
  /**
   * Choose which of the server's v2 `accepts` to pay. Default: the first
   * whose scheme is "exact", else the first. Return undefined to refuse all.
   */
  select?: (accepts: PaymentRequirementsV2[]) => PaymentRequirementsV2 | undefined;
  /** Optional mapping from a v2 requirement to a mandate id to bind. */
  mandateIdFor?: (req: PaymentRequirementsV2) => string | undefined;
  /**
   * v2 allows `payTo` to be a role constant (e.g. "merchant") instead of an
   * address, resolved out of band by someone who is not you. Refused by
   * default (PAYTO_ROLE_REFUSED) because an unresolvable recipient cannot be
   * allowlisted. List a role here to accept it explicitly — and understand
   * that recipient policing is then delegated to the resolver.
   */
  allowPayToRoles?: string[];
}

export interface X402FetchOptions {
  guard: VadunoGuard;
  agentId: string;
  /**
   * Produce the `X-PAYMENT` header value for the selected v1 requirement.
   * THIS is where your wallet/signer lives — Vaduno never sees keys. It MUST
   * sign for exactly the requirement it is given (amount, payTo, asset);
   * Vaduno polices the requirement, not the bytes you sign.
   */
  pay: (req: PaymentRequirements) => Promise<string>;
  /** Underlying fetch (injectable for tests). Defaults to global fetch. */
  fetch?: FetchLike;
  /**
   * Choose which of the server's v1 `accepts` to pay. Default: the first
   * whose scheme is "exact", else the first. Return undefined to refuse all
   * (raises X402RequirementRefusedError; the payer never runs).
   */
  select?: (accepts: PaymentRequirements[]) => PaymentRequirements | undefined;
  /**
   * Trusted token registry. When provided, a requirement whose (network, asset)
   * pair is NOT listed is refused (fail closed), and the intent's currency is
   * taken from the registry's `symbol` — so a hostile server cannot spoof
   * `extra.symbol` to satisfy your policy.currency. STRONGLY recommended.
   * Applies to BOTH protocol versions; v1 names and v2 CAIP-2 ids are
   * separate keys (see AssetInfo.network).
   */
  assets?: AssetInfo[];
  /**
   * Require the server's claimed resource origin to equal the origin actually
   * contacted. Default true (fail closed on mismatch) — catches a server
   * claiming a different host than the one reached. v1 checks each
   * requirement's `resource`; v2 checks the body-level `resource.url`.
   */
  requireResourceOriginMatch?: boolean;
  /** Category tag applied to produced intents (for policy/audit). */
  category?: string;
  /** Optional mapping from a v1 requirement to a mandate id to bind. */
  mandateIdFor?: (req: PaymentRequirements) => string | undefined;
  /** Notified after execution. `auditDegraded` true = charge's audit write failed. */
  onSettled?: (
    settlement: SettlementResponse | null,
    intentId: string,
    auditDegraded: boolean,
  ) => void;
  now?: () => Date;
  /** Enable x402 v2 (header-carried) payments. Absent = v2 402s are refused. */
  v2?: X402V2Options;
}

function defaultSelect(
  accepts: PaymentRequirements[],
): PaymentRequirements | undefined {
  return accepts.find((r) => r.scheme.toLowerCase() === "exact") ?? accepts[0];
}

function defaultSelectV2(
  accepts: PaymentRequirementsV2[],
): PaymentRequirementsV2 | undefined {
  return accepts.find((r) => r.scheme.toLowerCase() === "exact") ?? accepts[0];
}

function originOf(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

/**
 * Read an untrusted response body, counting BYTES received and aborting the
 * transfer the moment `maxBytes` is exceeded. Two attacks this closes:
 *  - Content-Length is advisory and absent entirely on chunked/HTTP-2
 *    responses, so a cap tested only against the header (or against a fully
 *    buffered string) bounds nothing — a hostile 402 responder could stream
 *    hundreds of MiB into memory before the "64 KB" check ever ran.
 *  - Measuring the cap in UTF-16 code units (`text.length`) undercounts
 *    multi-byte characters ~3x; counting `Uint8Array.byteLength` measures
 *    what is actually held in memory.
 * `reader.cancel()` tears down the body stream, so at most the cap plus one
 * in-flight chunk is ever buffered.
 *
 * A non-cap read error resolves to "" (the old `.text().catch(() => "")`
 * behavior): JSON.parse then fails and parsePaymentRequired rejects the body —
 * fail closed either way, always via a documented X402* error.
 */
async function readBodyCapped(res: Response, maxBytes: number): Promise<string> {
  const stream = res.body;
  if (!stream) return "";
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      let result: ReadableStreamReadResult<Uint8Array>;
      try {
        result = await reader.read();
      } catch {
        return "";
      }
      if (result.done) break;
      total += result.value.byteLength;
      if (total > maxBytes) {
        await reader.cancel("x402: 402 body exceeded byte cap").catch(() => {});
        throw new X402ProtocolError(`402 body too large (> ${maxBytes} bytes)`);
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }
  const buf = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    buf.set(c, offset);
    offset += c.byteLength;
  }
  return new TextDecoder().decode(buf);
}

interface NormalizedRequest {
  url: string;
  init: RequestInit;
}

/**
 * Resolve `input`+`init` into a URL string and a re-usable init. When `input`
 * is a Request, its method/headers/body are folded in and the body is buffered
 * so the paid retry can re-send it. init values take precedence.
 */
async function normalizeRequest(
  input: string | URL | Request,
  init: RequestInit | undefined,
): Promise<NormalizedRequest> {
  const isRequest =
    typeof input !== "string" &&
    !(input instanceof URL) &&
    typeof (input as Request).url === "string";
  const req = isRequest ? (input as Request) : null;
  const url = typeof input === "string" ? input : req ? req.url : input.toString();

  const headers = new Headers(req ? req.headers : undefined);
  if (init?.headers) {
    new Headers(init.headers).forEach((v, k) => headers.set(k, v));
  }

  let body: BodyInit | undefined =
    init?.body !== undefined && init?.body !== null ? (init.body as BodyInit) : undefined;
  if (body === undefined && req && req.body) {
    // Buffer once so both the probe and the retry can read it.
    body = await req.clone().arrayBuffer();
  }

  const method = init?.method ?? req?.method ?? "GET";
  const finalInit: RequestInit = {
    ...(init ?? {}),
    method,
    headers,
    // NEVER follow redirects: a 3xx could send the probe (or the paid retry,
    // leaking the X-PAYMENT / PAYMENT-SIGNATURE bearer) to a different origin,
    // defeating the resource-origin check and the host allowlist. A redirect
    // is surfaced as a non-402 response and never paid.
    redirect: "manual",
    ...(body !== undefined ? { body } : {}),
  };
  return { url, init: finalInit };
}

/**
 * Shared tail of both protocol paths: turn the guard's verdict into a
 * Response or a documented X402* error. `sentHeaderName` names the bearer
 * header of the protocol version in flight, purely for error text.
 */
function finishGuardResult(
  result: GuardResult<Response>,
  settlement: SettlementResponse | null,
  intentId: string,
  opts: X402FetchOptions,
  sentHeaderName: string,
): Response {
  if (result.status === "executed") {
    const paid = result.value;
    const degraded = result.auditDegraded === true;
    opts.onSettled?.(settlement, intentId, degraded);
    if (!paid.ok) {
      throw new X402PaymentFailedError(
        `server returned ${paid.status} after ${sentHeaderName} was sent (spend counted; funds may have settled)`,
        true,
      );
    }
    return paid;
  }
  if (result.status === "denied" || result.status === "approval_rejected") {
    throw new X402PaymentBlockedError(result);
  }
  if (result.status === "replayed") {
    // This wrapper mints a fresh intent id per call, so a replay can only
    // mean an id collision with an earlier consume. Nothing was signed or
    // transmitted on THIS call — surface it, never re-pay.
    throw new X402PaymentFailedError(
      `intent id was already consumed under this mandate (original: ${result.original.status}); no new payment was made`,
      false,
    );
  }
  // "authorized" cannot occur here: that status only comes from the two-phase
  // `guard.authorize()`, and this wrapper drives the single-call
  // `guard.execute()`. Handled explicitly rather than left to a cast, so that
  // if this adapter ever moves to the two-phase path the omission is a
  // compile error instead of a silently unhandled outcome.
  if (result.status === "authorized") {
    throw new X402PaymentFailedError(
      "guard returned a two-phase authorization to a single-call path; nothing was signed",
      false,
    );
  }
  // "failed": pay() threw before an authorization was transmitted.
  throw new X402PaymentFailedError(result.error ?? "payment could not be signed", false);
}

/**
 * A fetch-compatible function that transparently handles x402 payments under
 * Vaduno's policy + audit. On a 402 it binds the REAL request URL and (with an
 * asset registry) the REAL token into a PaymentIntent, runs the guard, and only
 * if allowed invokes your `pay` signer and retries.
 *
 * PROTOCOL VERSION ROUTING (single-carrier, total): if the 402 carries a
 * PAYMENT-REQUIRED header, the response is v2 — the header is parsed and the
 * body is NEVER read, matching the reference SDK, so a hostile server cannot
 * present one price in a v1 body and another in the v2 header and have
 * different layers read different carriers. Without the header, the body is
 * parsed as v1 exactly as before. v2 requires the `v2` option; without it a
 * v2 402 is refused by name (no payment attempted).
 *
 * Returns the paid Response on success. Throws:
 *  - X402RequirementRefusedError  — refused before paying (no money moved)
 *  - X402PaymentBlockedError      — policy/mandate/freeze blocked it (no money moved)
 *  - X402PaymentFailedError       — payer ran; server did not return success.
 *    NOTE its `transmitted` flag: when true, an authorization was sent and the
 *    spend is counted because the server could still settle it.
 *
 * Non-402 responses pass straight through. A retried request re-sends the
 * original body, which therefore must be re-readable (string/Buffer/ArrayBuffer/
 * a Request — not a one-shot ReadableStream).
 */
export function createX402Fetch(opts: X402FetchOptions): FetchLike {
  const doFetch = opts.fetch ?? (globalThis.fetch as FetchLike);
  const select = opts.select ?? defaultSelect;
  const requireOriginMatch = opts.requireResourceOriginMatch ?? true;

  return async function x402Fetch(input, init) {
    const { url, init: baseInit } = await normalizeRequest(input, init);

    const first = await doFetch(url, baseInit);
    if (first.status !== 402) return first;

    // ── v2: the PAYMENT-REQUIRED header is the discriminating carrier. ──────
    // Its PRESENCE (even empty) routes here; an unparseable value is a
    // protocol error, never a fallback to reading the body — falling back
    // would let a server race two carriers and have the client pay from
    // whichever it failed to reject.
    const v2Header = first.headers.get(PAYMENT_REQUIRED_HEADER);
    if (v2Header !== null) {
      // The body is a server implementation concern in v2 and is NEVER read
      // (no bytes buffered, no parse). Cancel it so the connection is not
      // held open by an unread stream.
      await first.body?.cancel().catch(() => {});
      return payV2(url, baseInit, v2Header, doFetch, opts, requireOriginMatch);
    }

    // ── v1: body-carried PaymentRequired, exactly as before. ────────────────
    // Bound the untrusted 402 body. An honest over-large Content-Length is
    // rejected before reading anything, but the header is advisory (and absent
    // on chunked/HTTP-2 responses), so the real bound is readBodyCapped, which
    // counts the bytes actually received and aborts the transfer at the cap.
    // No clone(): the 402 response is never handed back to the caller (only
    // the paid retry's response is), and clone() would tee the body into a
    // second unread buffer — growing the very allocation the cap exists to
    // prevent.
    const declared = Number(first.headers.get("content-length"));
    if (Number.isFinite(declared) && declared > MAX_402_BYTES) {
      throw new X402ProtocolError(`402 body too large (${declared} bytes)`);
    }
    const text = await readBodyCapped(first, MAX_402_BYTES);
    let body: unknown = null;
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
    const parsed = parsePaymentRequired(body);
    const requirement = select(parsed.accepts);
    if (!requirement) {
      throw new X402RequirementRefusedError(
        "NO_REQUIREMENT_SELECTED",
        "no acceptable payment requirement was selected",
      );
    }

    // Defense in depth: the server's claimed resource origin must match where
    // we actually connected. Fail closed on a mismatch (or unparseable claim).
    if (requireOriginMatch) {
      const reqOrigin = originOf(requirement.resource);
      const actualOrigin = originOf(url);
      if (reqOrigin === null || actualOrigin === null || reqOrigin !== actualOrigin) {
        throw new X402RequirementRefusedError(
          "RESOURCE_ORIGIN_MISMATCH",
          `requirement.resource origin (${reqOrigin}) != request origin (${actualOrigin})`,
        );
      }
    }

    // Bind the real token via the trusted asset registry (if configured).
    let currencyOverride: string | undefined;
    if (opts.assets) {
      const match = opts.assets.find(
        (a) =>
          a.network.toLowerCase() === requirement.network.toLowerCase() &&
          a.asset.toLowerCase() === requirement.asset.toLowerCase(),
      );
      if (!match) {
        throw new X402RequirementRefusedError(
          "ASSET_NOT_ALLOWED",
          `token ${requirement.asset} on ${requirement.network} is not in the trusted asset registry`,
        );
      }
      currencyOverride = match.symbol;
    }

    const intentId = randomUUID();
    const intent = requirementToIntent(requirement, {
      agentId: opts.agentId,
      intentId,
      requestUrl: url,
      ...(currencyOverride !== undefined ? { currency: currencyOverride } : {}),
      ...(opts.category !== undefined ? { category: opts.category } : {}),
      ...(opts.mandateIdFor
        ? (() => {
            const mid = opts.mandateIdFor(requirement);
            return mid !== undefined ? { mandateId: mid } : {};
          })()
        : {}),
      ...(opts.now ? { now: opts.now } : {}),
    });

    let settlement: SettlementResponse | null = null;

    const result = await opts.guard.execute(intent, async () => {
      // pay() throwing here means nothing was transmitted. The guard records
      // "failed" — but the spend STAYS COUNTED: burn-on-failure holds for any
      // thrown executor, because a throw cannot distinguish "never sent" from
      // "sent, then the connection died". Measured, not assumed: 4000 of a
      // 5000 cap remains counted after a throw here, and the next 4000 is
      // denied. (This comment previously claimed the spend was NOT counted;
      // it was wrong, and a caller who believed it would have expected budget
      // back that never returns.) If you can PROVE the rail did not charge,
      // guard.releaseSpend(intentId) is the deliberate, explicit way to
      // reclaim it — this adapter never calls it on your behalf.
      const paymentHeader = await opts.pay(requirement);
      const headers = new Headers(baseInit.headers);
      headers.set(X_PAYMENT_HEADER, paymentHeader);
      const paid = await doFetch(url, { ...baseInit, headers });
      // Once the authorization is transmitted, the server can settle it, so we
      // ALWAYS return (count the spend) regardless of HTTP status. Pessimistic
      // accounting prevents a hostile server from evading caps by returning an
      // error after receiving X-PAYMENT.
      settlement = decodeSettlementResponse(
        paid.headers.get(X_PAYMENT_RESPONSE_HEADER),
      );
      return paid;
    });

    return finishGuardResult(result, settlement, intentId, opts, X_PAYMENT_HEADER);
  };
}

/**
 * The v2 payment path. Every security property of the v1 path holds here,
 * against the v2 carrier:
 *  - the requirement VALIDATED is the identical object handed to pay() and to
 *    the intent — one object, one reading, no per-carrier disagreement;
 *  - resource-origin match against the body-level resource.url;
 *  - the trusted asset registry gates (CAIP-2 network, asset) pairs;
 *  - pessimistic accounting: once PAYMENT-SIGNATURE is transmitted the spend
 *    is counted regardless of HTTP status (settlement failure in v2 is a 402
 *    + PAYMENT-RESPONSE{success:false} — still counted);
 *  - redirects are never followed (redirect:"manual" rides in baseInit).
 */
async function payV2(
  url: string,
  baseInit: RequestInit,
  v2HeaderValue: string,
  doFetch: FetchLike,
  opts: X402FetchOptions,
  requireOriginMatch: boolean,
): Promise<Response> {
  const v2 = opts.v2;
  if (!v2) {
    throw new X402RequirementRefusedError(
      "V2_NOT_CONFIGURED",
      "server speaks x402 v2 (PAYMENT-REQUIRED header present) but no v2 payer is " +
        "configured — pass the `v2` option to createX402Fetch to enable v2 payments",
    );
  }

  const parsed = parsePaymentRequiredHeader(v2HeaderValue);
  const requirement = (v2.select ?? defaultSelectV2)(parsed.accepts);
  if (!requirement) {
    throw new X402RequirementRefusedError(
      "NO_REQUIREMENT_SELECTED",
      "no acceptable payment requirement was selected",
    );
  }

  // v2 payTo may be a role constant instead of an address. Refuse by default:
  // an unresolvable recipient cannot be allowlisted, so every `id:<payTo>`
  // policy would silently stop constraining where the money goes.
  if (PAYTO_ROLE_RE.test(requirement.payTo) && !v2.allowPayToRoles?.includes(requirement.payTo)) {
    throw new X402RequirementRefusedError(
      "PAYTO_ROLE_REFUSED",
      `payTo ${JSON.stringify(requirement.payTo)} looks like a v2 role constant, not a ` +
        `recipient address; list it in v2.allowPayToRoles to accept it explicitly`,
    );
  }

  // Defense in depth: the server's claimed resource origin (body-level in v2)
  // must match where we actually connected. Fail closed on a mismatch.
  if (requireOriginMatch) {
    const claimedOrigin = originOf(parsed.resource.url);
    const actualOrigin = originOf(url);
    if (claimedOrigin === null || actualOrigin === null || claimedOrigin !== actualOrigin) {
      throw new X402RequirementRefusedError(
        "RESOURCE_ORIGIN_MISMATCH",
        `resource.url origin (${claimedOrigin}) != request origin (${actualOrigin})`,
      );
    }
  }

  // Bind the real token via the trusted asset registry (if configured).
  // CAIP-2 network ids are matched EXACTLY (case-sensitive): the namespace is
  // lowercase by grammar and references like Solana genesis hashes are
  // case-sensitive. The asset is case-folded only on eip155 (EVM hex)
  // networks, where checksum-casing varies; everywhere else case-folding
  // could alias two distinct tokens onto one registry entry.
  let currencyOverride: string | undefined;
  if (opts.assets) {
    const evm = requirement.network.startsWith("eip155:");
    const match = opts.assets.find(
      (a) =>
        a.network === requirement.network &&
        (evm
          ? a.asset.toLowerCase() === requirement.asset.toLowerCase()
          : a.asset === requirement.asset),
    );
    if (!match) {
      throw new X402RequirementRefusedError(
        "ASSET_NOT_ALLOWED",
        `token ${requirement.asset} on ${requirement.network} is not in the trusted asset registry`,
      );
    }
    currencyOverride = match.symbol;
  }

  const intentId = randomUUID();
  const intent = requirementToIntentV2(requirement, parsed.resource, {
    agentId: opts.agentId,
    intentId,
    requestUrl: url,
    ...(currencyOverride !== undefined ? { currency: currencyOverride } : {}),
    ...(opts.category !== undefined ? { category: opts.category } : {}),
    ...(v2.mandateIdFor
      ? (() => {
          const mid = v2.mandateIdFor(requirement);
          return mid !== undefined ? { mandateId: mid } : {};
        })()
      : {}),
    ...(opts.now ? { now: opts.now } : {}),
  });

  const ctx: X402V2PayContext = {
    resource: parsed.resource,
    ...(parsed.extensions !== undefined ? { extensions: parsed.extensions } : {}),
  };

  let settlement: SettlementResponse | null = null;

  const result = await opts.guard.execute(intent, async () => {
    // v2.pay() throwing here means nothing was transmitted -> guard records
    // "failed" and the spend is NOT counted. Correct: no money moved.
    const paymentHeader = await v2.pay(requirement, ctx);
    const headers = new Headers(baseInit.headers);
    headers.set(PAYMENT_SIGNATURE_HEADER, paymentHeader);
    const paid = await doFetch(url, { ...baseInit, headers });
    // Once the authorization is transmitted, the server can settle it, so we
    // ALWAYS return (count the spend) regardless of HTTP status. For `upto`
    // the counted amount is the authorized MAX — what the signature permits —
    // and the smaller settled amount an untrusted PAYMENT-RESPONSE may later
    // report is never reconciled downward.
    settlement = decodeSettlementResponse(paid.headers.get(PAYMENT_RESPONSE_HEADER));
    return paid;
  });

  return finishGuardResult(result, settlement, intentId, opts, PAYMENT_SIGNATURE_HEADER);
}
