import type { SwaleGuard } from "@swale/guard";
import { randomUUID } from "node:crypto";
import {
  X_PAYMENT_HEADER,
  X_PAYMENT_RESPONSE_HEADER,
  X402ProtocolError,
  decodeSettlementResponse,
  parsePaymentRequired,
} from "./parse.js";
import { requirementToIntent } from "./intent.js";
import {
  X402PaymentBlockedError,
  X402PaymentFailedError,
  X402RequirementRefusedError,
} from "./errors.js";
import type { PaymentRequirements, SettlementResponse } from "./types.js";

export type FetchLike = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

/** Hard cap on the untrusted 402 body we will read (DoS guard). */
const MAX_402_BYTES = 64 * 1024;

/** A trusted (network, asset) -> token identity. Binds spend to a real token. */
export interface AssetInfo {
  network: string;
  /** Token contract address (compared case-insensitively). */
  asset: string;
  symbol: string;
  decimals: number;
}

export interface X402FetchOptions {
  guard: SwaleGuard;
  agentId: string;
  /**
   * Produce the `X-PAYMENT` header value for the selected requirement. THIS is
   * where your wallet/signer lives — Swale never sees keys. It MUST sign for
   * exactly the requirement it is given (amount, payTo, asset); Swale polices
   * the requirement, not the bytes you sign.
   */
  pay: (req: PaymentRequirements) => Promise<string>;
  /** Underlying fetch (injectable for tests). Defaults to global fetch. */
  fetch?: FetchLike;
  /**
   * Choose which of the server's `accepts` to pay. Default: the first whose
   * scheme is "exact", else the first. Return undefined to refuse all (raises
   * X402RequirementRefusedError; the payer never runs).
   */
  select?: (accepts: PaymentRequirements[]) => PaymentRequirements | undefined;
  /**
   * Trusted token registry. When provided, a requirement whose (network, asset)
   * pair is NOT listed is refused (fail closed), and the intent's currency is
   * taken from the registry's `symbol` — so a hostile server cannot spoof
   * `extra.symbol` to satisfy your policy.currency. STRONGLY recommended.
   */
  assets?: AssetInfo[];
  /**
   * Require the server's `resource` origin to equal the request origin.
   * Default true (fail closed on mismatch) — catches a server claiming a
   * different host than the one actually contacted.
   */
  requireResourceOriginMatch?: boolean;
  /** Category tag applied to produced intents (for policy/audit). */
  category?: string;
  /** Optional mapping from a requirement to a mandate id to bind. */
  mandateIdFor?: (req: PaymentRequirements) => string | undefined;
  /** Notified after execution. `auditDegraded` true = charge's audit write failed. */
  onSettled?: (
    settlement: SettlementResponse | null,
    intentId: string,
    auditDegraded: boolean,
  ) => void;
  now?: () => Date;
}

function defaultSelect(
  accepts: PaymentRequirements[],
): PaymentRequirements | undefined {
  return accepts.find((r) => r.scheme.toLowerCase() === "exact") ?? accepts[0];
}

function originOf(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
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
    // leaking the X-PAYMENT bearer) to a different origin, defeating the
    // resource-origin check and the host allowlist. A redirect is surfaced as
    // a non-402 response and never paid.
    redirect: "manual",
    ...(body !== undefined ? { body } : {}),
  };
  return { url, init: finalInit };
}

/**
 * A fetch-compatible function that transparently handles x402 payments under
 * Swale's policy + audit. On a 402 it binds the REAL request URL and (with an
 * asset registry) the REAL token into a PaymentIntent, runs the guard, and only
 * if allowed invokes your `pay` signer and retries.
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

    // Bound the untrusted 402 body: reject an over-large Content-Length, and
    // cap the bytes actually read so a hostile server can't exhaust the agent.
    const declared = Number(first.headers.get("content-length"));
    if (Number.isFinite(declared) && declared > MAX_402_BYTES) {
      throw new X402ProtocolError(`402 body too large (${declared} bytes)`);
    }
    const text = await first.clone().text().catch(() => "");
    if (text.length > MAX_402_BYTES) {
      throw new X402ProtocolError(`402 body too large (${text.length} bytes)`);
    }
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
      // pay() throwing here means nothing was transmitted -> guard records
      // "failed" and the spend is NOT counted. Correct: no money moved.
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

    if (result.status === "executed") {
      const paid = result.value;
      const degraded =
        result.status === "executed" && result.auditDegraded === true;
      opts.onSettled?.(settlement, intentId, degraded);
      if (!paid.ok) {
        throw new X402PaymentFailedError(
          `server returned ${paid.status} after X-PAYMENT was sent (spend counted; funds may have settled)`,
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
    // "failed": pay() threw before an authorization was transmitted.
    throw new X402PaymentFailedError(result.error ?? "payment could not be signed", false);
  };
}
