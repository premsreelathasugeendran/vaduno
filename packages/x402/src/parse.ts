import type {
  PaymentRequiredBody,
  PaymentRequirements,
  SettlementResponse,
} from "./types.js";

/** The header a client sets to carry its signed payment payload. */
export const X_PAYMENT_HEADER = "X-PAYMENT";
/** The header a server returns describing settlement. */
export const X_PAYMENT_RESPONSE_HEADER = "X-PAYMENT-RESPONSE";

/**
 * Validate and normalize a 402 response body into typed payment requirements.
 * Throws X402ProtocolError on a malformed body so the caller fails closed
 * rather than paying against garbage.
 */
export function parsePaymentRequired(body: unknown): PaymentRequiredBody {
  if (!body || typeof body !== "object") {
    throw new X402ProtocolError("402 body is not an object");
  }
  const b = body as Record<string, unknown>;
  if (!Array.isArray(b.accepts)) {
    throw new X402ProtocolError("402 body has no `accepts` array");
  }

  // Detect an unsupported protocol version BEFORE field validation, so a v2
  // body produces a named, actionable error instead of
  // "accepts[0].maxAmountRequired must be a non-empty string" — which reads
  // like a malformed server rather than an adapter that does not speak v2.
  //
  // This is deliberately a REFUSAL, not a partial parse. v2 renamed
  // `maxAmountRequired` to `amount` and moved to CAIP-2 network ids, and
  // `validateRequirement` below builds its result from a fixed allowlist that
  // copies no unknown keys. Accepting `amount` there without also threading it
  // through to the requirement handed to `pay()` would let policy approve one
  // amount while the signer signs another — strictly worse than refusing.
  const detected = detectUnsupportedVersion(b);
  if (detected) throw new X402VersionUnsupportedError(detected.version, detected.detail);
  // Cap the array so a hostile server can't force unbounded mapping work.
  if (b.accepts.length > 32) {
    throw new X402ProtocolError(`402 body has too many accepts entries (${b.accepts.length} > 32)`);
  }
  const accepts = b.accepts.map((r, i) => validateRequirement(r, i));
  if (accepts.length === 0) {
    throw new X402ProtocolError("402 body `accepts` is empty");
  }
  return {
    x402Version: typeof b.x402Version === "number" ? b.x402Version : 1,
    accepts,
    ...(typeof b.error === "string" ? { error: b.error } : {}),
  };
}

function validateRequirement(r: unknown, index: number): PaymentRequirements {
  if (!r || typeof r !== "object") {
    throw new X402ProtocolError(`accepts[${index}] is not an object`);
  }
  const o = r as Record<string, unknown>;
  const str = (k: string): string => {
    const v = o[k];
    if (typeof v !== "string" || v.length === 0) {
      throw new X402ProtocolError(`accepts[${index}].${k} must be a non-empty string`);
    }
    return v;
  };
  const req: PaymentRequirements = {
    scheme: str("scheme"),
    network: str("network"),
    maxAmountRequired: str("maxAmountRequired"),
    resource: str("resource"),
    payTo: str("payTo"),
    asset: str("asset"),
  };
  if (typeof o.description === "string") req.description = o.description;
  if (typeof o.mimeType === "string") req.mimeType = o.mimeType;
  if (typeof o.maxTimeoutSeconds === "number") {
    req.maxTimeoutSeconds = o.maxTimeoutSeconds;
  }
  if (o.extra && typeof o.extra === "object") {
    req.extra = o.extra as NonNullable<PaymentRequirements["extra"]>;
  }
  return req;
}

/** base64 the JSON payment payload for the X-PAYMENT header. */
export function encodePaymentHeader(payload: unknown): string {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
}

/** Decode an X-PAYMENT-RESPONSE header value; returns null if absent/garbage. */
export function decodeSettlementResponse(
  headerValue: string | null | undefined,
): SettlementResponse | null {
  if (!headerValue) return null;
  try {
    const json = Buffer.from(headerValue, "base64").toString("utf8");
    const parsed = JSON.parse(json);
    if (parsed && typeof parsed === "object") return parsed as SettlementResponse;
    return null;
  } catch {
    return null;
  }
}

export class X402ProtocolError extends Error {
  constructor(message: string) {
    super(`x402 protocol: ${message}`);
    this.name = "X402ProtocolError";
  }
}

/**
 * The server speaks a version of x402 this adapter does not implement.
 *
 * Separate from `X402ProtocolError` because the two demand different responses:
 * a protocol error means the server sent something malformed, while this means
 * the SERVER is fine and the ADAPTER is behind. Conflating them sends people
 * hunting a bug in someone else's implementation.
 */
export class X402VersionUnsupportedError extends Error {
  constructor(
    readonly detectedVersion: number,
    detail: string,
  ) {
    super(
      `x402 v${detectedVersion} is not supported by @vaduno/x402 (this adapter implements v1 only): ${detail}. ` +
        `No payment was attempted. Track https://github.com/premsreelathasugeendran/vaduno/issues for v2 support.`,
    );
    this.name = "X402VersionUnsupportedError";
  }
}

/**
 * Identify a 402 body this adapter cannot safely handle, or null.
 *
 * Two independent signals, because a server may declare its version, imply it
 * through field names, or both:
 *  - an explicit `x402Version` above 1;
 *  - a requirement carrying v2's `amount` where v1's `maxAmountRequired` is
 *    absent — the rename that makes the two wire-incompatible.
 *
 * Deliberately conservative: it only fires when the body cannot be v1. A body
 * that satisfies v1 is parsed as v1 even if it carries extra unknown keys,
 * since forward-compatible servers add fields all the time.
 */
function detectUnsupportedVersion(
  b: Record<string, unknown>,
): { version: number; detail: string } | null {
  const declared = typeof b.x402Version === "number" ? b.x402Version : null;
  if (declared !== null && declared > 1) {
    return { version: declared, detail: `body declares x402Version ${declared}` };
  }

  const accepts = Array.isArray(b.accepts) ? b.accepts : [];
  for (let i = 0; i < accepts.length; i += 1) {
    const r = accepts[i];
    if (!r || typeof r !== "object") continue;
    const o = r as Record<string, unknown>;
    if (o.maxAmountRequired === undefined && typeof o.amount === "string") {
      return {
        version: 2,
        detail: `accepts[${i}] carries \`amount\` and no \`maxAmountRequired\` (renamed in v2)`,
      };
    }
  }

  return null;
}
