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
