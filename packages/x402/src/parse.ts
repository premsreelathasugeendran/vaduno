import type {
  PaymentRequiredBody,
  PaymentRequiredV2,
  PaymentRequirements,
  PaymentRequirementsV2,
  ResourceInfo,
  SettlementResponse,
  X402Extension,
} from "./types.js";

/** v1: the header a client sets to carry its signed payment payload. */
export const X_PAYMENT_HEADER = "X-PAYMENT";
/** v1: the header a server returns describing settlement. */
export const X_PAYMENT_RESPONSE_HEADER = "X-PAYMENT-RESPONSE";

/** v2: server -> client, base64(JSON PaymentRequired) on the 402. */
export const PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED";
/** v2: client -> server, base64(JSON PaymentPayload) on the paid retry. */
export const PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE";
/** v2: server -> client, base64(JSON SettlementResponse). */
export const PAYMENT_RESPONSE_HEADER = "PAYMENT-RESPONSE";

/**
 * Hard cap on an untrusted PAYMENT-REQUIRED header value (base64 chars).
 * Matches the 64 KB body cap in spirit: a hostile server must not be able to
 * make the client buffer/parse unbounded data before any decision is made.
 */
export const MAX_PAYMENT_REQUIRED_HEADER_CHARS = 64 * 1024;

/**
 * The TOTAL classification of an `x402Version` value. Every possible input
 * lands in exactly one bucket — there is no default arm that silently coerces.
 *
 * This exists because the previous read,
 * `typeof v === "number" ? v : 1`, was a DOWNGRADE CHANNEL: the string "2"
 * silently became 1, and 0 / -7 / 1.5 passed through verbatim as if declared.
 * Once the version routes behavior, a non-total read lets a hostile server
 * declare one version in one place and ship another version's data —
 * validated under one reading, paid under another.
 */
type VersionClass =
  | { kind: "absent" }
  | { kind: "v1" }
  | { kind: "v2" }
  | { kind: "future"; version: number }
  | { kind: "invalid"; description: string };

function classifyX402Version(v: unknown): VersionClass {
  if (v === undefined) return { kind: "absent" };
  if (typeof v === "number" && Number.isInteger(v)) {
    if (v === 1) return { kind: "v1" };
    if (v === 2) return { kind: "v2" };
    if (v > 2) return { kind: "future", version: v };
    // 0, negative: no such protocol version has ever existed.
    return { kind: "invalid", description: `the integer ${v}` };
  }
  const description =
    typeof v === "number"
      ? `the non-integer number ${v}`
      : typeof v === "string"
        ? `the string ${JSON.stringify(v)}`
        : v === null
          ? "null"
          : Array.isArray(v)
            ? "an array"
            : `a ${typeof v}`;
  return { kind: "invalid", description };
}

/**
 * Validate and normalize a v1 402 JSON body into typed payment requirements.
 * Throws X402ProtocolError on a malformed body so the caller fails closed
 * rather than paying against garbage.
 *
 * VERSION HANDLING (total — every input has a defined outcome):
 *  - absent        -> parsed as v1. Deliberate back-compat: v1 servers in the
 *    wild omit the field, and this adapter has always accepted that. A body
 *    that omits the version but carries v2-shaped data is still refused by
 *    the shape detection below.
 *  - integer 1     -> parsed as v1.
 *  - integer 2     -> REFUSED (X402VersionUnsupportedError). v2 delivers
 *    PaymentRequired in the PAYMENT-REQUIRED response header; a v2
 *    declaration on the v1 body carrier is version confusion, and paying
 *    from it would mean validating one protocol's reading of another's data.
 *  - integer > 2   -> REFUSED (X402VersionUnsupportedError): adapter behind.
 *  - anything else -> REFUSED (X402ProtocolError): "2", 1.5, 0, -7, null,
 *    objects, arrays. A non-v1 declaration is NEVER coerced to 1 — that
 *    would be a downgrade channel.
 */
export function parsePaymentRequired(body: unknown): PaymentRequiredBody {
  if (!body || typeof body !== "object") {
    throw new X402ProtocolError("402 body is not an object");
  }
  const b = body as Record<string, unknown>;

  // Version first, so a declared-but-wrong version is named before any field
  // error can mislead ("maxAmountRequired must be a non-empty string" reads
  // like a malformed server, not a version mismatch).
  const version = classifyX402Version(b.x402Version);
  switch (version.kind) {
    case "invalid":
      throw new X402ProtocolError(
        `x402Version must be the integer 1 on the 402-body carrier; got ${version.description}. ` +
          `A non-v1 declaration is refused, never coerced to 1`,
      );
    case "v2":
      throw new X402VersionUnsupportedError(
        2,
        "the 402 JSON body declares x402Version 2, but v2 delivers PaymentRequired in the " +
          "PAYMENT-REQUIRED response header and this body carrier is v1-only — refusing the " +
          "mixed carrier rather than guessing which protocol the server means",
      );
    case "future":
      throw new X402VersionUnsupportedError(
        version.version,
        `body declares x402Version ${version.version}`,
      );
    case "absent":
    case "v1":
      break;
  }

  // Detect v2-SHAPED data that arrived without a v2 declaration, BEFORE field
  // validation (and before the accepts-array check, so a body that is v2 in
  // structure gets the version error rather than "no accepts array"). The
  // point is a named, actionable error instead of "accepts[0].maxAmountRequired
  // must be a non-empty string" — which reads like a malformed server rather
  // than an adapter/carrier mismatch.
  //
  // This is deliberately a REFUSAL, not a partial parse: v2 data on the v1
  // carrier is version confusion, and `validateRequirement` below builds its
  // result from a fixed allowlist that copies no unknown keys. Accepting
  // `amount` there without also threading it through to the requirement
  // handed to `pay()` would let policy approve one amount while the signer
  // signs another — strictly worse than refusing. A spec-conformant v2 server
  // sends the PAYMENT-REQUIRED header, which the fetch layer handles.
  const detected = detectV2Shape(b);
  if (detected) throw new X402VersionUnsupportedError(2, detected);

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
    // Total: the two arms that reach here are "absent" (documented back-compat
    // default) and "v1". Everything else threw above.
    x402Version: 1,
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
  // null is a common JSON idiom for "no extra"; treat it as absent.
  if (o.extra !== undefined && o.extra !== null) {
    req.extra = validateExtra(o.extra, index);
  }
  return req;
}

/**
 * Validate and defensively copy a requirement's `extra`. Strict for two
 * reasons:
 *  1. The keys THIS package reads (symbol/name/version/decimals) must carry
 *     the right types here, or a hostile value escapes later as a bare
 *     TypeError from intent mapping — outside the documented X402* error set
 *     a caller is told to catch. Malformed input is an X402ProtocolError, at
 *     the parse boundary.
 *  2. `extra` used to flow BY REFERENCE from the untrusted body into the
 *     requirement handed to pay(). The JSON round-trip severs that reference
 *     (and collapses getters, so the values validated are the values kept —
 *     no re-read of a hostile object after validation).
 * Unknown keys are KEPT: schemes carry scheme-specific fields there (e.g.
 * Solana's `feePayer`) that the caller's signer may need. Only the keys this
 * package itself interprets are type-enforced.
 */
function validateExtra(
  raw: unknown,
  index: number,
): NonNullable<PaymentRequirements["extra"]> {
  if (typeof raw !== "object" || Array.isArray(raw)) {
    throw new X402ProtocolError(`accepts[${index}].extra must be an object`);
  }
  let copy: unknown;
  try {
    copy = JSON.parse(JSON.stringify(raw));
  } catch {
    // Circular / non-serializable input can't have come off the wire.
    throw new X402ProtocolError(`accepts[${index}].extra is not JSON-representable`);
  }
  // A toJSON() on the source can rewrite the round-trip into a non-object.
  if (!copy || typeof copy !== "object" || Array.isArray(copy)) {
    throw new X402ProtocolError(`accepts[${index}].extra must be an object`);
  }
  const extra = copy as Record<string, unknown>;
  for (const key of ["name", "version", "symbol"] as const) {
    if (extra[key] !== undefined && typeof extra[key] !== "string") {
      throw new X402ProtocolError(`accepts[${index}].extra.${key} must be a string`);
    }
  }
  if (
    extra.decimals !== undefined &&
    (typeof extra.decimals !== "number" ||
      !Number.isInteger(extra.decimals) ||
      extra.decimals < 0 ||
      extra.decimals > 255)
  ) {
    throw new X402ProtocolError(
      `accepts[${index}].extra.decimals must be an integer in [0, 255]`,
    );
  }
  return extra as NonNullable<PaymentRequirements["extra"]>;
}

// ── v2 parsing (PAYMENT-REQUIRED header carrier) ─────────────────────────────

/**
 * CAIP-2 chain id grammar: namespace ":" reference.
 * Enforced in full — the reference SDK accepts any string containing a colon,
 * but a firewall that keys its trusted-asset registry on the network string
 * must not let "eip155:8453 " or "EIP155:8453" alias past an exact-match
 * registry entry.
 */
const CAIP2_RE = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/;

/** Structural caps on the untrusted `extensions` object. */
const MAX_EXTENSIONS = 16;
const MAX_EXTENSION_ID_CHARS = 128;
const MAX_EXTENSIONS_JSON_CHARS = 32 * 1024;

/**
 * Decode and validate a PAYMENT-REQUIRED header value (base64 JSON).
 * Everything about the value is untrusted: its size is capped BEFORE decoding,
 * and the decoded JSON goes through the same total version check and
 * fixed-allowlist field validation as the v1 body.
 */
export function parsePaymentRequiredHeader(headerValue: string): PaymentRequiredV2 {
  if (headerValue.length > MAX_PAYMENT_REQUIRED_HEADER_CHARS) {
    throw new X402ProtocolError(
      `PAYMENT-REQUIRED header too large (${headerValue.length} > ${MAX_PAYMENT_REQUIRED_HEADER_CHARS} chars)`,
    );
  }
  // STRICT, because Node's base64 decoder is not. It silently skips any
  // character outside the alphabet and stops at padding, which makes DUPLICATE
  // HEADERS ambiguous rather than invalid: `Headers.get()` joins repeated
  // `PAYMENT-REQUIRED` values with ", ", and the decoder skips that separator
  // and merges or truncates them. Measured: two headers quoting 1 and 999999
  // minor units decoded to the 1 — with the SERVER choosing which survives, by
  // its own choice of padding. A hostile server must not get to send two prices
  // and pick which one is policed, so every dual-header 402 is refused here
  // instead of silently resolved.
  if (!/^[A-Za-z0-9+/_-]*={0,2}$/.test(headerValue)) {
    throw new X402ProtocolError(
      "PAYMENT-REQUIRED header is not canonical base64 (stray characters, or duplicate headers joined by the transport)",
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(headerValue, "base64").toString("utf8"));
  } catch {
    throw new X402ProtocolError("PAYMENT-REQUIRED header is not base64-encoded JSON");
  }
  return parsePaymentRequiredV2(parsed);
}

/**
 * Validate a decoded v2 PaymentRequired structure.
 *
 * VERSION HANDLING (total, and STRICTER than the body carrier): the header
 * carrier exists only in v2, so `x402Version` MUST be the integer 2. An
 * absent version, a declared 1, "2", 1.5, 0, null, or any non-number is a
 * refusal — a server that emits the v2 carrier with a non-v2 declaration is
 * confused or hostile, and guessing on its behalf is how a client validates
 * one protocol's data under another's rules.
 */
export function parsePaymentRequiredV2(body: unknown): PaymentRequiredV2 {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new X402ProtocolError("PAYMENT-REQUIRED payload is not an object");
  }
  const b = body as Record<string, unknown>;

  const version = classifyX402Version(b.x402Version);
  switch (version.kind) {
    case "v2":
      break;
    case "absent":
      throw new X402ProtocolError(
        "PAYMENT-REQUIRED payload has no x402Version; v2 requires the integer 2",
      );
    case "v1":
      throw new X402ProtocolError(
        "PAYMENT-REQUIRED payload declares x402Version 1 — the v2 header carrier with a v1 " +
          "declaration is version confusion, refused",
      );
    case "future":
      throw new X402VersionUnsupportedError(
        version.version,
        `PAYMENT-REQUIRED payload declares x402Version ${version.version}`,
      );
    case "invalid":
      throw new X402ProtocolError(
        `PAYMENT-REQUIRED payload's x402Version must be the integer 2; got ${version.description}`,
      );
  }

  const resource = validateResourceInfo(b.resource);

  if (!Array.isArray(b.accepts)) {
    throw new X402ProtocolError("PAYMENT-REQUIRED payload has no `accepts` array");
  }
  if (b.accepts.length > 32) {
    throw new X402ProtocolError(
      `PAYMENT-REQUIRED payload has too many accepts entries (${b.accepts.length} > 32)`,
    );
  }
  const accepts = b.accepts.map((r, i) => validateRequirementV2(r, i));
  if (accepts.length === 0) {
    throw new X402ProtocolError("PAYMENT-REQUIRED payload `accepts` is empty");
  }

  const result: PaymentRequiredV2 = { x402Version: 2, resource, accepts };
  if (typeof b.error === "string") result.error = b.error;
  if (b.extensions !== undefined && b.extensions !== null) {
    result.extensions = validateExtensions(b.extensions);
  }
  return result;
}

/**
 * v2 ResourceInfo: `url` is required; description/mimeType, when present, must
 * be strings (fail closed on wrong types — this is a new parser with no
 * tolerant legacy to preserve). Built field-by-field so no reference to the
 * untrusted object survives.
 */
function validateResourceInfo(raw: unknown): ResourceInfo {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new X402ProtocolError(
      "PAYMENT-REQUIRED payload `resource` must be a ResourceInfo object (required in v2)",
    );
  }
  const o = raw as Record<string, unknown>;
  if (typeof o.url !== "string" || o.url.length === 0) {
    throw new X402ProtocolError("resource.url must be a non-empty string");
  }
  const info: ResourceInfo = { url: o.url };
  for (const k of ["description", "mimeType"] as const) {
    if (o[k] !== undefined) {
      if (typeof o[k] !== "string") {
        throw new X402ProtocolError(`resource.${k} must be a string when present`);
      }
      info[k] = o[k] as string;
    }
  }
  return info;
}

/**
 * One v2 requirement, built from a fixed allowlist — unknown keys are dropped,
 * so nothing unvalidated can reach policy, the intent, or `pay()`.
 *
 * MIXED-SHAPE REFUSALS: a v2 requirement carrying v1's `maxAmountRequired`
 * (money) or a per-requirement `resource` (origin binding) is refused
 * outright. Those fields have a DIFFERENT home or name in v2, so their
 * presence means either a confused server or an attempt to show one value to
 * clients reading v1 fields and another to clients reading v2 fields. The
 * money and binding fields must have exactly one reading.
 */
function validateRequirementV2(r: unknown, index: number): PaymentRequirementsV2 {
  if (!r || typeof r !== "object" || Array.isArray(r)) {
    throw new X402ProtocolError(`accepts[${index}] is not an object`);
  }
  const o = r as Record<string, unknown>;
  if (o.maxAmountRequired !== undefined) {
    throw new X402ProtocolError(
      `accepts[${index}] carries v1 \`maxAmountRequired\` in a v2 requirement — ` +
        `mixed-version money fields are refused (v2 names the amount \`amount\`)`,
    );
  }
  if (o.resource !== undefined) {
    throw new X402ProtocolError(
      `accepts[${index}] carries a per-requirement \`resource\` in a v2 requirement — ` +
        `mixed-version binding fields are refused (v2 moved resource to the top level)`,
    );
  }
  const str = (k: string): string => {
    const v = o[k];
    if (typeof v !== "string" || v.length === 0) {
      throw new X402ProtocolError(`accepts[${index}].${k} must be a non-empty string`);
    }
    return v;
  };
  const network = str("network");
  if (!CAIP2_RE.test(network)) {
    throw new X402ProtocolError(
      `accepts[${index}].network must be a CAIP-2 chain id (namespace:reference, e.g. "eip155:8453"); got ${JSON.stringify(network)}`,
    );
  }
  // REQUIRED in v2. Refusal (not a default) on absence: defaulting a field the
  // spec makes mandatory would accept bodies no conformant server produces.
  const timeout = o.maxTimeoutSeconds;
  if (typeof timeout !== "number" || !Number.isFinite(timeout) || timeout <= 0) {
    throw new X402ProtocolError(
      `accepts[${index}].maxTimeoutSeconds must be a positive number (required in v2)`,
    );
  }
  const req: PaymentRequirementsV2 = {
    scheme: str("scheme"),
    network,
    amount: str("amount"),
    payTo: str("payTo"),
    asset: str("asset"),
    maxTimeoutSeconds: timeout,
  };
  // Same key+type validation and defensive copy as v1 — this MUST survive the
  // v2 port: extra is the natural channel for smuggling attacker data into
  // whatever the payer signs.
  if (o.extra !== undefined && o.extra !== null) {
    req.extra = validateExtra(o.extra, index);
  }
  return req;
}

/**
 * v2 `extensions`: key = extension id, value = {info, schema}. The client is
 * obliged to ECHO at least `info` back in its PaymentPayload, which makes this
 * a reflection channel for unbounded untrusted server data — so it is
 * size-capped, structurally validated, and defensively copied here, BEFORE it
 * can reach the payer that does the echoing.
 */
function validateExtensions(raw: unknown): Record<string, X402Extension> {
  if (typeof raw !== "object" || Array.isArray(raw)) {
    throw new X402ProtocolError("PAYMENT-REQUIRED payload `extensions` must be an object");
  }
  let serialized: string;
  try {
    serialized = JSON.stringify(raw);
  } catch {
    throw new X402ProtocolError("`extensions` is not JSON-representable");
  }
  if (typeof serialized !== "string" || serialized.length > MAX_EXTENSIONS_JSON_CHARS) {
    throw new X402ProtocolError(
      `\`extensions\` too large (> ${MAX_EXTENSIONS_JSON_CHARS} JSON chars)`,
    );
  }
  const copy: unknown = JSON.parse(serialized);
  if (!copy || typeof copy !== "object" || Array.isArray(copy)) {
    throw new X402ProtocolError("`extensions` must be an object");
  }
  const entries = Object.entries(copy as Record<string, unknown>);
  if (entries.length > MAX_EXTENSIONS) {
    throw new X402ProtocolError(`too many extensions (${entries.length} > ${MAX_EXTENSIONS})`);
  }
  // Null-prototype: a server-supplied extension id must be DATA, never a lever
  // on this object's prototype.
  const out: Record<string, X402Extension> = Object.create(null);
  for (const [id, value] of entries) {
    if (id.length === 0 || id.length > MAX_EXTENSION_ID_CHARS) {
      throw new X402ProtocolError(
        `extension id length must be 1..${MAX_EXTENSION_ID_CHARS} chars`,
      );
    }
    // On a plain {}, assigning `__proto__` replaces the prototype instead of
    // adding a key, so the entry is SILENTLY DROPPED — verified: the write
    // lands nowhere and Object.keys stays empty. The client would then omit an
    // extension the spec obliges it to echo, and the server could reject the
    // request AFTER the payment signature was transmitted: a counted spend that
    // buys nothing. Refused outright rather than sanitized, so the failure is
    // loud on a body no honest server sends.
    if (id === "__proto__" || id === "constructor" || id === "prototype") {
      throw new X402ProtocolError(
        `extension id ${JSON.stringify(id)} is refused: it names an object-prototype slot rather than an extension`,
      );
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new X402ProtocolError(`extensions[${JSON.stringify(id)}] must be an object`);
    }
    const v = value as Record<string, unknown>;
    for (const k of ["info", "schema"] as const) {
      if (!v[k] || typeof v[k] !== "object" || Array.isArray(v[k])) {
        throw new X402ProtocolError(
          `extensions[${JSON.stringify(id)}].${k} must be an object (required)`,
        );
      }
    }
    out[id] = value as X402Extension;
  }
  return out;
}

/** base64 the JSON payment payload for the X-PAYMENT header. */
export function encodePaymentHeader(payload: unknown): string {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
}

/**
 * Decode a settlement header value (X-PAYMENT-RESPONSE in v1, PAYMENT-RESPONSE
 * in v2 — same base64-JSON encoding); returns null if absent/garbage.
 */
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
 * The server presented an x402 version (or a carrier/version combination)
 * this adapter will not pay against.
 *
 * Separate from `X402ProtocolError` because the two demand different
 * responses: a protocol error means the server sent something malformed,
 * while this means the versions/carriers themselves disagree. For a version
 * above 2 the ADAPTER is behind; for v2-on-the-body-carrier the SERVER is
 * emitting v2 data where only v1 can travel (a conformant v2 server sends the
 * PAYMENT-REQUIRED header, which this adapter does support). Conflating the
 * two sends people hunting a bug in someone else's implementation.
 */
export class X402VersionUnsupportedError extends Error {
  constructor(
    readonly detectedVersion: number,
    detail: string,
  ) {
    super(
      detectedVersion === 2
        ? `x402 v2 is not supported on this carrier by @vaduno/x402 (v2 PaymentRequired travels ` +
          `in the PAYMENT-REQUIRED response header, which this adapter handles when the ` +
          `\`v2\` option is configured): ${detail}. No payment was attempted.`
        : `x402 v${detectedVersion} is not supported by @vaduno/x402 (this adapter implements ` +
          `v1 and v2): ${detail}. No payment was attempted. ` +
          `Track https://github.com/premsreelathasugeendran/vaduno/issues for newer versions.`,
    );
    this.name = "X402VersionUnsupportedError";
  }
}

/**
 * Identify v2-SHAPED data in a body that did not declare v2, or null.
 *
 * Three independent signals, because a server may declare its version, imply
 * it through field names, or both (the explicit `x402Version: 2` declaration
 * is handled by the total version check in parsePaymentRequired):
 *  - a requirement carrying v2's `amount` — of ANY type, since the point of
 *    this detection is a clear version error rather than a misleading field
 *    error, and a numeric amount deserves that clarity as much as a string —
 *    where v1's `maxAmountRequired` is absent;
 *  - a top-level `resource` OBJECT: v1 has no top-level resource at all
 *    (v2's ResourceInfo), so its presence cannot be v1;
 *  - at the fetch layer (not here): a PAYMENT-REQUIRED response header, the
 *    dominant real-world v2 signal, routes to the v2 parser before the body
 *    is ever read.
 *
 * Deliberately conservative: it only fires when the body cannot be v1. A body
 * that satisfies v1 is parsed as v1 even if it carries extra unknown keys,
 * since forward-compatible servers add fields all the time.
 */
function detectV2Shape(b: Record<string, unknown>): string | null {
  if (b.resource !== undefined && b.resource !== null && typeof b.resource === "object") {
    return "body carries a top-level `resource` object (v2's ResourceInfo; v1 has no top-level resource)";
  }

  const accepts = Array.isArray(b.accepts) ? b.accepts : [];
  for (let i = 0; i < accepts.length; i += 1) {
    const r = accepts[i];
    if (!r || typeof r !== "object") continue;
    const o = r as Record<string, unknown>;
    if (o.maxAmountRequired === undefined && o.amount !== undefined) {
      return `accepts[${i}] carries \`amount\` (${typeof o.amount}) and no \`maxAmountRequired\` (renamed in v2)`;
    }
  }

  return null;
}
