/**
 * Out-of-process key custody for the guarded signer.
 *
 * WHY THIS EXISTS: `guardedSigner()` makes the guard mandatory for every
 * signature THAT OBJECT can produce — but when the raw key lives in the same
 * process, injected code can read the key and sign around the wrapper. The
 * README has said from the start that closing this needs the key kept "where
 * only the wrapper reaches it (a separate process, Durable Object, or KMS)".
 * This module is that configuration, shipped:
 *
 *   agent process                          key-holding process / Durable Object
 *   ─────────────                          ────────────────────────────────────
 *   remoteSigner({ address, send })  ───►  createSignerHost({ account, guard, … })
 *     the ONLY capability:                   holds the key in ITS closure;
 *     signTypedData, forwarded               its ONLY method is the policy-gated
 *     as text                                signTypedData of a guardedSigner
 *
 * THE BOUNDARY IS TEXTUAL BY CONSTRUCTION. `handle()` takes a string and
 * returns a string, so nothing that is not JSON-serializable can cross in
 * either direction — no object references, no functions, no key material.
 * The agent process holds an address (public) and a transport. Compromise of
 * the agent process yields the ability to ASK for signatures, every one of
 * which is policed and written to the host's ledger; it does not yield the
 * key, and it cannot reach an ungated capability, because the host does not
 * have one to offer.
 *
 * WHAT THIS DOES NOT DO, stated before anything else:
 *  - It does not protect against compromise of the HOST process. The key
 *    lives there; the host's job is to have no other reachable surface.
 *  - It does not authenticate the caller. Anyone who can reach the transport
 *    can request policy-gated signatures. Put the transport somewhere only
 *    the agent reaches (a Durable Object binding, a localhost socket, a
 *    private network) and add caller auth at that layer if you need it.
 *  - Client-side refusals (a request the codec cannot faithfully encode) are
 *    thrown in the agent process and CANNOT be audited on the host's ledger —
 *    the request never reaches it. Every refusal the host decides is audited.
 *
 * THE WIRE CODEC preserves exactly the values `structuredClone` +
 * EIP-712-relevant JavaScript can carry: null, boolean, finite number,
 * string, bigint, plain object, array. bigint — which JSON cannot carry and
 * typed-data requests are full of — travels as `{"$vadunoBigint":"<decimal>"}`,
 * and a caller-controlled object that LOOKS like that tag is escaped
 * (`{"$vadunoEscape":…}`) so the codec stays injective: decode(encode(x)) is
 * x for every accepted input, and no input decodes into something the caller
 * did not present. Anything else — Date, Map, a non-finite number — is
 * REFUSED, because JSON.stringify would silently mangle it into different
 * signed bytes, and "silently different bytes" is the defect family this
 * whole package exists to kill.
 */
import { guardedSigner } from "./guarded-signer.js";
import type {
  GuardedSigner,
  GuardedSignerOptions,
  RefusalReason,
  SignerGuard,
  TypedDataRequest,
} from "./guarded-signer.js";
import { GuardSignerRefusedError } from "./guarded-signer.js";

/** Protocol version. A request naming any other version is refused. */
export const SIGNER_WIRE_VERSION = 1;

const BIGINT_TAG = "$vadunoBigint";
const ESCAPE_TAG = "$vadunoEscape";

export interface SignerWireRefusal {
  v: number;
  ok: false;
  code: string;
  message: string;
  intentId?: string;
  reasons?: RefusalReason[];
}

export type SignerWireResponse =
  | { v: number; ok: true; signature: `0x${string}` }
  | { v: number; ok: true; address: `0x${string}` }
  | SignerWireRefusal;

/**
 * Sends one serialized request and returns the serialized response. This is
 * the whole client-side contract: strings in, strings out. An HTTP POST, a
 * Durable Object stub call, a Unix socket, a child-process pipe all fit.
 */
export type SignerTransport = (requestJson: string) => Promise<string>;

export interface SignerHost {
  /** The signing address (public). */
  readonly address: `0x${string}`;
  /**
   * Handle one wire request. Never throws: every failure — unparseable
   * request, unknown method, refused payment — returns a serialized refusal.
   * The host process stays alive to keep writing its ledger.
   */
  handle(requestJson: string): Promise<string>;
  /**
   * The same boundary as a fetch handler, for a Durable Object or Worker:
   * `POST` with the wire request as the body. 200 on success, 403 on any
   * refusal, 405 on a non-POST method.
   */
  fetch(request: Request): Promise<Response>;
}

function isPlainRecord(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

class WireCodecError extends Error {}

/**
 * Encode a decoded-JavaScript value into JSON-safe form. Refuses anything
 * JSON.stringify would mangle rather than round-trip.
 */
function encodeWire(v: unknown): unknown {
  if (v === null || typeof v === "boolean" || typeof v === "string") return v;
  if (typeof v === "number") {
    if (!Number.isFinite(v)) {
      throw new WireCodecError(`a non-finite number (${v}) cannot cross the wire faithfully`);
    }
    return v;
  }
  if (typeof v === "bigint") {
    const tagged: Record<string, unknown> = Object.create(null);
    tagged[BIGINT_TAG] = v.toString(10);
    return tagged;
  }
  if (Array.isArray(v)) return v.map(encodeWire);
  if (isPlainRecord(v)) {
    const out: Record<string, unknown> = Object.create(null);
    for (const key of Object.keys(v)) {
      Object.defineProperty(out, key, {
        value: encodeWire(v[key]),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    // A caller-controlled object that LOOKS like one of the codec's tags must
    // not decode into one. Wrap it once; decode unwraps once. Injective.
    if (Object.hasOwn(v, BIGINT_TAG) || Object.hasOwn(v, ESCAPE_TAG)) {
      const escaped: Record<string, unknown> = Object.create(null);
      escaped[ESCAPE_TAG] = out;
      return escaped;
    }
    return out;
  }
  throw new WireCodecError(
    `a value of type ${
      typeof v === "object" ? Object.prototype.toString.call(v) : typeof v
    } cannot cross the wire faithfully (JSON would silently change the signed bytes)`,
  );
}

/** Decode the JSON-parsed wire form back into the value the caller presented. */
function decodeWire(v: unknown): unknown {
  if (v === null || typeof v === "boolean" || typeof v === "string") return v;
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new WireCodecError("non-finite number on the wire");
    return v;
  }
  if (Array.isArray(v)) return v.map(decodeWire);
  if (typeof v === "object") {
    const rec = v as Record<string, unknown>;
    const keys = Object.keys(rec);
    if (keys.length === 1 && keys[0] === BIGINT_TAG) {
      const raw = rec[BIGINT_TAG];
      if (typeof raw !== "string" || !/^-?\d+$/.test(raw)) {
        throw new WireCodecError("malformed bigint tag on the wire");
      }
      return BigInt(raw);
    }
    if (keys.length === 1 && keys[0] === ESCAPE_TAG) {
      const inner = rec[ESCAPE_TAG];
      if (inner === null || typeof inner !== "object" || Array.isArray(inner)) {
        throw new WireCodecError("malformed escape tag on the wire");
      }
      // Unwrap exactly one level; the inner object's own keys are literal.
      const out: Record<string, unknown> = Object.create(null);
      for (const key of Object.keys(inner as Record<string, unknown>)) {
        Object.defineProperty(out, key, {
          value: decodeWire((inner as Record<string, unknown>)[key]),
          enumerable: true,
          writable: true,
          configurable: true,
        });
      }
      return out;
    }
    const out: Record<string, unknown> = Object.create(null);
    for (const key of keys) {
      Object.defineProperty(out, key, {
        value: decodeWire(rec[key]),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return out;
  }
  throw new WireCodecError(`unexpected wire value of type ${typeof v}`);
}

function refusalBody(
  code: string,
  message: string,
  extra: { intentId?: string; reasons?: RefusalReason[] } = {},
): string {
  const body: SignerWireRefusal = {
    v: SIGNER_WIRE_VERSION,
    ok: false,
    code,
    message,
    ...(extra.intentId !== undefined ? { intentId: extra.intentId } : {}),
    ...(extra.reasons !== undefined ? { reasons: extra.reasons } : {}),
  };
  return JSON.stringify(body);
}

/** Hex-encoded random bytes for refusal intent ids (same shape as the signer's). */
function randomHex(byteLength: number): string {
  const buf = new Uint8Array(byteLength);
  const cryptoObj = (globalThis as { crypto?: Crypto }).crypto;
  if (cryptoObj && typeof cryptoObj.getRandomValues === "function") {
    cryptoObj.getRandomValues(buf);
  } else {
    for (let i = 0; i < buf.length; i += 1) buf[i] = Math.floor(Math.random() * 256);
  }
  let out = "";
  for (const b of buf) out += b.toString(16).padStart(2, "0");
  return out;
}

/**
 * Keep the raw account in THIS process and expose exactly one capability —
 * the policy-gated `signTypedData` of a `guardedSigner` built from the same
 * options. Run it where the agent is not: a separate OS process, a Durable
 * Object whose only binding is this host's `fetch`, or a sidecar.
 *
 * Every refusal the host decides — an unknown method, an unparseable
 * request, and every refusal the inner guarded signer produces — lands in
 * the guard's tamper-evident ledger, which lives with the key, out of the
 * agent's reach.
 */
export function createSignerHost(options: GuardedSignerOptions): SignerHost {
  const inner: GuardedSigner = guardedSigner(options);
  const guard: SignerGuard = options.guard;
  const agentId = options.agentId ?? "cloudflare-agent";

  /**
   * Audit a HOST-level refusal (bad wire input, disabled method) in the same
   * way the guarded signer audits its local refusals: through
   * `guard.authorize()` with an amount the policy engine denies
   * unconditionally, so the row is indistinguishable in shape and hashing
   * from a policy denial. Best-effort: a ledger problem must never turn a
   * refusal into anything else.
   */
  async function auditHostRefusal(code: string, message: string): Promise<string> {
    const intentId = `refused:${code}:0x${randomHex(16)}`;
    try {
      const result = await guard.authorize({
        id: intentId,
        agentId,
        merchant: { id: `refusal:${code}` },
        amount: { amountMinor: 0, currency: `REFUSED:${code}` },
        rail: "x402",
        description: `signer host refusal [${code}]: ${message.slice(0, 500)}`,
        metadata: { refusal: code },
        requestedAt: new Date().toISOString(),
      });
      if (result?.status === "authorized") {
        await guard.settle(intentId, { status: "failed", error: `refused locally: ${code}` });
        await guard.releaseSpend(intentId);
      }
    } catch {
      // Never let an audit failure change the refusal.
    }
    return intentId;
  }

  async function refuse(code: string, message: string): Promise<string> {
    const intentId = await auditHostRefusal(code, message);
    return refusalBody(code, message, { intentId });
  }

  async function handle(requestJson: string): Promise<string> {
    let parsed: unknown;
    try {
      if (typeof requestJson !== "string") throw new Error("request is not a string");
      parsed = JSON.parse(requestJson);
    } catch (err) {
      return refuse(
        "HOST_REQUEST_UNPARSEABLE",
        `signer host request is not parseable JSON (${
          err instanceof Error ? err.message : String(err)
        })`,
      );
    }
    if (!isPlainRecord(parsed)) {
      return refuse("HOST_REQUEST_MALFORMED", "signer host request is not a JSON object");
    }
    if (parsed["v"] !== SIGNER_WIRE_VERSION) {
      return refuse(
        "HOST_PROTOCOL_VERSION",
        `signer host speaks wire version ${SIGNER_WIRE_VERSION}; request declares ${JSON.stringify(
          parsed["v"],
        )}`,
      );
    }
    const method = parsed["method"];

    if (method === "address") {
      // The address is public; answering it is not a capability.
      return JSON.stringify({ v: SIGNER_WIRE_VERSION, ok: true, address: inner.address });
    }

    if (method !== "signTypedData") {
      // THE load-bearing default-deny: signTransaction, signMessage, sign,
      // exportKey, or anything else anyone invents — the host recognizes ONE
      // capability, and everything else is an audited refusal. This is what
      // makes "the raw signer is unreachable from the agent process" a
      // property of the design: there is no door here to leave open.
      return refuse(
        "HOST_METHOD_DISABLED",
        `signer host exposes exactly one capability, signTypedData; ` +
          `refusing method ${JSON.stringify(String(method).slice(0, 64))}`,
      );
    }

    if (!("typedData" in parsed)) {
      return refuse("HOST_REQUEST_MALFORMED", "signTypedData request carries no typedData");
    }
    let typedData: unknown;
    try {
      typedData = decodeWire(parsed["typedData"]);
    } catch (err) {
      return refuse(
        "HOST_TYPED_DATA_UNDECODABLE",
        `typedData did not decode from the wire (${
          err instanceof Error ? err.message : String(err)
        })`,
      );
    }

    try {
      // The inner guarded signer snapshots, polices, audits, and only then
      // signs. Everything security-relevant happens in there.
      const signature = await inner.signTypedData(typedData as TypedDataRequest);
      return JSON.stringify({ v: SIGNER_WIRE_VERSION, ok: true, signature });
    } catch (err) {
      if (err instanceof GuardSignerRefusedError) {
        return refusalBody(err.code, err.message, {
          ...(err.intentId !== undefined ? { intentId: err.intentId } : {}),
          ...(err.reasons !== undefined ? { reasons: err.reasons } : {}),
        });
      }
      // An unexpected throw is still a refusal on the wire — the agent gets
      // no signature and a diagnosis, and the host stays up.
      return refuse(
        "HOST_SIGNER_ERROR",
        `signer failed (${err instanceof Error ? err.message : String(err)})`,
      );
    }
  }

  async function fetchHandler(request: Request): Promise<Response> {
    const headers = { "content-type": "application/json" };
    if (request.method !== "POST") {
      return new Response(
        refusalBody("HOST_METHOD_DISABLED", "signer host accepts POST only"),
        { status: 405, headers },
      );
    }
    let body: string;
    try {
      body = await request.text();
    } catch {
      body = "";
    }
    const responseJson = await handle(body);
    const ok = (JSON.parse(responseJson) as { ok: boolean }).ok;
    return new Response(responseJson, { status: ok ? 200 : 403, headers });
  }

  return Object.freeze({
    address: inner.address,
    handle,
    fetch: fetchHandler,
  });
}

export interface RemoteSignerOptions {
  /** The host's signing address (public). Use `connectRemoteSigner` to fetch it. */
  address: `0x${string}`;
  /** Carries serialized requests to the host and returns serialized responses. */
  send: SignerTransport;
}

function refusalFromWire(parsed: SignerWireRefusal): GuardSignerRefusedError {
  return new GuardSignerRefusedError(String(parsed.message), {
    code: String(parsed.code),
    ...(typeof parsed.intentId === "string" ? { intentId: parsed.intentId } : {}),
    ...(Array.isArray(parsed.reasons)
      ? {
          reasons: parsed.reasons.map((r) => ({
            code: String(r?.code),
            message: String(r?.message),
          })),
        }
      : {}),
  });
}

/**
 * The agent-process end: structurally a `ClientEvmSigner` — pass it to
 * `withX402Client(client, { account })` exactly like a local account — whose
 * `signTypedData` forwards the request, as text, to a `createSignerHost`
 * somewhere else. It is constructed from an address and a transport; there is
 * no key here to steal and no raw account to reach around.
 */
export function remoteSigner(options: RemoteSignerOptions): GuardedSigner {
  const { address, send } = options;
  if (typeof send !== "function") {
    throw new Error("remoteSigner: `send` must be a function");
  }
  if (typeof address !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error("remoteSigner: `address` must be a 0x-prefixed 20-byte hex address");
  }

  async function signTypedData(untrusted: TypedDataRequest): Promise<`0x${string}`> {
    // Snapshot before reading, same as the local wrapper — the encoded wire
    // form is taken from an inert copy, so getter games cannot make the host
    // sign different bytes than the caller saw leave.
    let snapshot: TypedDataRequest;
    try {
      snapshot = structuredClone(untrusted);
    } catch {
      throw new GuardSignerRefusedError(
        "typed data could not be safely snapshotted (default-deny)",
        { code: "TYPED_DATA_NOT_SERIALIZABLE" },
      );
    }
    let encoded: unknown;
    try {
      encoded = encodeWire(snapshot);
    } catch (err) {
      throw new GuardSignerRefusedError(
        `typed data cannot cross the process boundary faithfully (${
          err instanceof Error ? err.message : String(err)
        }); refusing rather than signing silently different bytes`,
        { code: "TYPED_DATA_NOT_SERIALIZABLE" },
      );
    }
    const requestJson = JSON.stringify({
      v: SIGNER_WIRE_VERSION,
      method: "signTypedData",
      typedData: encoded,
    });

    let responseJson: string;
    try {
      responseJson = await send(requestJson);
    } catch (err) {
      throw new GuardSignerRefusedError(
        `signer host transport failed (${err instanceof Error ? err.message : String(err)}); ` +
          "no signature exists",
        { code: "REMOTE_TRANSPORT_FAILED" },
      );
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(responseJson);
    } catch {
      parsed = null;
    }
    if (!isPlainRecord(parsed) || parsed["v"] !== SIGNER_WIRE_VERSION) {
      throw new GuardSignerRefusedError(
        "signer host response is not a recognizable wire message; refusing (default-deny)",
        { code: "REMOTE_RESPONSE_INVALID" },
      );
    }
    if (parsed["ok"] !== true) {
      throw refusalFromWire(parsed as unknown as SignerWireRefusal);
    }
    const signature = parsed["signature"];
    if (typeof signature !== "string" || !/^0x[0-9a-fA-F]+$/.test(signature)) {
      throw new GuardSignerRefusedError(
        "signer host said ok but returned no signature-shaped value; refusing (default-deny)",
        { code: "REMOTE_RESPONSE_INVALID" },
      );
    }
    return signature as `0x${string}`;
  }

  return Object.freeze({ address, signTypedData });
}

/**
 * Build a remote signer by asking the host for its (public) address first.
 */
export async function connectRemoteSigner(send: SignerTransport): Promise<GuardedSigner> {
  const responseJson = await send(
    JSON.stringify({ v: SIGNER_WIRE_VERSION, method: "address" }),
  );
  let parsed: unknown;
  try {
    parsed = JSON.parse(responseJson);
  } catch {
    parsed = null;
  }
  if (
    !isPlainRecord(parsed) ||
    parsed["v"] !== SIGNER_WIRE_VERSION ||
    parsed["ok"] !== true ||
    typeof parsed["address"] !== "string"
  ) {
    throw new GuardSignerRefusedError(
      "signer host did not answer the address request; refusing to construct a remote signer",
      { code: "REMOTE_RESPONSE_INVALID" },
    );
  }
  return remoteSigner({ address: parsed["address"] as `0x${string}`, send });
}

/**
 * A `SignerTransport` over HTTP(S) POST, for a host exposed via
 * `SignerHost.fetch` — a Durable Object, a Worker route, or any HTTP server.
 */
export function httpTransport(
  url: string,
  fetchImpl: typeof globalThis.fetch = globalThis.fetch,
): SignerTransport {
  return async (requestJson: string): Promise<string> => {
    const res = await fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: requestJson,
    });
    return res.text();
  };
}
