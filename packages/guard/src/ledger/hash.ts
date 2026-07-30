import { createHash } from "node:crypto";

/**
 * Canonical JSON serializer for hashing and signing.
 *
 * THE PROPERTY THAT MATTERS: distinct inputs must produce distinct output.
 * Everything this commits to — ledger entry hashes, mandate signatures,
 * `contextHash`, transparency-log leaves, status-list credentials — is only as
 * trustworthy as that.
 *
 * Until 0.3.0 it was NOT true. The previous version deliberately coerced
 * anything JSON cannot represent "instead of throwing", which produced five
 * classes of collision — found by execution, not by reading:
 *
 *     canonicalJson({n: 1n})          === canonicalJson({n: "1n"})
 *     canonicalJson({d: new Date(0)}) === canonicalJson({d: "1970-01-01T00:00:00.000Z"})
 *     canonicalJson({x: NaN})         === canonicalJson({x: null})
 *     canonicalJson([undefined])      === canonicalJson([null])
 *     new Map([[1,2]]), new Set(), /re/ and every class instance all became "{}"
 *
 * That made `contextHash` forgeable, which defeats CONTEXT_MISMATCH — the check
 * binding a mandate to ONE approved task run. An agent controlling
 * `intent.context` could craft a different object hashing to the same value.
 *
 * So this version REFUSES ambiguity rather than resolving it. Anything JSON
 * cannot represent exactly throws `CanonicalizeError`, which every caller
 * already treats as fail-closed (rejected append / `{ok:false}` verify /
 * SIGNATURE_INVALID mandate). If you want a timestamp or a big integer in a
 * signed payload, serialize it yourself — then the bytes are your decision
 * rather than this function's guess.
 *
 * Guarantees:
 *  - object keys sorted by code unit at every level; arrays kept in order;
 *  - only JSON's own types accepted: null, boolean, finite number, string,
 *    array, plain object;
 *  - `__proto__` and friends are serialized as ordinary own keys — the hash
 *    commits to them, and no property assignment ever happens. Built as a
 *    string builder precisely so that assigning "__proto__" to an accumulator
 *    cannot mutate a prototype and silently drop the key;
 *  - nesting beyond MAX_DEPTH throws rather than overflowing the stack.
 *
 * THE ONE DELIBERATE OMISSION: an own property whose value is `undefined` is
 * skipped, so `{a: 1, b: undefined}` and `{a: 1}` agree. Both say "b is
 * absent", so that is not a meaningful collision, and matching
 * `JSON.stringify` here keeps optional TypeScript fields usable. `undefined`
 * inside an ARRAY is different — it would collide with `null`, which means
 * something else — so it throws.
 *
 * Aligned with RFC 8785 (JCS) in spirit: the accepted value space is JSON's and
 * serialization is deterministic. Numbers use ECMAScript `JSON.stringify`
 * formatting, which agrees with JCS on every integer and on the decimals this
 * project produces; amounts here are integer minor units, so the pathological
 * float cases JCS enumerates are unreachable.
 */

/**
 * Maximum nesting depth. Beyond this, canonicalJson throws a catchable
 * CanonicalizeError instead of overflowing the call stack — so an
 * attacker-shaped deeply-nested value becomes a fail-closed error at the
 * callers rather than an uncaught RangeError. Legitimate payment metadata never
 * approaches this.
 */
const MAX_DEPTH = 256;

export class CanonicalizeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalizeError";
  }
}

export function canonicalJson(value: unknown): string {
  return serialize(value, 0, "$");
}

function serialize(v: unknown, depth: number, path: string): string {
  if (depth > MAX_DEPTH) {
    throw new CanonicalizeError(`input nesting exceeds max depth ${MAX_DEPTH} at ${path}`);
  }
  if (v === null) return "null";

  const t = typeof v;
  if (t === "string") return JSON.stringify(v);
  if (t === "boolean") return v ? "true" : "false";

  if (t === "number") {
    // NaN and ±Infinity used to become "null", colliding with a real null.
    if (!Number.isFinite(v as number)) {
      throw new CanonicalizeError(
        `${path} is ${String(v)}, which JSON cannot represent; rendering it as ` +
          `null would collide with an actual null`,
      );
    }
    return JSON.stringify(v);
  }

  if (t === "bigint") {
    throw new CanonicalizeError(
      `${path} is a bigint; convert it to a string or a safe integer yourself — ` +
        `any encoding chosen here collides with a string that happens to match it`,
    );
  }

  if (t === "undefined") {
    throw new CanonicalizeError(
      `${path} is undefined; in an array that would collide with null, which ` +
        `means something different`,
    );
  }

  if (t === "function" || t === "symbol") {
    throw new CanonicalizeError(`${path} is a ${t}, which cannot be signed`);
  }

  if (Array.isArray(v)) {
    const parts: string[] = [];
    for (let i = 0; i < v.length; i += 1) {
      parts.push(serialize(v[i], depth + 1, `${path}[${i}]`));
    }
    return "[" + parts.join(",") + "]";
  }

  // PLAIN objects only. A Date, Map, Set, RegExp, Buffer or class instance has
  // no own enumerable keys worth speaking of, so `Object.keys` rendered them
  // all as "{}" — colliding with each other and with a genuinely empty object.
  const proto = Object.getPrototypeOf(v);
  if (proto !== Object.prototype && proto !== null) {
    const name = (v as { constructor?: { name?: string } }).constructor?.name ?? "object";
    throw new CanonicalizeError(
      `${path} is a ${name}, not a plain object; convert it to JSON types ` +
        `yourself so the signed bytes are your decision`,
    );
  }

  const keys = Object.keys(v as Record<string, unknown>).sort();
  const parts: string[] = [];
  for (const k of keys) {
    const val = (v as Record<string, unknown>)[k];
    // The one deliberate omission — see the docblock. "b is absent" and "b is
    // undefined" are the same statement.
    if (val === undefined) continue;
    parts.push(JSON.stringify(k) + ":" + serialize(val, depth + 1, `${path}.${k}`));
  }
  return "{" + parts.join(",") + "}";
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}
