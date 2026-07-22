import { createHash } from "node:crypto";

/**
 * Canonical JSON serializer for hashing. Guarantees:
 *  - object keys sorted lexicographically at every level;
 *  - arrays kept in order;
 *  - `undefined` / function / symbol members dropped in objects, rendered as
 *    null inside arrays (matching JSON semantics);
 *  - `__proto__` and other dangerous keys are serialized as ordinary own keys
 *    (no prototype pollution, no silent omission — the hash commits to them);
 *  - `bigint` and `Date` are represented deterministically instead of throwing.
 *
 * Built as a manual string builder rather than JSON.stringify(sortedObject)
 * so that no property assignment ever occurs — assigning a key like
 * "__proto__" to an accumulator object would mutate its prototype and drop
 * the key from the output, making the hash non-injective.
 */
/**
 * Maximum nesting depth. Beyond this, canonicalJson throws a catchable
 * CanonicalizeError instead of overflowing the call stack — so an
 * attacker-shaped deeply-nested value becomes a fail-closed error at the
 * callers (rejected append / {ok:false} verify / SIGNATURE_INVALID mandate)
 * rather than an uncaught RangeError. Legitimate payment metadata never
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
  return serialize(value, 0);
}

function serialize(v: unknown, depth: number): string {
  if (depth > MAX_DEPTH) {
    throw new CanonicalizeError(`input nesting exceeds max depth ${MAX_DEPTH}`);
  }
  if (v === null) return "null";
  const t = typeof v;
  if (t === "string") return JSON.stringify(v);
  if (t === "boolean") return v ? "true" : "false";
  if (t === "number") return Number.isFinite(v as number) ? JSON.stringify(v) : "null";
  if (t === "bigint") return JSON.stringify((v as bigint).toString() + "n");
  if (t === "undefined" || t === "function" || t === "symbol") return "null";
  if (Array.isArray(v)) {
    return "[" + v.map((x) => serializeArrayMember(x, depth + 1)).join(",") + "]";
  }
  if (v instanceof Date) return JSON.stringify(v.toISOString());
  // Plain object (or object-like). Use own enumerable string keys, sorted.
  const keys = Object.keys(v as Record<string, unknown>).sort();
  const parts: string[] = [];
  for (const k of keys) {
    const val = (v as Record<string, unknown>)[k];
    const tv = typeof val;
    if (val === undefined || tv === "function" || tv === "symbol") continue;
    parts.push(JSON.stringify(k) + ":" + serialize(val, depth + 1));
  }
  return "{" + parts.join(",") + "}";
}

function serializeArrayMember(v: unknown, depth: number): string {
  const t = typeof v;
  if (v === undefined || t === "function" || t === "symbol") return "null";
  return serialize(v, depth);
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}
