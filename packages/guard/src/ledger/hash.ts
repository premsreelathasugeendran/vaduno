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
export function canonicalJson(value: unknown): string {
  return serialize(value);
}

function serialize(v: unknown): string {
  if (v === null) return "null";
  const t = typeof v;
  if (t === "string") return JSON.stringify(v);
  if (t === "boolean") return v ? "true" : "false";
  if (t === "number") return Number.isFinite(v as number) ? JSON.stringify(v) : "null";
  if (t === "bigint") return JSON.stringify((v as bigint).toString() + "n");
  if (t === "undefined" || t === "function" || t === "symbol") return "null";
  if (Array.isArray(v)) {
    return "[" + v.map(serializeArrayMember).join(",") + "]";
  }
  if (v instanceof Date) return JSON.stringify(v.toISOString());
  // Plain object (or object-like). Use own enumerable string keys, sorted.
  const keys = Object.keys(v as Record<string, unknown>).sort();
  const parts: string[] = [];
  for (const k of keys) {
    const val = (v as Record<string, unknown>)[k];
    const tv = typeof val;
    if (val === undefined || tv === "function" || tv === "symbol") continue;
    parts.push(JSON.stringify(k) + ":" + serialize(val));
  }
  return "{" + parts.join(",") + "}";
}

function serializeArrayMember(v: unknown): string {
  const t = typeof v;
  if (v === undefined || t === "function" || t === "symbol") return "null";
  return serialize(v);
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}
