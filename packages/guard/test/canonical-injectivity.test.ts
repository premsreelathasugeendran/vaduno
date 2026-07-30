/**
 * Injectivity of canonicalJson — the property every signature in this project
 * rests on.
 *
 * Each case below was a REAL collision in 0.2.2 and earlier, found by running
 * the function rather than reading it. The old implementation coerced anything
 * JSON could not represent "instead of throwing", so five families of distinct
 * inputs produced identical bytes. `contextHash` is built on this, which made
 * CONTEXT_MISMATCH — the check binding a mandate to one approved task run —
 * forgeable by whoever controls `intent.context`.
 */
import { describe, expect, it } from "vitest";
import { CanonicalizeError, canonicalJson, sha256Hex } from "../src/ledger/hash.js";

describe("canonicalJson rejects what it cannot represent unambiguously", () => {
  it("a bigint throws instead of colliding with the string that spells it", () => {
    // Was: canonicalJson({n: 1n}) === canonicalJson({n: "1n"})
    expect(() => canonicalJson({ n: 1n })).toThrow(CanonicalizeError);
    expect(canonicalJson({ n: "1n" })).toBe('{"n":"1n"}');
  });

  it("a Date throws instead of colliding with its own ISO string", () => {
    // Was: canonicalJson({d: new Date(0)}) === canonicalJson({d: "1970-01-01T00:00:00.000Z"})
    expect(() => canonicalJson({ d: new Date(0) })).toThrow(CanonicalizeError);
    expect(canonicalJson({ d: new Date(0).toISOString() })).toBe(
      '{"d":"1970-01-01T00:00:00.000Z"}',
    );
  });

  it("NaN and Infinity throw instead of colliding with null", () => {
    // Was: both rendered as "null".
    expect(() => canonicalJson({ x: Number.NaN })).toThrow(CanonicalizeError);
    expect(() => canonicalJson({ x: Number.POSITIVE_INFINITY })).toThrow(CanonicalizeError);
    expect(() => canonicalJson({ x: Number.NEGATIVE_INFINITY })).toThrow(CanonicalizeError);
    expect(canonicalJson({ x: null })).toBe('{"x":null}');
  });

  it("undefined inside an array throws instead of colliding with null", () => {
    // Was: canonicalJson([undefined]) === canonicalJson([null]).
    // In an array, position is meaningful, so "absent" and "null" differ.
    expect(() => canonicalJson([undefined])).toThrow(CanonicalizeError);
    expect(canonicalJson([null])).toBe("[null]");
  });

  it("non-plain objects throw instead of all collapsing to {}", () => {
    // Was: Map, Set, RegExp and every class instance had no own enumerable keys,
    // so Object.keys() rendered each of them — and a real empty object — as "{}".
    class Mandate {
      constructor(public amount = 1) {}
    }
    for (const exotic of [new Map([[1, 2]]), new Set([1]), /re/, new Mandate(), Buffer.from("x")]) {
      expect(() => canonicalJson({ v: exotic })).toThrow(CanonicalizeError);
    }
    expect(canonicalJson({ v: {} })).toBe('{"v":{}}');
  });

  it("functions and symbols throw rather than being silently dropped", () => {
    expect(() => canonicalJson([() => 1])).toThrow(CanonicalizeError);
    expect(() => canonicalJson([Symbol("s")])).toThrow(CanonicalizeError);
  });

  it("the error names the path, so a rejected payload is debuggable", () => {
    try {
      canonicalJson({ outer: { inner: [1, Number.NaN] } });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(CanonicalizeError);
      expect((err as Error).message).toContain("$.outer.inner[1]");
    }
  });
});

describe("canonicalJson still accepts everything JSON can express", () => {
  it("sorts keys at every level and preserves array order", () => {
    expect(canonicalJson({ b: 1, a: { d: 2, c: 3 } })).toBe('{"a":{"c":3,"d":2},"b":1}');
    expect(canonicalJson([3, 1, 2])).toBe("[3,1,2]");
  });

  it("commits to __proto__ as an ordinary key rather than dropping it", () => {
    // The string-builder implementation exists for exactly this: assigning
    // "__proto__" onto an accumulator object would mutate a prototype and drop
    // the key, so the hash would not commit to it.
    const out = canonicalJson(JSON.parse('{"__proto__":{"admin":true},"a":1}'));
    expect(out).toBe('{"__proto__":{"admin":true},"a":1}');
  });

  it("omits undefined OWN PROPERTIES — the one intentional exception", () => {
    // "b is absent" and "b is undefined" are the same statement, unlike in an
    // array where position carries meaning.
    expect(canonicalJson({ a: 1, b: undefined })).toBe(canonicalJson({ a: 1 }));
  });

  it("distinguishes values that merely look similar", () => {
    const distinct = [
      { a: 1 },
      { a: "1" },
      { a: true },
      { a: null },
      { a: [1] },
      { a: { b: 1 } },
      { a: 1, b: 2 },
      { ab: 1 },
      { "a.b": 1 },
    ];
    const hashes = distinct.map((d) => sha256Hex(canonicalJson(d)));
    expect(new Set(hashes).size).toBe(distinct.length);
  });

  it("still fails closed on absurd nesting instead of overflowing the stack", () => {
    let deep: unknown = 1;
    for (let i = 0; i < 400; i += 1) deep = { n: deep };
    expect(() => canonicalJson(deep)).toThrow(CanonicalizeError);
  });
});
