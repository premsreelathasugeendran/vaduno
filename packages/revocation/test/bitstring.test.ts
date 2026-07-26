import { describe, expect, it } from "vitest";
import { gunzipSync, gzipSync } from "node:zlib";
import { Bitstring, BitstringError, MINIMUM_ENTRIES } from "../src/bitstring.js";

describe("Bitstring — W3C index semantics", () => {
  it("index 0 is the LEFT-MOST (most significant) bit of the first byte", () => {
    const bs = new Bitstring(16);
    bs.set(0, true);
    // Decode our own encoding back to raw bytes to inspect bit placement.
    const raw = gunzipSync(Buffer.from(bs.encode().slice(1), "base64url"));
    expect(raw[0]).toBe(0b1000_0000);
    expect(raw[1]).toBe(0);
  });

  it("index n-1 is the right-most bit", () => {
    const bs = new Bitstring(16);
    bs.set(15, true);
    const raw = gunzipSync(Buffer.from(bs.encode().slice(1), "base64url"));
    expect(raw[0]).toBe(0);
    expect(raw[1]).toBe(0b0000_0001);
  });

  it("sets, reads, and clears independent bits", () => {
    const bs = new Bitstring(64);
    expect(bs.get(9)).toBe(false);
    bs.set(9, true);
    bs.set(63, true);
    expect(bs.get(9)).toBe(true);
    expect(bs.get(63)).toBe(true);
    expect(bs.get(8)).toBe(false);
    expect(bs.get(10)).toBe(false);
    expect(bs.setIndices()).toEqual([9, 63]);
    bs.set(9, false);
    expect(bs.get(9)).toBe(false);
    expect(bs.setIndices()).toEqual([63]);
  });

  it("defaults to the 16KB / 131,072-entry minimum", () => {
    expect(new Bitstring().length).toBe(MINIMUM_ENTRIES);
    expect(MINIMUM_ENTRIES).toBe(16 * 1024 * 8);
  });

  it("raises RANGE_ERROR outside the bitstring", () => {
    const bs = new Bitstring(64);
    expect(() => bs.get(64)).toThrow(BitstringError);
    expect(() => bs.set(-1, true)).toThrow(/outside the bitstring/);
    try {
      bs.get(9999);
    } catch (err) {
      expect((err as BitstringError).code).toBe("RANGE_ERROR");
    }
  });

  it("round-trips through encode/decode with bits preserved", () => {
    const bs = new Bitstring(MINIMUM_ENTRIES);
    const marked = [0, 1, 7, 8, 1000, 131_071];
    for (const i of marked) bs.set(i, true);
    const back = Bitstring.decode(bs.encode());
    expect(back.length).toBe(MINIMUM_ENTRIES);
    expect(back.setIndices()).toEqual(marked);
  });

  it("encodes with the multibase base64url prefix and no padding", () => {
    const encoded = new Bitstring(MINIMUM_ENTRIES).encode();
    expect(encoded.startsWith("u")).toBe(true);
    expect(encoded).not.toContain("=");
    expect(encoded.slice(1)).toMatch(/^[A-Za-z0-9_-]+$/);
    // An all-zero 16KB list compresses to a tiny payload.
    expect(encoded.length).toBeLessThan(200);
  });

  it("decodes the W3C spec's example encodedList (all entries unset)", () => {
    // From the spec's Status List Credential example.
    const example =
      "uH4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA";
    const bs = Bitstring.decode(example);
    expect(bs.length).toBeGreaterThanOrEqual(MINIMUM_ENTRIES);
    expect(bs.setIndices()).toEqual([]);
  });

  it("rejects malformed encodings instead of guessing", () => {
    expect(() => Bitstring.decode("")).toThrow(/non-empty/);
    expect(() => Bitstring.decode("zAAAA")).toThrow(/multibase base64url prefix/);
    expect(() => Bitstring.decode("u!!!!")).toThrow(/not valid base64url/);
    expect(() => Bitstring.decode("uAAAA")).toThrow(/could not be decompressed/);
  });

  it("refuses a decompression bomb", () => {
    // ~64MB of zeros compresses tiny but must not be inflated.
    const bomb = "u" + gzipSync(Buffer.alloc(64 * 1024 * 1024)).toString("base64url");
    expect(() => Bitstring.decode(bomb)).toThrow(/could not be decompressed/);
  });

  it("rejects invalid sizes", () => {
    expect(() => new Bitstring(0)).toThrow(/invalid entry count/);
    expect(() => new Bitstring(12)).toThrow(/multiple of 8/);
  });
});
