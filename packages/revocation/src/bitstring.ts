import { gzipSync, gunzipSync } from "node:zlib";

/**
 * W3C Bitstring Status List v1.0 encoding.
 * https://www.w3.org/TR/vc-bitstring-status-list/
 *
 * Index 0 is the LEFT-MOST bit of the first byte (most-significant bit first),
 * and index n-1 is the right-most bit — per §3.1: "the first index, with a
 * value of zero (0), is located at the left-most bit in the bitstring".
 *
 * The encoded form is GZIP-compressed then multibase base64url WITHOUT
 * padding, i.e. prefixed with "u" (§3.3).
 */

/** §3.1: the uncompressed bitstring MUST be at least 16KB (131,072 entries). */
export const MINIMUM_ENTRIES = 131_072;

/** Multibase prefix for base64url-no-pad. */
const MULTIBASE_BASE64URL = "u";

/**
 * Refuse to inflate an untrusted list beyond this. A GZIP bomb could otherwise
 * expand to gigabytes; a legitimate status list is 16KB..a few MB.
 */
const MAX_DECODED_BYTES = 16 * 1024 * 1024;

export class BitstringError extends Error {
  constructor(
    message: string,
    /** Spec error code where one applies (RANGE_ERROR, STATUS_LIST_LENGTH_ERROR). */
    readonly code?: string,
  ) {
    super(message);
    this.name = "BitstringError";
  }
}

/**
 * A fixed-size bit array with W3C index semantics. Status size is 1 bit
 * (revocation/suspension are boolean purposes).
 */
export class Bitstring {
  private readonly bytes: Uint8Array;

  /** @param entries number of 1-bit entries; defaults to the 16KB minimum. */
  constructor(entries: number = MINIMUM_ENTRIES) {
    if (!Number.isSafeInteger(entries) || entries <= 0) {
      throw new BitstringError(`invalid entry count: ${entries}`);
    }
    if (entries % 8 !== 0) {
      throw new BitstringError("entry count must be a multiple of 8 (whole bytes)");
    }
    this.bytes = new Uint8Array(entries / 8);
  }

  /** Total 1-bit entries addressable in this list. */
  get length(): number {
    return this.bytes.length * 8;
  }

  private locate(index: number): { byte: number; mask: number } {
    if (!Number.isSafeInteger(index) || index < 0 || index >= this.length) {
      throw new BitstringError(
        `index ${index} is outside the bitstring (length ${this.length})`,
        "RANGE_ERROR",
      );
    }
    // Index 0 => most-significant bit of byte 0.
    return { byte: index >>> 3, mask: 0b1000_0000 >>> (index & 7) };
  }

  get(index: number): boolean {
    const { byte, mask } = this.locate(index);
    return (this.bytes[byte]! & mask) !== 0;
  }

  set(index: number, value: boolean): void {
    const { byte, mask } = this.locate(index);
    if (value) this.bytes[byte]! |= mask;
    else this.bytes[byte]! &= ~mask & 0xff;
  }

  /** Indices currently set — for diagnostics and audit summaries. */
  setIndices(): number[] {
    const out: number[] = [];
    for (let b = 0; b < this.bytes.length; b++) {
      const v = this.bytes[b]!;
      if (v === 0) continue;
      for (let bit = 0; bit < 8; bit++) {
        if ((v & (0b1000_0000 >>> bit)) !== 0) out.push(b * 8 + bit);
      }
    }
    return out;
  }

  /** §3.3: GZIP, then multibase base64url (no padding). */
  encode(): string {
    const gz = gzipSync(Buffer.from(this.bytes));
    return MULTIBASE_BASE64URL + gz.toString("base64url");
  }

  /** §3.4: multibase-decode, then GZIP-decompress. */
  static decode(encoded: string): Bitstring {
    if (typeof encoded !== "string" || encoded.length === 0) {
      throw new BitstringError("encodedList must be a non-empty string");
    }
    if (!encoded.startsWith(MULTIBASE_BASE64URL)) {
      throw new BitstringError(
        `encodedList must use the multibase base64url prefix "${MULTIBASE_BASE64URL}"`,
      );
    }
    const body = encoded.slice(1);
    if (!/^[A-Za-z0-9_-]*$/.test(body)) {
      throw new BitstringError("encodedList is not valid base64url (no padding)");
    }
    let raw: Buffer;
    try {
      raw = gunzipSync(Buffer.from(body, "base64url"), {
        maxOutputLength: MAX_DECODED_BYTES,
      });
    } catch (err) {
      throw new BitstringError(
        `encodedList could not be decompressed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    if (raw.length === 0) {
      throw new BitstringError("encodedList decoded to an empty bitstring");
    }
    const bs = new Bitstring(raw.length * 8);
    bs.bytes.set(raw);
    return bs;
  }
}
