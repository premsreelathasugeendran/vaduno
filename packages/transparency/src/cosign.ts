import {
  createPrivateKey,
  createPublicKey,
  sign as edSign,
  verify as edVerify,
} from "node:crypto";
import {
  SIG_TYPE_COSIGNATURE_V1,
  CheckpointError,
  keyId,
  parseNote,
  rawEd25519PublicKey,
  signatureLine,
  verifyNoteSignature,
  type Checkpoint,
  type ParsedNote,
} from "./checkpoint.js";

/**
 * C2SP tlog-cosignature v1 — a witness's timestamped attestation that it saw
 * this checkpoint AND that the checkpoint was append-only consistent with
 * everything it had seen before.
 *
 * WHY THIS EXISTS: a log operator's own signature proves authorship, not
 * honesty. A malicious operator can sign TWO different histories and show one
 * to you and another to someone else (equivocation / split view) — every
 * signature verifies, every consistency proof passes, and nothing in the log's
 * own math catches it. Cosignatures are the fix: if k independent witnesses
 * each refuse to cosign a checkpoint that contradicts what they already
 * signed, an equivocating operator cannot reach quorum without k witnesses
 * colluding.
 *
 * HONEST LIMITS, stated up front:
 *  - Witnessing gives NON-EQUIVOCATION, not completeness or truth. It proves
 *    everyone sees the SAME log; it does not prove the log contains every
 *    event that happened (pair it with log-before-authorize).
 *  - A "witness" you run yourself is not independent. One operator holding all
 *    the witness keys adds exactly zero assurance. Quorum counts distinct
 *    KEYS, which catches the same key twice — it cannot catch one operator
 *    running several distinct keys. That remains a SOCIAL property.
 *
 * WIRE FORMAT (this is easy to get wrong, and getting it wrong silently
 * breaks interop in both directions):
 *
 *   signature line  = "— " <name> " " base64( keyID[4] || timestamp[8] || sig )
 *   timestamp       = uint64 POSIX seconds, BIG-ENDIAN (RFC 8446 §3.3 order)
 *   signed message  = "cosignature/v1\n" + "time <seconds>\n" + <note body>
 *
 * The timestamp therefore travels INSIDE the note; there is no side-channel
 * to keep in sync and nothing to lose.
 */

const COSIG_HEADER = "cosignature/v1\n";
/** uint64 big-endian timestamp precedes the signature bytes. */
const TIMESTAMP_BYTES = 8;
/** Ed25519 signatures are 64 bytes. */
const ED25519_SIG_BYTES = 64;
/** POSIX seconds must fit in a signed 64-bit int per the spec. */
const MAX_TIMESTAMP = 2n ** 63n - 1n;

/** What a witness returns when it agrees to cosign. */
export interface CosignatureRecord {
  name: string;
  /** The `— name base64(...)` line to append to the note. */
  line: string;
  /** POSIX seconds baked into the signed payload (also carried in the line). */
  timestamp: number;
}

/** The exact bytes a witness signs. */
export function cosignaturePayload(body: string, timestamp: number): Buffer {
  if (!body.endsWith("\n")) {
    throw new CheckpointError("checkpoint body must end with a newline");
  }
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
    throw new CheckpointError(`invalid cosignature timestamp: ${timestamp}`);
  }
  return Buffer.from(`${COSIG_HEADER}time ${timestamp}\n${body}`, "utf8");
}

function encodeTimestamp(timestamp: number): Buffer {
  const b = Buffer.alloc(TIMESTAMP_BYTES);
  const v = BigInt(timestamp);
  if (v < 0n || v > MAX_TIMESTAMP) {
    throw new CheckpointError(`cosignature timestamp out of range: ${timestamp}`);
  }
  b.writeBigUInt64BE(v);
  return b;
}

/**
 * Produce a witness cosignature for a checkpoint note. This is the raw
 * cryptographic step and does NOT check consistency — use `witnessCosign`
 * (witness.ts) for the full protocol, which refuses to cosign a checkpoint
 * that contradicts what the witness already cosigned.
 */
export function cosignCheckpoint(
  note: string | ParsedNote,
  opts: {
    name: string;
    privateKeyPem: string;
    publicKeyPem: string;
    /** POSIX seconds; defaults to now. */
    timestamp?: number;
  },
): CosignatureRecord {
  const parsed = typeof note === "string" ? parseNote(note) : note;
  const timestamp = opts.timestamp ?? Math.floor(Date.now() / 1000);
  const payload = cosignaturePayload(parsed.body, timestamp);
  const sig = edSign(null, payload, createPrivateKey(opts.privateKeyPem));
  const id = keyId(
    opts.name,
    SIG_TYPE_COSIGNATURE_V1,
    rawEd25519PublicKey(opts.publicKeyPem),
  );
  // Blob = keyID || uint64BE timestamp || signature.
  const blob = Buffer.concat([encodeTimestamp(timestamp), sig]);
  return { name: opts.name, line: signatureLine(opts.name, id, blob), timestamp };
}

/** Append cosignature lines to a note. */
export function attachCosignatures(
  note: string,
  records: readonly CosignatureRecord[],
): string {
  if (!note.endsWith("\n")) {
    throw new CheckpointError("note must end with a newline");
  }
  let out = note;
  for (const r of records) {
    out += r.line.endsWith("\n") ? r.line : r.line + "\n";
  }
  return out;
}

export interface KnownWitness {
  /** Must match the name on the signature line exactly. */
  name: string;
  publicKeyPem: string;
}

export interface VerifiedCosignature {
  name: string;
  timestamp: number;
}

export interface CosignatureVerifyOptions {
  /**
   * Reject cosignatures timestamped further ahead than this (seconds). A
   * witness clock slightly ahead is normal; a wildly future timestamp would
   * let a cosignature look fresh long after it should have expired.
   */
  maxClockSkewSeconds?: number;
  /**
   * Reject cosignatures older than this (seconds). Freshness is the point of
   * a timestamped cosignature: without it, an operator who simply stops
   * publishing can keep serving one old, validly-cosigned checkpoint forever.
   */
  maxAgeSeconds?: number;
  /** Injectable clock (POSIX seconds). */
  nowSeconds?: () => number;
}

/**
 * Binding a quorum to THIS log. Required, not optional: witness cosignatures
 * attest "this is the log I have been following" — they say nothing about
 * WHICH log that is, and public witnesses cosign many logs under one key.
 * Without this binding an operator can stand up a second origin, let honest
 * witnesses cosign it at trust-on-first-use, and serve the result as though
 * it were this log.
 */
export interface LogBinding {
  /** The origin line this relying party follows. */
  origin: string;
  /** The log's own Ed25519 public key. */
  logPublicKeyPem: string;
  /** Name on the log's signature line (defaults to `origin`). */
  logKeyName?: string;
}

function verifyOneCosignature(
  parsed: ParsedNote,
  witness: KnownWitness,
  bounds: { now: number; skew: number; maxAge: number },
): VerifiedCosignature | null {
  let expectedId: string;
  let key;
  try {
    expectedId = keyId(
      witness.name,
      SIG_TYPE_COSIGNATURE_V1,
      rawEd25519PublicKey(witness.publicKeyPem),
    );
    key = createPublicKey(witness.publicKeyPem);
  } catch {
    return null;
  }
  for (const sig of parsed.signatures) {
    if (sig.name !== witness.name || sig.keyId !== expectedId) continue;
    // Blob after the key ID is: uint64BE timestamp || signature.
    if (sig.signature.length !== TIMESTAMP_BYTES + ED25519_SIG_BYTES) continue;
    const tsRaw = sig.signature.readBigUInt64BE(0);
    if (tsRaw > BigInt(Number.MAX_SAFE_INTEGER)) continue;
    const timestamp = Number(tsRaw);
    if (timestamp > bounds.now + bounds.skew) continue; // implausibly future
    if (timestamp < bounds.now - bounds.maxAge) continue; // stale
    const raw = sig.signature.subarray(TIMESTAMP_BYTES);
    let ok = false;
    try {
      ok = edVerify(null, cosignaturePayload(parsed.body, timestamp), key, raw);
    } catch {
      ok = false;
    }
    if (ok) return { name: witness.name, timestamp };
  }
  return null;
}

/**
 * Verify which of `witnesses` cosigned this checkpoint. Fails closed: an
 * unparseable note, a stale or future-dated cosignature, a wrong-length blob,
 * or a bad signature simply does not appear in the result.
 *
 * Returns at most ONE entry per witness NAME. Note that `.length >= k` is
 * still not a safe quorum test — use `checkCosignatureQuorum`, which counts
 * distinct KEYS and binds the checkpoint to your log.
 */
export function verifyCosignatures(
  note: string,
  witnesses: readonly KnownWitness[],
  opts: CosignatureVerifyOptions = {},
): VerifiedCosignature[] {
  let parsed: ParsedNote;
  try {
    parsed = parseNote(note);
  } catch {
    return [];
  }
  const rawNow = opts.nowSeconds ? opts.nowSeconds() : Math.floor(Date.now() / 1000);
  // A broken clock must not silently disable the freshness checks.
  if (!Number.isFinite(rawNow)) return [];
  const bounds = {
    now: Math.floor(rawNow),
    maxAge: opts.maxAgeSeconds ?? 24 * 60 * 60,
    skew: opts.maxClockSkewSeconds ?? 300,
  };
  if (!Number.isFinite(bounds.maxAge) || !Number.isFinite(bounds.skew)) return [];

  const seen = new Set<string>();
  const verified: VerifiedCosignature[] = [];
  for (const witness of witnesses) {
    if (seen.has(witness.name)) continue;
    const v = verifyOneCosignature(parsed, witness, bounds);
    if (v) {
      seen.add(witness.name);
      verified.push(v);
    }
  }
  return verified;
}

export interface QuorumResult {
  /** True when at least `k` DISTINCT witness KEYS cosigned. */
  ok: boolean;
  required: number;
  verified: VerifiedCosignature[];
  /** Known witnesses that did not produce a verifiable cosignature. */
  missing: string[];
  /**
   * Configured witness names that share a public key with another entry —
   * i.e. the SAME party under several names. They count ONCE toward the
   * quorum, and are listed because such a config is almost certainly a
   * mistake (or an attempt to fake independence).
   */
  duplicateKeys: string[];
  /**
   * The checkpoint this quorum actually attests to — present only when the
   * result is `ok`. Consume THIS rather than re-parsing the raw note, so the
   * value you act on is the value that was verified.
   */
  checkpoint?: Checkpoint;
  message: string;
}

/** Stable identity of a witness's key material, for independence counting. */
function keyFingerprint(publicKeyPem: string): string | null {
  try {
    return rawEd25519PublicKey(publicKeyPem).toString("hex");
  } catch {
    return null;
  }
}

/**
 * The policy check a relying party actually runs: "does this checkpoint, from
 * MY log, carry at least k INDEPENDENT witness cosignatures?"
 *
 * Two bindings are enforced before any cosignature is counted, because a
 * quorum on somebody else's log is not a quorum on yours:
 *   1. the checkpoint's origin must equal `binding.origin`; and
 *   2. the note must carry the LOG's own valid signature.
 * Both are required arguments — this check fails closed by construction
 * rather than by remembering to opt in.
 *
 * Independence is counted by KEY, not by name: key IDs are name-derived, so a
 * single party holding one private key could otherwise mint valid cosignature
 * lines under k names and fill a quorum alone.
 */
export function checkCosignatureQuorum(
  note: string,
  witnesses: readonly KnownWitness[],
  k: number,
  binding: LogBinding,
  opts: CosignatureVerifyOptions = {},
): QuorumResult {
  const unique = new Map<string, KnownWitness>();
  for (const w of witnesses) if (!unique.has(w.name)) unique.set(w.name, w);
  const names = [...unique.keys()];

  // Group names by key material; each distinct key is one party.
  const nameToKey = new Map<string, string>();
  const keyToNames = new Map<string, string[]>();
  for (const w of unique.values()) {
    const fp = keyFingerprint(w.publicKeyPem);
    if (fp === null) continue; // unusable key cannot count toward a quorum
    nameToKey.set(w.name, fp);
    const list = keyToNames.get(fp);
    if (list) list.push(w.name);
    else keyToNames.set(fp, [w.name]);
  }
  const duplicateKeys = [...keyToNames.values()]
    .filter((ns) => ns.length > 1)
    .flat()
    .sort();
  const distinctParties = keyToNames.size;
  const fail = (message: string): QuorumResult => ({
    ok: false,
    required: k,
    verified: [],
    missing: names,
    duplicateKeys,
    message,
  });

  if (!binding || typeof binding.origin !== "string" || binding.origin.length === 0) {
    return fail("a LogBinding with an origin is required");
  }
  if (typeof binding.logPublicKeyPem !== "string" || binding.logPublicKeyPem.length === 0) {
    return fail("a LogBinding with the log's public key is required");
  }
  if (!Number.isSafeInteger(k) || k < 1) {
    return fail(`invalid quorum threshold: ${k}`);
  }
  if (k > distinctParties) {
    return fail(
      `quorum of ${k} is unreachable: only ${distinctParties} independent witness key(s) configured` +
        (duplicateKeys.length > 0
          ? ` (these names share a key and count once: ${duplicateKeys.join(", ")})`
          : ""),
    );
  }

  let parsed: ParsedNote;
  try {
    parsed = parseNote(note);
  } catch (err) {
    return fail(
      `checkpoint could not be parsed: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (parsed.checkpoint.origin !== binding.origin) {
    return fail(
      `checkpoint origin "${parsed.checkpoint.origin}" != expected "${binding.origin}"`,
    );
  }
  const logName = binding.logKeyName ?? binding.origin;
  if (
    !verifyNoteSignature(parsed, {
      name: logName,
      publicKeyPem: binding.logPublicKeyPem,
    })
  ) {
    return fail(`checkpoint is not signed by the expected log key ("${logName}")`);
  }

  const verified = verifyCosignatures(note, [...unique.values()], opts);
  const seenNames = new Set(verified.map((v) => v.name));
  const seenKeys = new Set<string>();
  for (const v of verified) {
    const fp = nameToKey.get(v.name);
    if (fp !== undefined) seenKeys.add(fp);
  }
  const missing = names.filter((n) => !seenNames.has(n));
  const ok = seenKeys.size >= k;
  const dupeNote =
    duplicateKeys.length > 0
      ? ` — note: ${duplicateKeys.join(", ")} share a key and count as one party`
      : "";
  return {
    ok,
    required: k,
    verified,
    missing,
    duplicateKeys,
    ...(ok ? { checkpoint: parsed.checkpoint } : {}),
    message: ok
      ? `${seenKeys.size} of ${k} required independent witness cosignatures verified${dupeNote}`
      : `only ${seenKeys.size} of ${k} required independent witness cosignatures verified (missing: ${missing.join(", ") || "none"})${dupeNote}`,
  };
}
