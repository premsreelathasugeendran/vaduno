import {
  createPrivateKey,
  createPublicKey,
  sign as edSign,
  verify as edVerify,
} from "node:crypto";
import {
  checkedSign,
  MLDSA44_SIGNATURE_BYTES,
  nativeMlDsa44Ops,
  PqUnavailableError,
  rawMlDsa44PublicKey,
  type Ed25519Signer,
  type MlDsa44Ops,
} from "@vaduno/guard";
import {
  SIG_TYPE_COSIGNATURE_V1,
  SIG_TYPE_COSIGNATURE_MLDSA44,
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

/**
 * `cosignCheckpoint` through a non-exportable Ed25519Signer (KMS/HSM) — a
 * witness whose cosigning key never leaves its HSM. Signs the exact
 * tlog-cosignature v1 payload; byte-identical to the sync path for the same
 * key and timestamp. Signer failures reject via `checkedSign` — a witness
 * whose signer is down cosigns nothing, it never emits an unverified line.
 */
export async function cosignCheckpointWith(
  note: string | ParsedNote,
  opts: {
    name: string;
    signer: Ed25519Signer;
    /** POSIX seconds; defaults to now. */
    timestamp?: number;
    timeoutMs?: number;
  },
): Promise<CosignatureRecord> {
  const parsed = typeof note === "string" ? parseNote(note) : note;
  const timestamp = opts.timestamp ?? Math.floor(Date.now() / 1000);
  const payload = cosignaturePayload(parsed.body, timestamp);
  const sig = await checkedSign(
    opts.signer,
    payload,
    opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {},
  );
  const id = keyId(
    opts.name,
    SIG_TYPE_COSIGNATURE_V1,
    rawEd25519PublicKey(opts.signer.publicKeyPem),
  );
  const blob = Buffer.concat([encodeTimestamp(timestamp), sig]);
  return { name: opts.name, line: signatureLine(opts.name, id, blob), timestamp };
}

/**
 * The exact bytes an ML-DSA-44 (0x06) cosignature signs — per C2SP
 * tlog-cosignature this is a BINARY STRUCTURE, not a variant of the 0x04
 * text payload, which is why it is a separate builder and not a branch
 * inside `cosignaturePayload`:
 *
 *   struct {
 *     u8     label[12] = "subtree/v1\n\0";
 *     opaque cosigner_name<1..255>;      // 1-byte length prefix
 *     uint64 timestamp;                  // big-endian POSIX seconds
 *     opaque log_origin<1..255>;         // 1-byte length prefix
 *     uint64 start;                      // MUST be 0 for checkpoints
 *     uint64 end;                        // = tree size
 *     u8     hash[32];                   // RAW root hash, not base64
 *   }
 *
 * WITNESSING ASYMMETRY, stated rather than hidden: this struct covers the
 * checkpoint's (origin, size, root) — it does NOT cover extension lines,
 * while the 0x04 text payload signs the FULL note body including them. A
 * "witnessed-pq" verdict therefore attests TREE STATE only; equivocation
 * hidden in extension lines is witnessed only classically. (Vaduno's own
 * checkpoints carry no extension lines, and checkpointBody documents them
 * as NOT RECOMMENDED — but third-party notes may differ, so the limit is
 * part of the contract.)
 */
export function mlDsa44CosignaturePayload(opts: {
  cosignerName: string;
  /** POSIX seconds, uint64 big-endian. */
  timestamp: number;
  origin: string;
  treeSize: number;
  /** Root hash as 64 lowercase hex chars; encoded RAW (32 bytes). */
  rootHash: string;
}): Buffer {
  const label = Buffer.from("subtree/v1\n\0", "latin1");
  if (label.length !== 12) throw new CheckpointError("internal: bad subtree label");
  const name = Buffer.from(opts.cosignerName, "utf8");
  if (name.length < 1 || name.length > 255) {
    throw new CheckpointError("cosigner name must be 1..255 bytes");
  }
  const origin = Buffer.from(opts.origin, "utf8");
  if (origin.length < 1 || origin.length > 255) {
    throw new CheckpointError("log origin must be 1..255 bytes");
  }
  if (!Number.isSafeInteger(opts.treeSize) || opts.treeSize < 0) {
    throw new CheckpointError(`invalid tree size: ${opts.treeSize}`);
  }
  if (!Number.isSafeInteger(opts.timestamp) || opts.timestamp < 0) {
    throw new CheckpointError(`invalid cosignature timestamp: ${opts.timestamp}`);
  }
  if (!/^[0-9a-f]{64}$/.test(opts.rootHash)) {
    throw new CheckpointError("rootHash must be 64 lowercase hex chars (32-byte SHA-256)");
  }
  const u64 = (v: number): Buffer => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(BigInt(v));
    return b;
  };
  return Buffer.concat([
    label,
    Buffer.from([name.length]),
    name,
    u64(opts.timestamp),
    Buffer.from([origin.length]),
    origin,
    u64(0), // start: MUST be 0 for checkpoints (whole-tree subtree)
    u64(opts.treeSize), // end
    Buffer.from(opts.rootHash, "hex"),
  ]);
}

/**
 * Produce an ML-DSA-44 (0x06) witness cosignature for a checkpoint note.
 * Raw cryptographic step, like `cosignCheckpoint` — consistency checking is
 * the witness protocol's job (witness.ts): run `witnessCosign` first for the
 * refuse-inconsistent-history decision, then call this with the same note to
 * add the PQ line.
 *
 * SIGNING REQUIRES the runtime capability: with no native ML-DSA (and no
 * injected ops) this throws a typed `PqUnavailableError` — it never silently
 * falls back to a classical signature. The signature is verified against the
 * declared public key before a line is emitted (checkedSign's discipline).
 */
export function cosignCheckpointMlDsa44(
  note: string | ParsedNote,
  opts: {
    name: string;
    privateKeyPem: string;
    publicKeyPem: string;
    /** POSIX seconds; defaults to now. */
    timestamp?: number;
    /** Capability override for tests; defaults to the runtime probe. */
    pq?: MlDsa44Ops | null;
  },
): CosignatureRecord {
  const pq = opts.pq !== undefined ? opts.pq : nativeMlDsa44Ops();
  if (pq === null) throw new PqUnavailableError();
  const parsed = typeof note === "string" ? parseNote(note) : note;
  const timestamp = opts.timestamp ?? Math.floor(Date.now() / 1000);
  const payload = mlDsa44CosignaturePayload({
    cosignerName: opts.name,
    timestamp,
    origin: parsed.checkpoint.origin,
    treeSize: parsed.checkpoint.treeSize,
    rootHash: parsed.checkpoint.rootHash,
  });
  const sig = pq.sign(payload, opts.privateKeyPem);
  if (
    sig.length !== MLDSA44_SIGNATURE_BYTES ||
    !pq.verify(payload, opts.publicKeyPem, sig)
  ) {
    throw new CheckpointError(
      "ML-DSA-44 cosignature does not verify against the declared public key — refusing to emit it",
    );
  }
  const id = keyId(
    opts.name,
    SIG_TYPE_COSIGNATURE_MLDSA44,
    rawMlDsa44PublicKey(opts.publicKeyPem),
  );
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
  /** Ed25519 cosigning key (0x04 lines). Optional only when an ML-DSA-44 key
   * is given — a witness must have at least one usable key. */
  publicKeyPem?: string;
  /** ML-DSA-44 cosigning key (0x06 lines). The SAME witness may hold both;
   * they count as ONE party toward any quorum. */
  mlDsa44PublicKeyPem?: string;
}

/** Which signature type a verified cosignature came from. */
export type CosignatureAlg = "Ed25519" | "ML-DSA-44";

export interface VerifiedCosignature {
  name: string;
  timestamp: number;
  alg: CosignatureAlg;
}

/**
 * ARCHIVAL SEMANTICS — read this before passing bounds.
 *
 * Evidence verification is TEMPORAL-PRECEDENCE-based, not freshness-based.
 * A cosignature attests "this witness saw this checkpoint no later than T";
 * that statement does not decay. An EvidenceBundle or dispute packet is
 * verified months or years after the fact — that is the entire point of the
 * evidence layer — so BY DEFAULT there is NO staleness bound: only the
 * future-skew rejection applies (a timestamp ahead of the verifier's clock is
 * implausible at any age, and accepting it would let a cosignature claim a
 * witness time that has not happened yet).
 *
 * Freshness is a LIVENESS property and is opt-in: pass `maxAgeSeconds` when
 * you are deciding whether a log is still alive and publishing (an operator
 * who stops publishing can otherwise serve one old, validly-cosigned
 * checkpoint forever). Do not pass it when verifying archival evidence.
 */
export interface CosignatureVerifyOptions {
  /**
   * Reject cosignatures timestamped further ahead of the verifier's clock
   * than this (seconds). Default 300. Must be finite and >= 0 — an infinite
   * skew would disable the one temporal check archival verification keeps,
   * so it fails closed instead.
   */
  maxClockSkewSeconds?: number;
  /**
   * OPT-IN liveness bound: reject cosignatures older than this (seconds).
   * Default `Infinity` — unbounded age, the archival semantics above.
   * `Infinity` is the explicit way to spell "unbounded"; NaN or a negative
   * value fails closed (verifies nothing).
   */
  maxAgeSeconds?: number;
  /** Injectable clock (POSIX seconds). */
  nowSeconds?: () => number;
  /**
   * ML-DSA-44 capability. Defaults to the runtime probe
   * (`nativeMlDsa44Ops()`). On a runtime without native ML-DSA, 0x06
   * cosignatures are IGNORED (they simply do not appear in the result and
   * the note rests on its 0x04 cosignatures) rather than fatal — the
   * signed-note spec ignores unusable signatures, and a fatal treatment
   * would let one byzantine witness's garbage line veto everyone's quorum.
   * This cannot upgrade anything: labels and witness times computed from
   * cosignatures (`assessCheckpointAnchor`) only ever count what VERIFIED.
   * Tests may pass a deterministic fake, or `null` to force the no-PQ path.
   */
  pq?: MlDsa44Ops | null;
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

interface TimeBounds {
  now: number;
  skew: number;
  maxAge: number;
}

/** Timestamp acceptance shared by both cosignature types. */
function timestampAcceptable(timestamp: number, bounds: TimeBounds): boolean {
  if (timestamp > bounds.now + bounds.skew) return false; // implausibly future
  if (timestamp < bounds.now - bounds.maxAge) return false; // stale (opt-in bound)
  return true;
}

function verifyOneEd25519Cosignature(
  parsed: ParsedNote,
  witness: KnownWitness,
  bounds: TimeBounds,
): VerifiedCosignature | null {
  if (witness.publicKeyPem === undefined) return null;
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
    if (!timestampAcceptable(timestamp, bounds)) continue;
    const raw = sig.signature.subarray(TIMESTAMP_BYTES);
    let ok = false;
    try {
      ok = edVerify(null, cosignaturePayload(parsed.body, timestamp), key, raw);
    } catch {
      ok = false;
    }
    if (ok) return { name: witness.name, timestamp, alg: "Ed25519" };
  }
  return null;
}

function verifyOneMlDsa44Cosignature(
  parsed: ParsedNote,
  witness: KnownWitness,
  bounds: TimeBounds,
  pq: MlDsa44Ops,
): VerifiedCosignature | null {
  if (witness.mlDsa44PublicKeyPem === undefined) return null;
  let expectedId: string;
  try {
    expectedId = keyId(
      witness.name,
      SIG_TYPE_COSIGNATURE_MLDSA44,
      rawMlDsa44PublicKey(witness.mlDsa44PublicKeyPem),
    );
  } catch {
    return null;
  }
  for (const sig of parsed.signatures) {
    if (sig.name !== witness.name || sig.keyId !== expectedId) continue;
    if (sig.signature.length !== TIMESTAMP_BYTES + MLDSA44_SIGNATURE_BYTES) continue;
    const tsRaw = sig.signature.readBigUInt64BE(0);
    if (tsRaw > BigInt(Number.MAX_SAFE_INTEGER)) continue;
    const timestamp = Number(tsRaw);
    if (!timestampAcceptable(timestamp, bounds)) continue;
    const raw = sig.signature.subarray(TIMESTAMP_BYTES);
    let payload: Buffer;
    try {
      payload = mlDsa44CosignaturePayload({
        cosignerName: witness.name,
        timestamp,
        origin: parsed.checkpoint.origin,
        treeSize: parsed.checkpoint.treeSize,
        rootHash: parsed.checkpoint.rootHash,
      });
    } catch {
      continue;
    }
    if (pq.verify(payload, witness.mlDsa44PublicKeyPem, raw)) {
      return { name: witness.name, timestamp, alg: "ML-DSA-44" };
    }
  }
  return null;
}

/**
 * Verify which of `witnesses` cosigned this checkpoint. Fails closed: an
 * unparseable note, a future-dated cosignature, a cosignature older than an
 * OPT-IN `maxAgeSeconds` bound, a wrong-length blob, or a bad signature
 * simply does not appear in the result. By default age is UNBOUNDED — see
 * `CosignatureVerifyOptions` for the archival semantics.
 *
 * Returns at most one entry per witness NAME per ALGORITHM (a witness
 * holding both key types can contribute one 0x04 and one 0x06 entry — still
 * ONE party for quorum purposes). 0x06 entries appear only when the runtime
 * (or an injected `opts.pq`) can verify ML-DSA-44; otherwise they are
 * ignored and the note rests on its Ed25519 cosignatures.
 *
 * `.length >= k` is NOT a safe quorum test — use `checkCosignatureQuorum`,
 * which counts distinct PARTIES and binds the checkpoint to your log.
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
  // A broken clock must not silently disable the future-skew check.
  if (!Number.isFinite(rawNow)) return [];
  const bounds: TimeBounds = {
    now: Math.floor(rawNow),
    // Unbounded age is the ARCHIVAL default; Infinity is also the explicit
    // spelling of "unbounded". NaN and negatives fail closed below.
    maxAge: opts.maxAgeSeconds ?? Infinity,
    skew: opts.maxClockSkewSeconds ?? 300,
  };
  // skew must be FINITE (an infinite skew would disable the one temporal
  // check archival verification keeps); maxAge may be Infinity but must not
  // be NaN or negative. Anything else verifies nothing.
  if (!Number.isFinite(bounds.skew) || bounds.skew < 0) return [];
  if (Number.isNaN(bounds.maxAge) || bounds.maxAge < 0) return [];

  const pq = opts.pq !== undefined ? opts.pq : nativeMlDsa44Ops();

  const seen = new Set<string>();
  const verified: VerifiedCosignature[] = [];
  for (const witness of witnesses) {
    if (seen.has(witness.name)) continue;
    seen.add(witness.name);
    const ed = verifyOneEd25519Cosignature(parsed, witness, bounds);
    if (ed) verified.push(ed);
    if (pq !== null) {
      const ml = verifyOneMlDsa44Cosignature(parsed, witness, bounds, pq);
      if (ml) verified.push(ml);
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

/**
 * Stable identities of a witness's key material, for independence counting.
 * Family-prefixed so an Ed25519 key and an ML-DSA key can never alias each
 * other by byte coincidence.
 */
function keyFingerprints(w: KnownWitness): string[] {
  const fps: string[] = [];
  if (w.publicKeyPem !== undefined) {
    try {
      fps.push("ed25519:" + rawEd25519PublicKey(w.publicKeyPem).toString("hex"));
    } catch {
      /* unusable key contributes nothing */
    }
  }
  if (w.mlDsa44PublicKeyPem !== undefined) {
    try {
      fps.push("ml-dsa-44:" + rawMlDsa44PublicKey(w.mlDsa44PublicKeyPem).toString("hex"));
    } catch {
      /* unusable key contributes nothing */
    }
  }
  return fps;
}

/**
 * Group witness NAMES into PARTIES by key material: names sharing ANY key
 * (either family) are one party. A witness with no usable key belongs to no
 * party and can never count toward a quorum.
 */
function groupParties(unique: Map<string, KnownWitness>): {
  nameToParty: Map<string, number>;
  partyCount: number;
  duplicateKeys: string[];
} {
  const fpToParty = new Map<string, number>();
  const nameToParty = new Map<string, number>();
  const partyToNames = new Map<number, string[]>();
  let nextParty = 0;
  for (const w of unique.values()) {
    const fps = keyFingerprints(w);
    if (fps.length === 0) continue;
    let party: number | undefined;
    for (const fp of fps) {
      const existing = fpToParty.get(fp);
      if (existing !== undefined) {
        party = existing;
        break;
      }
    }
    if (party === undefined) party = nextParty++;
    for (const fp of fps) fpToParty.set(fp, party);
    nameToParty.set(w.name, party);
    const list = partyToNames.get(party);
    if (list) list.push(w.name);
    else partyToNames.set(party, [w.name]);
  }
  const duplicateKeys = [...partyToNames.values()]
    .filter((ns) => ns.length > 1)
    .flat()
    .sort();
  return { nameToParty, partyCount: partyToNames.size, duplicateKeys };
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
 * Independence is counted by KEY MATERIAL, not by name: key IDs are
 * name-derived, so a single party holding one private key could otherwise
 * mint valid cosignature lines under k names and fill a quorum alone. A
 * witness's Ed25519 and ML-DSA-44 keys count as ONE party, whichever (or
 * both) of them cosigned.
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

  const { nameToParty, partyCount: distinctParties, duplicateKeys } = groupParties(unique);
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
  const seenParties = new Set<number>();
  for (const v of verified) {
    const party = nameToParty.get(v.name);
    if (party !== undefined) seenParties.add(party);
  }
  const missing = names.filter((n) => !seenNames.has(n));
  const ok = seenParties.size >= k;
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
      ? `${seenParties.size} of ${k} required independent witness cosignatures verified${dupeNote}`
      : `only ${seenParties.size} of ${k} required independent witness cosignatures verified (missing: ${missing.join(", ") || "none"})${dupeNote}`,
  };
}

export type AnchorStrength = "unwitnessed" | "witnessed" | "witnessed-pq";

/**
 * How strongly a checkpoint is anchored, for ARCHIVAL evidence: which quorum
 * it reaches and since WHEN it can be said to have been witnessed.
 */
export interface AnchorAssessment {
  /**
   * "witnessed-pq"  — a k-party quorum of VERIFIED ML-DSA-44 (0x06)
   *                   cosignatures. Holds against a future adversary who can
   *                   forge Ed25519 but not ML-DSA-44.
   * "witnessed"     — a k-party quorum of verified cosignatures of any type,
   *                   but not a PQ-only quorum. Post-CRQC, Ed25519
   *                   cosignatures are forgeable, so this label's value
   *                   decays with Ed25519 itself.
   * "unwitnessed"   — no quorum at all.
   *
   * A verifier that CANNOT verify ML-DSA-44 (no native support, no injected
   * ops) can never report "witnessed-pq" — unverifiable 0x06 lines are
   * ignored, and honesty about that is the anti-downgrade property: nothing
   * unverifiable ever upgrades a label.
   */
  strength: AnchorStrength;
  /**
   * Earliest timestamp among VERIFIED cosignatures AT LEAST AS STRONG as
   * `strength` — for "witnessed-pq" that means 0x06 cosignatures ONLY.
   *
   * Never the earliest across all algorithms: a post-CRQC attacker who can
   * forge Ed25519 could append a 0x04 line with an arbitrarily BACKDATED
   * timestamp to a witnessed-pq note and silently move its claimed witness
   * time earlier. Scoping the minimum to the reported strength closes that
   * (the label-upgrade/witnessedAt-poisoning attack test pins it).
   *
   * Null when unwitnessed.
   */
  witnessedAt: number | null;
  /** Quorum over cosignatures of ANY type (0x04 and 0x06). */
  classical: QuorumResult;
  /** Quorum over 0x06 cosignatures ONLY. Fails closed where ML-DSA-44
   * cannot be verified. */
  pq: QuorumResult;
}

/**
 * Assess a checkpoint's witness anchoring at both strengths. Same required
 * log binding as `checkCosignatureQuorum`; same archival time semantics as
 * `verifyCosignatures` (unbounded age by default, future-skew still
 * rejected).
 *
 * Remember the witnessing asymmetry (see `mlDsa44CosignaturePayload`): the
 * PQ struct covers (origin, size, root) only, so "witnessed-pq" attests tree
 * state; extension lines are witnessed only classically.
 */
export function assessCheckpointAnchor(
  note: string,
  witnesses: readonly KnownWitness[],
  k: number,
  binding: LogBinding,
  opts: CosignatureVerifyOptions = {},
): AnchorAssessment {
  const classical = checkCosignatureQuorum(note, witnesses, k, binding, opts);
  // The PQ quorum re-runs the same bound checks over PQ-only witness entries
  // so its party counting, duplicate detection and unreachable-quorum guard
  // all apply to the PQ key set alone.
  const pqWitnesses = witnesses
    .filter((w) => w.mlDsa44PublicKeyPem !== undefined)
    .map((w) => {
      const entry: KnownWitness = { name: w.name };
      entry.mlDsa44PublicKeyPem = w.mlDsa44PublicKeyPem!;
      return entry;
    });
  const pq = checkCosignatureQuorum(note, pqWitnesses, k, binding, opts);
  const strength: AnchorStrength = pq.ok ? "witnessed-pq" : classical.ok ? "witnessed" : "unwitnessed";
  let witnessedAt: number | null = null;
  if (strength === "witnessed-pq") {
    // 0x06 timestamps ONLY — see the field docs for the attack this blocks.
    witnessedAt = pq.verified
      .filter((v) => v.alg === "ML-DSA-44")
      .reduce<number | null>((min, v) => (min === null || v.timestamp < min ? v.timestamp : min), null);
  } else if (strength === "witnessed") {
    witnessedAt = classical.verified.reduce<number | null>(
      (min, v) => (min === null || v.timestamp < min ? v.timestamp : min),
      null,
    );
  }
  return { strength, witnessedAt, classical, pq };
}
