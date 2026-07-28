import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from "node:crypto";

/**
 * C2SP signed-note + tlog-checkpoint encoding — the INTEROP format.
 *
 * Swale's own `SignedTreeHead` (sth.ts) is a JSON convenience shape. This
 * module speaks the format the transparency ecosystem actually uses (Go
 * sumdb notes, Sigsum, Trillian/tlog witnesses), so a third-party witness can
 * cosign a Swale log without any Swale-specific code.
 *
 * Note layout (signed-note):
 *
 *     <origin>\n
 *     <tree size>\n
 *     <base64 root hash>\n
 *     [extension lines...]\n
 *     \n                         <- blank line separates body from signatures
 *     — <key name> <base64(keyID||sig)>\n
 *     — <witness name> <base64(keyID||cosig)>\n
 *
 * The body (everything up to and including the blank-line separator's
 * preceding newline) is what gets signed.
 */

/** Signature type bytes from the signed-note spec. */
export const SIG_TYPE_ED25519 = 0x01;
/** Timestamped Ed25519 checkpoint cosignatures (tlog-cosignature v1). */
export const SIG_TYPE_COSIGNATURE_V1 = 0x04;

/** Em dash + space begins every signature line. */
const SIG_PREFIX = "— ";

/**
 * Bounds on an UNTRUSTED note. The witness/verify paths are reachable before
 * authentication, so a peer must not be able to make us do unbounded work: a
 * note with a million signature lines would otherwise cost a million
 * Ed25519 verifies (and the body is re-hashed for each attempt).
 */
const MAX_NOTE_BYTES = 1024 * 1024;
const MAX_SIGNATURE_LINES = 256;
/** RFC 6962 root hashes are SHA-256. */
const ROOT_HASH_BYTES = 32;
/** Root of the empty Merkle tree: SHA-256 of the empty string. */
export const EMPTY_TREE_ROOT_HEX =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

export class CheckpointError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CheckpointError";
  }
}

export interface Checkpoint {
  /** Log identity, e.g. "swale.example/ledger". */
  origin: string;
  treeSize: number;
  /** Root hash as lowercase hex (Swale's internal representation). */
  rootHash: string;
  /** Opaque extension lines. NOT RECOMMENDED — monitors cannot audit them. */
  extensions?: string[];
}

export interface NoteSignature {
  /** Key name from the signature line. */
  name: string;
  /** 4-byte key ID, big-endian, as lowercase hex. */
  keyId: string;
  /** Raw signature bytes (without the key ID prefix). */
  signature: Buffer;
}

export interface ParsedNote {
  checkpoint: Checkpoint;
  /** The exact body bytes that were signed (ends with a newline). */
  body: string;
  signatures: NoteSignature[];
  /**
   * Count of signature lines that could not be parsed. Per the signed-note
   * spec, unknown/unusable signatures are IGNORED rather than fatal — a
   * single byzantine witness appending garbage must not let it veto an
   * otherwise-valid k-of-n quorum for everyone else.
   */
  malformedSignatures: number;
}

/**
 * key ID = SHA-256(name || 0x0A || sigType || rawPublicKey)[:4]
 *
 * `sigType` distinguishes a log's own signature (0x01) from a witness
 * cosignature (0x04) — the SAME key under two roles yields two different IDs,
 * which is what stops a cosignature being replayed as a log signature.
 */
export function keyId(name: string, sigType: number, publicKeyRaw: Buffer): string {
  const h = createHash("sha256")
    .update(Buffer.from(name, "utf8"))
    .update(Buffer.from([0x0a]))
    .update(Buffer.from([sigType]))
    .update(publicKeyRaw)
    .digest();
  return h.subarray(0, 4).toString("hex");
}

/** Extract the 32 raw Ed25519 public key bytes from a PEM/KeyObject. */
export function rawEd25519PublicKey(publicKeyPem: string | KeyObject): Buffer {
  const key =
    typeof publicKeyPem === "string" ? createPublicKey(publicKeyPem) : publicKeyPem;
  // SPKI DER for Ed25519 is a fixed 44-byte structure; the key is the last 32.
  const der = key.export({ type: "spki", format: "der" });
  if (der.length < 32) {
    throw new CheckpointError("public key DER is too short to contain an Ed25519 key");
  }
  return Buffer.from(der.subarray(der.length - 32));
}

/**
 * Render the checkpoint body — the exact bytes that get signed. Ends with a
 * newline; the blank-line separator is added when assembling the full note.
 */
export function checkpointBody(cp: Checkpoint): string {
  if (cp.origin.length === 0 || cp.origin.includes("\n")) {
    throw new CheckpointError("origin must be a non-empty single line");
  }
  if (!Number.isSafeInteger(cp.treeSize) || cp.treeSize < 0) {
    throw new CheckpointError(`invalid tree size: ${cp.treeSize}`);
  }
  // RFC 6962/9162 roots are SHA-256: always exactly 32 bytes. Accepting other
  // lengths would let a short/long "root" be presented as a tree head.
  if (!/^[0-9a-f]{64}$/.test(cp.rootHash)) {
    throw new CheckpointError("rootHash must be 64 lowercase hex chars (32-byte SHA-256)");
  }
  const rootB64 = Buffer.from(cp.rootHash, "hex").toString("base64");
  let body = `${cp.origin}\n${cp.treeSize}\n${rootB64}\n`;
  for (const ext of cp.extensions ?? []) {
    if (ext.length === 0 || ext.includes("\n")) {
      throw new CheckpointError("extension lines must be non-empty single lines");
    }
    body += `${ext}\n`;
  }
  return body;
}

/** Assemble a full note from a body and its signature lines. */
export function assembleNote(body: string, signatureLines: readonly string[]): string {
  if (!body.endsWith("\n")) {
    throw new CheckpointError("note body must end with a newline");
  }
  return body + "\n" + signatureLines.map((l) => (l.endsWith("\n") ? l : l + "\n")).join("");
}

/** Build one `— name base64(keyID||sig)` line. */
export function signatureLine(name: string, keyIdHex: string, signature: Buffer): string {
  if (name.includes(" ") || name.includes("\n") || name.length === 0) {
    throw new CheckpointError("key name must be a non-empty string without spaces or newlines");
  }
  const payload = Buffer.concat([Buffer.from(keyIdHex, "hex"), signature]);
  return `${SIG_PREFIX}${name} ${payload.toString("base64")}\n`;
}

/**
 * Sign a checkpoint as the LOG (signature type 0x01). Returns the full note.
 */
export function signCheckpoint(
  cp: Checkpoint,
  opts: { name: string; privateKeyPem: string; publicKeyPem: string },
): string {
  const body = checkpointBody(cp);
  const sig = edSign(null, Buffer.from(body, "utf8"), createPrivateKey(opts.privateKeyPem));
  const id = keyId(opts.name, SIG_TYPE_ED25519, rawEd25519PublicKey(opts.publicKeyPem));
  return assembleNote(body, [signatureLine(opts.name, id, sig)]);
}

/**
 * Parse a note into its checkpoint, exact signed body, and signature lines.
 * Strict: a malformed note throws rather than being partially interpreted.
 */
export function parseNote(note: string): ParsedNote {
  if (typeof note !== "string" || note.length === 0) {
    throw new CheckpointError("note is empty");
  }
  if (Buffer.byteLength(note, "utf8") > MAX_NOTE_BYTES) {
    throw new CheckpointError(`note exceeds ${MAX_NOTE_BYTES} bytes`);
  }
  // The body ends at the first blank line (i.e. "\n\n").
  const sep = note.indexOf("\n\n");
  if (sep === -1) {
    throw new CheckpointError("note has no blank line separating body from signatures");
  }
  const body = note.slice(0, sep + 1);
  const sigBlock = note.slice(sep + 2);
  const bodyLines = body.split("\n");
  // body ends with "\n", so the final split element is "".
  bodyLines.pop();
  if (bodyLines.length < 3) {
    throw new CheckpointError("checkpoint body must have at least 3 lines");
  }
  const [origin, sizeLine, rootB64, ...extensions] = bodyLines as [
    string,
    string,
    string,
    ...string[],
  ];
  if (origin.length === 0) throw new CheckpointError("origin line is empty");
  if (!/^(0|[1-9][0-9]*)$/.test(sizeLine)) {
    throw new CheckpointError(`tree size must be decimal with no leading zeroes: "${sizeLine}"`);
  }
  const treeSize = Number(sizeLine);
  if (!Number.isSafeInteger(treeSize)) {
    throw new CheckpointError(`tree size is not a safe integer: "${sizeLine}"`);
  }
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(rootB64) || rootB64.length === 0) {
    throw new CheckpointError("root hash line is not base64");
  }
  const rootBytes = Buffer.from(rootB64, "base64");
  // Node's base64 decoder is lenient (it skips invalid characters), so check
  // the DECODED length rather than trusting the input string's shape.
  if (rootBytes.length !== ROOT_HASH_BYTES) {
    throw new CheckpointError(
      `root hash must decode to ${ROOT_HASH_BYTES} bytes (got ${rootBytes.length})`,
    );
  }
  const rootHash = rootBytes.toString("hex");
  // An empty tree has exactly one legitimate root. Accepting any other value
  // at size 0 would let a bogus checkpoint become a witness's TOFU baseline.
  if (treeSize === 0 && rootHash !== EMPTY_TREE_ROOT_HEX) {
    throw new CheckpointError("tree size 0 must carry the empty-tree root hash");
  }
  for (const ext of extensions) {
    if (ext.length === 0) throw new CheckpointError("extension lines must be non-empty");
  }

  const signatures: NoteSignature[] = [];
  let malformedSignatures = 0;
  if (sigBlock.length > 0) {
    const lines = sigBlock.split("\n");
    if (lines[lines.length - 1] === "") lines.pop();
    if (lines.length > MAX_SIGNATURE_LINES) {
      throw new CheckpointError(
        `note has ${lines.length} signature lines (max ${MAX_SIGNATURE_LINES})`,
      );
    }
    for (const line of lines) {
      // Malformed lines are COUNTED and skipped, never fatal: one byzantine
      // cosigner appending garbage must not void an otherwise-valid note.
      if (!line.startsWith(SIG_PREFIX)) {
        malformedSignatures += 1;
        continue;
      }
      const rest = line.slice(SIG_PREFIX.length);
      const space = rest.indexOf(" ");
      if (space <= 0) {
        malformedSignatures += 1;
        continue;
      }
      const name = rest.slice(0, space);
      const b64 = rest.slice(space + 1);
      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64) || b64.length === 0) {
        malformedSignatures += 1;
        continue;
      }
      const payload = Buffer.from(b64, "base64");
      if (payload.length < 5) {
        malformedSignatures += 1;
        continue;
      }
      signatures.push({
        name,
        keyId: payload.subarray(0, 4).toString("hex"),
        // Everything after the key ID. For a LOG signature (type 0x01) this is
        // the raw Ed25519 signature; for a COSIGNATURE (type 0x04) it is
        // uint64 big-endian timestamp || signature, split by the cosign
        // verifier — parseNote cannot tell them apart without key config.
        signature: Buffer.from(payload.subarray(4)),
      });
    }
  }
  return {
    checkpoint: {
      origin,
      treeSize,
      rootHash,
      ...(extensions.length > 0 ? { extensions } : {}),
    },
    body,
    signatures,
    malformedSignatures,
  };
}

/**
 * Verify the LOG's own signature on a note. Fails closed: an unparseable
 * note, an unknown key name/ID, or a bad signature all return false.
 *
 * Per the spec, signatures from unknown keys are IGNORED rather than
 * treated as failures — so this asks specifically "did THIS key sign it?".
 */
export function verifyNoteSignature(
  note: string | ParsedNote,
  opts: { name: string; publicKeyPem: string; sigType?: number },
): boolean {
  try {
    const parsed = typeof note === "string" ? parseNote(note) : note;
    const sigType = opts.sigType ?? SIG_TYPE_ED25519;
    const raw = rawEd25519PublicKey(opts.publicKeyPem);
    const expectedId = keyId(opts.name, sigType, raw);
    const key = createPublicKey(opts.publicKeyPem);
    for (const sig of parsed.signatures) {
      if (sig.name !== opts.name || sig.keyId !== expectedId) continue;
      if (edVerify(null, Buffer.from(parsed.body, "utf8"), key, sig.signature)) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}
