import {
  createPrivateKey,
  createPublicKey,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from "node:crypto";

/**
 * Pluggable, NON-EXPORTABLE signing for Vaduno's evidence keys — the keys
 * that sign mandates, tree heads, checkpoints, cosignatures and status lists.
 *
 * An Ed25519Signer is a CAPABILITY, not a key: it can produce signatures and
 * it can name its public key, and that is all. There is no export path and no
 * toJSON, so a signer backed by a cloud KMS or an HSM never brings key
 * material into this process — a dependency-harvesting worm that reads every
 * reachable object finds a resource name, never a key.
 *
 * These keys sign authorization and audit EVIDENCE. They are never keys to
 * funds, and a key used with this interface MUST NOT hold any other signing
 * authority — see docs/signers.md for the normative key-separation
 * requirement (no blockchain wallet keys, no shared keys, ever).
 */
export interface Ed25519Signer {
  /** The only algorithm Vaduno signs with. Anything else is refused. */
  readonly algorithm: "Ed25519";
  /** SPKI PEM of the public half. Every signature is verified against it. */
  readonly publicKeyPem: string;
  /**
   * Sign `message` (handed as a private copy) and resolve to the raw 64-byte
   * Ed25519 signature. Reject or hang on failure — `checkedSign` maps every
   * failure mode to a typed error and never lets one become an "allowed".
   */
  sign(message: Uint8Array): Promise<Uint8Array>;
}

/** Base class for every signer failure. All of them DENY — none are advisory. */
export class SignerError extends Error {
  constructor(message: string, opts?: { cause?: unknown }) {
    super(message, opts);
    this.name = "SignerError";
  }
}

/** The signer did not respond within the deadline. Nothing was emitted. */
export class SignerTimeoutError extends SignerError {
  constructor(message: string) {
    super(message);
    this.name = "SignerTimeoutError";
  }
}

/**
 * The signer returned 64 bytes that do NOT verify against its declared public
 * key. A wrong or substituted key, a corrupt proxy, a MITM — all land here,
 * BEFORE anything is recorded or returned.
 */
export class SignerVerificationError extends SignerError {
  constructor(message: string) {
    super(message);
    this.name = "SignerVerificationError";
  }
}

/** Ed25519 signatures are exactly 64 bytes; anything else is not a signature. */
const ED25519_SIGNATURE_BYTES = 64;

/** Default deadline for a single sign call. */
export const DEFAULT_SIGN_TIMEOUT_MS = 10_000;

export interface CheckedSignOptions {
  /** Deadline for the signer to respond. Default 10s. */
  timeoutMs?: number;
}

/**
 * The single gate every signer output passes through. Contract:
 *
 *  1. The message is COPIED in; the signer receives its own copy, so a signer
 *     that mutates its input cannot alter what gets verified or emitted.
 *  2. The sign call races a deadline. A timeout throws SignerTimeoutError; a
 *     late resolution is discarded without mutating anything.
 *  3. The output must be exactly 64 bytes, or SignerError — before any verify.
 *  4. The signature is verified against the signer's DECLARED public key using
 *     the ORIGINAL bytes. Only a verified signature is ever returned
 *     (SignerVerificationError otherwise), so "trust the signer's bytes" is
 *     not a thing any caller can accidentally do.
 *
 * Every failure path throws; no failure path returns a value. Fail closed.
 */
export async function checkedSign(
  signer: Ed25519Signer,
  message: Uint8Array,
  opts: CheckedSignOptions = {},
): Promise<Buffer> {
  if (signer.algorithm !== "Ed25519") {
    throw new SignerError(
      `signer declares algorithm "${String(signer.algorithm)}"; only Ed25519 is supported`,
    );
  }
  let publicKey: KeyObject;
  try {
    publicKey = createPublicKey(signer.publicKeyPem);
  } catch (err) {
    throw new SignerError("signer's declared publicKeyPem does not parse", { cause: err });
  }
  // Two private copies: `original` is what gets verified and what the emitted
  // signature is bound to; `handed` is the signer's to scribble on.
  const original = Buffer.from(message);
  const handed = Buffer.from(original);

  const timeoutMs = opts.timeoutMs ?? DEFAULT_SIGN_TIMEOUT_MS;
  let timer: NodeJS.Timeout | undefined;
  let raw: unknown;
  try {
    const signing = Promise.resolve().then(() => signer.sign(handed));
    // If the deadline wins, the signer's eventual settlement must be inert:
    // handled (no unhandled-rejection crash) and never observed.
    signing.catch(() => undefined);
    raw = await Promise.race([
      signing,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new SignerTimeoutError(`signer did not respond within ${timeoutMs}ms`)),
          timeoutMs,
        );
      }),
    ]);
  } catch (err) {
    if (err instanceof SignerError) throw err;
    throw new SignerError(
      `signer rejected: ${err instanceof Error ? err.message : String(err)}`,
      { cause: err },
    );
  } finally {
    if (timer) clearTimeout(timer);
  }

  if (!(raw instanceof Uint8Array) || raw.length !== ED25519_SIGNATURE_BYTES) {
    throw new SignerError(
      `signer returned ${raw instanceof Uint8Array ? `${raw.length} bytes` : "a non-byte value"}; an Ed25519 signature is exactly ${ED25519_SIGNATURE_BYTES} bytes`,
    );
  }
  // Copy the signature too: a signer retaining a reference to its return
  // value must not be able to mutate it after verification.
  const signature = Buffer.from(raw);
  let verified: boolean;
  try {
    verified = edVerify(null, original, publicKey, signature);
  } catch (err) {
    throw new SignerVerificationError(
      `signature could not be verified against the signer's declared public key: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (!verified) {
    throw new SignerVerificationError(
      "signer output does not verify against its declared public key — refusing to emit it",
    );
  }
  return signature;
}

/**
 * In-process signer over a PKCS#8 PEM private key. This is the ONE place a
 * raw private key is accepted, so legacy `privateKeyPem` configs and
 * signer configs share a single signing path with byte-identical output
 * (Ed25519 is deterministic).
 *
 * The key lives in an ECMAScript #private field: it is not an own property,
 * so JSON.stringify and util.inspect of the signer never contain it, and no
 * method exports it.
 */
export class LocalKeySigner implements Ed25519Signer {
  readonly algorithm = "Ed25519" as const;
  readonly publicKeyPem: string;
  readonly #privateKey: KeyObject;

  constructor(privateKeyPem: string) {
    let key: KeyObject;
    try {
      key = createPrivateKey(privateKeyPem);
    } catch (err) {
      throw new SignerError("privateKeyPem does not parse as a private key", { cause: err });
    }
    if (key.asymmetricKeyType !== "ed25519") {
      throw new SignerError(
        `LocalKeySigner requires an Ed25519 key (got ${String(key.asymmetricKeyType)})`,
      );
    }
    this.#privateKey = key;
    // createPublicKey on a private-key PEM derives the public half.
    this.publicKeyPem = createPublicKey(privateKeyPem)
      .export({ type: "spki", format: "pem" })
      .toString();
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    return edSign(null, Buffer.from(message), this.#privateKey);
  }
}
