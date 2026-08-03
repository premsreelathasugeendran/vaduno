import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  verify as edVerify,
  type KeyObject,
} from "node:crypto";
import {
  checkedSign,
  LocalKeySigner,
  SignerError,
  type Ed25519Signer,
} from "./signer.js";
import { canonicalJson, sha256Hex } from "../ledger/hash.js";
import type { AuditLedger } from "../ledger/ledger.js";
import type { PaymentIntent } from "../types.js";
import { merchantMatches } from "../policy/engine.js";
import { parseMs } from "../util/time.js";
import { intentDigest, MemoryConsumeStore, UNBOUNDED_USES } from "../enforce/consume-store.js";
import type { ConsumeStore, StoredOutcome, UseClaim } from "../enforce/consume-store.js";

/**
 * A mandate is a signed, time-bound, consume-once (or bounded-use) permission
 * slip: "this human authorized this agent to spend up to X at these merchants
 * until T". It creates verifiable evidence binding human intent to execution.
 *
 * Design follows the published attacks on replayable mandate schemes:
 * every mandate is time-bound, use-bounded, and consumed atomically at
 * execution time.
 */
export interface MandateConstraints {
  maxAmountMinor: number;
  currency: string;
  /** Merchant ids/hosts this mandate covers. Empty/omitted = any merchant. */
  merchants?: string[];
  categories?: string[];
  validFrom: string;
  expiresAt: string;
  /** Total number of times this mandate may authorize execution. */
  maxUses: number;
  /**
   * Optional context binding: `mandateContextHash(contextObject)` computed at
   * issue time. An intent must then present the EXACT context object (and its
   * well-known fields must match the intent) or the mandate is refused —
   * binding the authorization to one approved task run, not just "any spend
   * within constraints".
   */
  contextHash?: string;
}

/**
 * Hash of the task-context blob a mandate is bound to. Domain-separated and
 * versioned; the blob is caller-defined JSON. Two fields carry ENFORCED
 * meaning when present: `agentId` and `merchantId` must equal the paying
 * intent's values (a stolen context blob cannot be replayed at a different
 * merchant or by a different agent even inside the mandate's allowlists).
 */
export function mandateContextHash(context: Record<string, unknown>): string {
  return sha256Hex("vaduno-mandate-ctx/v1\n" + canonicalJson(context));
}

/**
 * Domain separator for the mandate signing payload.
 *
 * Added in 0.3.0. Before that the payload was bare `canonicalJson(mandate)`,
 * while `mandateContextHash`, the transparency STH, the status-list credential
 * and the transparency leaf ALL domain-separated correctly — mandates were the
 * one signed structure that did not.
 *
 * Without a domain tag, a signature is only bound to some canonical JSON, not
 * to what that JSON *means*. Any future structure whose canonical form could
 * coincide with a mandate's would share a signature space with it. Tagging is
 * a few bytes and removes the entire question.
 */
export const MANDATE_DOMAIN = "vaduno-mandate/v1\n";

/** Value of `Mandate.v` this build issues and accepts. */
export const MANDATE_FORMAT_VERSION = 1;

/** The only signature algorithm currently defined for mandates. */
export const MANDATE_ALG = "Ed25519";

const KEY_ID_DOMAIN = "vaduno-mandate-key/v1\n";

/**
 * Stable short identifier for a mandate signing key: the first 8 bytes of
 * SHA-256 over a domain tag and the key's SPKI DER encoding, in hex.
 *
 * This is what lets a verifier hold several public keys at once and pick the
 * right one — which is what makes key ROTATION possible without an
 * flag-day, and multiple ISSUERS possible at all. Derived from the key rather
 * than assigned, so two parties independently compute the same id.
 */
export function mandateKeyId(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return createHash("sha256")
    .update(KEY_ID_DOMAIN, "utf8")
    .update(der)
    .digest("hex")
    .slice(0, 16);
}

export interface Mandate {
  /**
   * Mandate format version. A verifier that does not recognise the value MUST
   * refuse rather than guess — an unversioned format cannot be changed safely
   * once anyone else implements it.
   */
  v: number;
  /**
   * Signature algorithm. Present so a verifier refuses an algorithm it does
   * not implement instead of mis-verifying under the one it assumed.
   */
  alg: string;
  /** Which signing key produced `signature`. See `mandateKeyId`. */
  kid: string;
  id: string;
  /** Human/organization that issued (signed) this mandate. */
  issuer: string;
  agentId: string;
  constraints: MandateConstraints;
  createdAt: string;
  /**
   * Ed25519 signature (base64) over `MANDATE_DOMAIN` followed by the canonical
   * JSON of every field above.
   */
  signature: string;
}

export interface MandateCheck {
  ok: boolean;
  code:
    | "OK"
    | "SIGNATURE_INVALID"
    | "KEY_UNKNOWN"
    | "ALG_UNSUPPORTED"
    | "VERSION_UNSUPPORTED"
    | "NOT_YET_VALID"
    | "EXPIRED"
    | "TIME_UNPARSEABLE"
    | "REVOKED"
    | "USES_EXHAUSTED"
    | "ALREADY_CONSUMED"
    | "CONTEXT_MISMATCH"
    | "AGENT_MISMATCH"
    | "CURRENCY_MISMATCH"
    | "AMOUNT_EXCEEDS_MANDATE"
    | "MERCHANT_NOT_COVERED"
    | "CATEGORY_NOT_COVERED"
    | "UNKNOWN_MANDATE";
  message: string;
}

/**
 * The exact bytes a mandate signature covers: a domain tag, then the canonical
 * JSON of every field except the signature itself.
 *
 * `canonicalJson` throws `CanonicalizeError` on anything JSON cannot represent
 * exactly (0.3.0), so a mandate carrying a Date, bigint or NaN cannot be signed
 * or verified at all rather than being signed under a coerced encoding that
 * some other value would share.
 */
function mandatePayload(m: Omit<Mandate, "signature">): Buffer {
  return Buffer.from(MANDATE_DOMAIN + canonicalJson(m), "utf8");
}

export interface MandateKeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
}

export function generateMandateKeyPair(): MandateKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey
      .export({ type: "pkcs8", format: "pem" })
      .toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

interface MandateState {
  mandate: Mandate;
  uses: number;
  revoked: boolean;
}

/**
 * Issues, validates, and atomically consumes mandates.
 *
 * The private key stays wherever the ISSUER keeps it — an agent process that
 * only validates/consumes needs just the public key. Never put the private
 * key into an LLM's context. For key custody where NO process ever holds the
 * key, pass a non-exportable `signer` (KMS/HSM) instead of `privateKeyPem`;
 * every signer output passes through `checkedSign` before anything is
 * recorded. The key behind a signer MUST be dedicated to Vaduno — see
 * docs/signers.md for the normative key-separation requirement.
 *
 * Consumption is enforced through a ConsumeStore — an atomic consume-once
 * registry keyed on (mandateId, intent id). The default MemoryConsumeStore
 * covers a single process; pass a FileConsumeStore (or a DB-backed store with
 * a unique constraint) so multiple LIVE processes share one registry and a
 * race between them still yields exactly one execution. For durability across
 * restarts with a shared AuditLedger, call `hydrateFromLedger()` on startup.
 */
export class MandateManager {
  private readonly publicKey: KeyObject;
  /**
   * Every public key this manager will verify against, by key id.
   *
   * A map rather than a single key because that is what makes ROTATION
   * possible without a flag-day: publish the new key, accept both while
   * mandates signed by the old one are still inside their validity window,
   * then drop the old. Also what allows several ISSUERS at once.
   */
  private readonly verifyKeys = new Map<string, KeyObject>();
  /** Key id of the signing key, so issued mandates can name it. */
  private readonly signingKeyId: string;
  /**
   * ALWAYS null, and typed so. The manager never holds private key material:
   * a signer config never had any, and a legacy privateKeyPem is wrapped into
   * a LocalKeySigner (whose key lives in an ECMAScript #private field) without
   * the PEM being retained here. The field exists so a key-harvest probe can
   * assert the invariant at runtime instead of trusting this comment.
   */
  private readonly privateKey: null = null;
  /** Signing capability, or null for a verify-only manager. */
  private readonly signer: Ed25519Signer | null;
  private readonly signTimeoutMs: number | undefined;
  private readonly states = new Map<string, MandateState>();
  private readonly consumeStore: ConsumeStore;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    keys: {
      /** Verify key. Optional when a signer is given (defaults to its key). */
      publicKeyPem?: string;
      /** Legacy in-process signing key. Mutually exclusive with `signer`. */
      privateKeyPem?: string;
      /**
       * Non-exportable signing capability (KMS/HSM/hardware). The key behind
       * it MUST be dedicated to Vaduno — see docs/signers.md.
       */
      signer?: Ed25519Signer;
      /** Extra public keys to ACCEPT but never sign with — rotation overlap. */
      additionalPublicKeyPems?: string[];
    },
    private readonly ledger?: AuditLedger,
    private readonly now: () => Date = () => new Date(),
    opts: { consumeStore?: ConsumeStore; signTimeoutMs?: number } = {},
  ) {
    // Misconfiguration fails HERE, at construction, before any authority
    // exists — never at first issue, where a half-configured manager would
    // already be trusted.
    if (keys.privateKeyPem && keys.signer) {
      throw new SignerError(
        "pass privateKeyPem OR signer, not both — two signing paths would make it ambiguous which key a mandate names",
      );
    }
    if (keys.signer) {
      if (keys.signer.algorithm !== "Ed25519") {
        throw new SignerError(
          `signer declares algorithm "${String(keys.signer.algorithm)}"; mandates are ${MANDATE_ALG} only`,
        );
      }
      // Read the declared key ONCE and refuse it now if it does not parse —
      // not at first issue.
      const declaredPem = keys.signer.publicKeyPem;
      try {
        createPublicKey(declaredPem);
      } catch (err) {
        throw new SignerError("signer's declared publicKeyPem does not parse", { cause: err });
      }
      // FREEZE the declared key: every issue() verifies against this
      // construction-time snapshot, never against whatever the backend
      // declares at sign time. A KMS wrapper that resolves "latest key
      // version" and rotates mid-life therefore FAILS verification (deny)
      // instead of minting recorded mandates whose kid names the frozen key
      // this manager can no longer verify them against.
      const inner = keys.signer;
      this.signer = {
        algorithm: "Ed25519",
        publicKeyPem: declaredPem,
        sign: (m) => inner.sign(m),
      };
    } else {
      // Legacy path wraps into LocalKeySigner: ONE signing path, and
      // byte-identical wire output because Ed25519 is deterministic.
      this.signer = keys.privateKeyPem ? new LocalKeySigner(keys.privateKeyPem) : null;
    }
    // One rule for BOTH signing configs: an explicit publicKeyPem must be the
    // key that will actually sign. A mismatch (against a signer's declared
    // key OR against the key derived from a legacy privateKeyPem) would mint
    // mandates whose kid names a key that never signed them — permanently
    // unverifiable. Refused up front.
    if (
      this.signer &&
      keys.publicKeyPem !== undefined &&
      mandateKeyId(keys.publicKeyPem) !== mandateKeyId(this.signer.publicKeyPem)
    ) {
      throw new SignerError(
        "publicKeyPem does not match the signing key — issuing would mint mandates whose kid names a key that never signed them (permanently unverifiable)",
      );
    }
    const verifyPem = keys.publicKeyPem ?? this.signer?.publicKeyPem;
    if (verifyPem === undefined) {
      throw new SignerError("MandateManager needs a publicKeyPem or a signer");
    }
    this.publicKey = createPublicKey(verifyPem);
    this.signingKeyId = mandateKeyId(verifyPem);
    this.verifyKeys.set(this.signingKeyId, this.publicKey);
    // Additional keys are verify-only: they let a rotation overlap, or a second
    // issuer's mandates be accepted, without this manager being able to sign
    // as them.
    for (const pem of keys.additionalPublicKeyPems ?? []) {
      this.verifyKeys.set(mandateKeyId(pem), createPublicKey(pem));
    }
    this.signTimeoutMs = opts.signTimeoutMs;
    this.consumeStore = opts.consumeStore ?? new MemoryConsumeStore();
  }

  /**
   * Rebuild in-memory consumption/revocation state from the ledger. Idempotent.
   * Call once after construction when using a persistent, shared ledger.
   */
  async hydrateFromLedger(): Promise<void> {
    if (!this.ledger) return;
    const entries = await this.ledger.all();
    // Per intentId, the FIFO queue of (mandateId, useKey) consumes awaiting an
    // execution_result. Keyed by intentId alone because that is all an
    // execution_result carries; the QUEUE (not last-write) pairs each result
    // with its own consume, so an intent id consumed under two mandates
    // settles each claim correctly instead of clobbering one.
    const pendingByIntent = new Map<string, Array<{ mandateId: string; useKey: string }>>();
    for (const e of entries) {
      const data = e.data as Record<string, unknown>;
      if (e.type === "mandate_issued") {
        const mandate = data.mandate as Mandate | undefined;
        if (mandate && !this.states.has(mandate.id)) {
          this.states.set(mandate.id, { mandate, uses: 0, revoked: false });
        }
      } else if (e.type === "mandate_consumed") {
        const id = data.mandateId as string;
        const state = this.states.get(id);
        if (state) {
          const use = typeof data.use === "number" ? data.use : state.uses + 1;
          state.uses = Math.max(state.uses, use);
        }
        // Rebuild the consume-once registry. UNBOUNDED_USES: these uses ALREADY
        // passed the budget gate when they happened, so a rebuild must never be
        // rejected as exhausted. claim() is idempotent — an already-populated
        // shared store keeps its original claims.
        const useKey =
          typeof data.useKey === "string" ? data.useKey : e.intentId;
        if (typeof id === "string" && typeof useKey === "string") {
          await this.consumeStore.claim(
            {
              mandateId: id,
              useKey,
              // Entries without a recorded digest rebuild as "" — a retry of
              // them replays with digestMatches false (fail closed: no
              // re-execution, no unverifiable replay).
              intentDigest:
                typeof data.intentDigest === "string" ? data.intentDigest : "",
              claimedAt: e.timestamp,
              status: "pending",
            },
            UNBOUNDED_USES,
          );
          const q = pendingByIntent.get(useKey);
          if (q) q.push({ mandateId: id, useKey });
          else pendingByIntent.set(useKey, [{ mandateId: id, useKey }]);
        }
      } else if (e.type === "execution_result") {
        const q = e.intentId ? pendingByIntent.get(e.intentId) : undefined;
        const ref = q?.shift();
        if (ref) {
          const success = (data as { success?: unknown }).success === true;
          const error = (data as { error?: unknown }).error;
          await this.consumeStore.settle(ref.mandateId, ref.useKey, {
            status: success ? "executed" : "failed",
            settledAt: e.timestamp,
            ...(typeof error === "string" ? { error } : {}),
          });
        }
      } else if (e.type === "mandate_revoked") {
        const id = data.mandateId as string;
        const state = this.states.get(id);
        if (state) state.revoked = true;
      }
    }
  }

  /** Issue and sign a new mandate. Requires a private key or signer. */
  async issue(params: {
    issuer: string;
    agentId: string;
    constraints: MandateConstraints;
  }): Promise<Mandate> {
    if (!this.signer) {
      throw new Error(
        "MandateManager was constructed without a private key or signer; cannot issue",
      );
    }
    // Fail closed at issue time on unparseable constraint timestamps.
    if (
      Number.isNaN(parseMs(params.constraints.validFrom)) ||
      Number.isNaN(parseMs(params.constraints.expiresAt))
    ) {
      throw new Error(
        "mandate constraints validFrom/expiresAt must be parseable timestamps",
      );
    }
    const unsigned: Omit<Mandate, "signature"> = {
      v: MANDATE_FORMAT_VERSION,
      alg: MANDATE_ALG,
      kid: this.signingKeyId,
      id: randomUUID(),
      issuer: params.issuer,
      agentId: params.agentId,
      constraints: params.constraints,
      createdAt: this.now().toISOString(),
    };
    // Ordering is the guarantee: build unsigned -> checkedSign -> ONLY THEN
    // record. A signer that rejects, times out, or returns bad bytes throws
    // out of checkedSign, so no phantom mandate ever reaches states or the
    // ledger, and nothing unverifiable can leave this process.
    const signature = await checkedSign(
      this.signer,
      mandatePayload(unsigned),
      this.signTimeoutMs !== undefined ? { timeoutMs: this.signTimeoutMs } : {},
    );
    const mandate: Mandate = {
      ...unsigned,
      signature: signature.toString("base64"),
    };
    this.states.set(mandate.id, { mandate, uses: 0, revoked: false });
    // The full mandate is recorded so hydrateFromLedger can rebuild state.
    await this.ledger?.append(
      "mandate_issued",
      { mandateId: mandate.id, issuer: mandate.issuer, mandate },
      { agentId: mandate.agentId },
    );
    return mandate;
  }

  /** Register a mandate issued elsewhere (signature is checked on use). */
  register(mandate: Mandate): void {
    if (!this.states.has(mandate.id)) {
      this.states.set(mandate.id, { mandate, uses: 0, revoked: false });
    }
  }

  async revoke(mandateId: string, reason?: string): Promise<void> {
    const state = this.states.get(mandateId);
    if (!state) return;
    state.revoked = true;
    await this.ledger?.append(
      "mandate_revoked",
      { mandateId, reason: reason ?? null },
      { agentId: state.mandate.agentId },
    );
  }

  /** Validation without consumption — safe for pre-flight checks. */
  check(mandateId: string, intent: PaymentIntent): MandateCheck {
    const state = this.states.get(mandateId);
    if (!state) {
      return {
        ok: false,
        code: "UNKNOWN_MANDATE",
        message: `mandate ${mandateId} is not registered`,
      };
    }
    return this.checkState(state, intent);
  }

  private checkState(
    state: MandateState,
    intent: PaymentIntent,
    usesOverride?: number,
  ): MandateCheck {
    const { mandate } = state;
    const uses = usesOverride ?? state.uses;
    const { signature, ...unsigned } = mandate;

    // Refuse a format or algorithm this build does not implement, rather than
    // verifying under the one it happened to assume. Both checks precede
    // signature verification because neither is decidable from the signature.
    if (unsigned.v !== MANDATE_FORMAT_VERSION) {
      return {
        ok: false,
        code: "VERSION_UNSUPPORTED",
        message: `mandate format v${String(unsigned.v)} is not supported (this build issues and accepts v${MANDATE_FORMAT_VERSION})`,
      };
    }
    if (unsigned.alg !== MANDATE_ALG) {
      return {
        ok: false,
        code: "ALG_UNSUPPORTED",
        message: `mandate signature algorithm "${String(unsigned.alg)}" is not supported (expected ${MANDATE_ALG})`,
      };
    }

    // Pick the key the mandate NAMES, not whichever key we happen to hold.
    // Trying every key would make a rotation window silently accept a mandate
    // whose kid claims one key and whose signature was made by another.
    const key = this.verifyKeys.get(unsigned.kid);
    if (!key) {
      return {
        ok: false,
        code: "KEY_UNKNOWN",
        message: `mandate names signing key ${String(unsigned.kid)}, which this verifier does not hold`,
      };
    }

    let valid: boolean;
    try {
      valid = edVerify(
        null,
        mandatePayload(unsigned),
        key,
        Buffer.from(signature, "base64"),
      );
    } catch {
      // Non-canonicalizable / unverifiable payload -> treat as invalid, never
      // throw. Since 0.3.0 canonicalJson refuses values JSON cannot represent,
      // so this also covers a mandate carrying a Date, bigint or NaN.
      valid = false;
    }
    if (!valid) {
      return {
        ok: false,
        code: "SIGNATURE_INVALID",
        message: "mandate signature does not verify against issuer public key",
      };
    }
    if (state.revoked) {
      return { ok: false, code: "REVOKED", message: "mandate was revoked" };
    }
    const nowMs = this.now().getTime();
    const fromMs = parseMs(mandate.constraints.validFrom);
    const expMs = parseMs(mandate.constraints.expiresAt);
    if (Number.isNaN(fromMs) || Number.isNaN(expMs)) {
      return {
        ok: false,
        code: "TIME_UNPARSEABLE",
        message: "mandate validFrom/expiresAt is not a parseable timestamp",
      };
    }
    if (nowMs < fromMs) {
      return {
        ok: false,
        code: "NOT_YET_VALID",
        message: `mandate valid from ${mandate.constraints.validFrom}`,
      };
    }
    if (nowMs >= expMs) {
      return {
        ok: false,
        code: "EXPIRED",
        message: `mandate expired at ${mandate.constraints.expiresAt}`,
      };
    }
    if (uses >= mandate.constraints.maxUses) {
      return {
        ok: false,
        code: "USES_EXHAUSTED",
        message: `mandate already used ${uses}/${mandate.constraints.maxUses} times`,
      };
    }
    if (mandate.agentId !== intent.agentId) {
      return {
        ok: false,
        code: "AGENT_MISMATCH",
        message: `mandate issued to agent "${mandate.agentId}", intent is from "${intent.agentId}"`,
      };
    }
    if (
      mandate.constraints.currency.toUpperCase() !==
      intent.amount.currency.toUpperCase()
    ) {
      return {
        ok: false,
        code: "CURRENCY_MISMATCH",
        message: `mandate currency ${mandate.constraints.currency} != intent ${intent.amount.currency}`,
      };
    }
    if (intent.amount.amountMinor > mandate.constraints.maxAmountMinor) {
      return {
        ok: false,
        code: "AMOUNT_EXCEEDS_MANDATE",
        message: `${intent.amount.amountMinor} exceeds mandate max ${mandate.constraints.maxAmountMinor}`,
      };
    }
    const merchants = mandate.constraints.merchants;
    if (
      merchants &&
      merchants.length > 0 &&
      !merchants.some((m) => merchantMatches(intent, m))
    ) {
      return {
        ok: false,
        code: "MERCHANT_NOT_COVERED",
        message: `merchant "${intent.merchant.id}" is not covered by this mandate`,
      };
    }
    const categories = mandate.constraints.categories;
    if (categories && categories.length > 0) {
      const cat = intent.category?.toLowerCase();
      if (!cat || !categories.map((c) => c.toLowerCase()).includes(cat)) {
        return {
          ok: false,
          code: "CATEGORY_NOT_COVERED",
          message: `category "${intent.category ?? "(none)"}" is not covered by this mandate`,
        };
      }
    }
    const boundCtx = mandate.constraints.contextHash;
    if (boundCtx) {
      const ctx = intent.context;
      if (!ctx || typeof ctx !== "object" || Array.isArray(ctx)) {
        return {
          ok: false,
          code: "CONTEXT_MISMATCH",
          message: "mandate is context-bound but the intent carries no context object",
        };
      }
      let presented: string;
      try {
        presented = mandateContextHash(ctx);
      } catch {
        // Non-canonicalizable context -> fail closed, never throw.
        return {
          ok: false,
          code: "CONTEXT_MISMATCH",
          message: "intent context could not be canonicalized",
        };
      }
      if (presented !== boundCtx) {
        return {
          ok: false,
          code: "CONTEXT_MISMATCH",
          message: "intent context does not hash to the mandate's contextHash",
        };
      }
      // Well-known fields carry enforced meaning: a stolen context blob must
      // not be replayable by a different agent or at a different merchant.
      const agentId = (ctx as { agentId?: unknown }).agentId;
      if (typeof agentId === "string" && agentId !== intent.agentId) {
        return {
          ok: false,
          code: "CONTEXT_MISMATCH",
          message: `context is bound to agent "${agentId}", intent is from "${intent.agentId}"`,
        };
      }
      const merchantId = (ctx as { merchantId?: unknown }).merchantId;
      if (typeof merchantId === "string" && merchantId !== intent.merchant.id) {
        return {
          ok: false,
          code: "CONTEXT_MISMATCH",
          message: `context is bound to merchant "${merchantId}", intent pays "${intent.merchant.id}"`,
        };
      }
    }
    return { ok: true, code: "OK", message: "mandate valid" };
  }

  /**
   * Atomic check-and-consume with idempotent replay — the runtime-enforcement
   * core. Serialized in-process AND claimed through the ConsumeStore, so:
   *  - two concurrent consumes of a single-use mandate yield exactly ONE
   *    "consumed" (across every process sharing the store);
   *  - a RETRY of the same (mandate, intent id) yields "replayed" with the
   *    original claim — the caller must not execute again;
   *  - the same intent id presented with DIFFERENT money fields is exposed
   *    via `digestMatches: false` — deny, never replay, never execute.
   */
  consumeOnce(mandateId: string, intent: PaymentIntent): Promise<ConsumeOutcome> {
    const task = this.queue.then(async (): Promise<ConsumeOutcome> => {
      const state = this.states.get(mandateId);
      if (!state) {
        return {
          kind: "rejected",
          check: {
            ok: false,
            code: "UNKNOWN_MANDATE",
            message: `mandate ${mandateId} is not registered`,
          },
        };
      }
      const digest = intentDigest(intent);
      // Replay lookup FIRST: a retry of an already-claimed use must replay its
      // outcome even when the mandate has since expired or exhausted its uses
      // (the original decision stands; nothing new is authorized).
      const prior = await this.consumeStore.get(mandateId, intent.id);
      if (prior) {
        return this.replayOutcome(mandateId, intent, prior, digest);
      }
      // Validate everything EXCEPT the use-count (pass 0 so this never trips
      // USES_EXHAUSTED for maxUses>=1) — the budget is enforced ATOMICALLY by
      // claim() below, inside the store's lock, so two processes racing with
      // different intent ids cannot both pass the gate (TOCTOU-free).
      const check = this.checkState(state, intent, 0);
      if (!check.ok) return { kind: "rejected", check };
      const claimed = await this.consumeStore.claim(
        {
          mandateId,
          useKey: intent.id,
          intentDigest: digest,
          claimedAt: this.now().toISOString(),
          status: "pending",
        },
        state.mandate.constraints.maxUses,
      );
      if (!claimed.winner) {
        if (claimed.reason === "duplicate") {
          // Another process won this exact use between our get and claim.
          return this.replayOutcome(mandateId, intent, claimed.existing, digest);
        }
        // Budget was full when the atomic claim ran.
        return {
          kind: "rejected",
          check: {
            ok: false,
            code: "USES_EXHAUSTED",
            message: `mandate already used ${claimed.used}/${state.mandate.constraints.maxUses} times`,
          },
        };
      }
      // Mirror the store's authoritative count for the non-consuming check().
      state.uses = Math.max(state.uses, claimed.used);
      await this.ledger?.append(
        "mandate_consumed",
        {
          mandateId,
          use: claimed.used,
          maxUses: state.mandate.constraints.maxUses,
          useKey: intent.id,
          // Recorded so hydrateFromLedger can rebuild replay verification.
          intentDigest: digest,
        },
        { intentId: intent.id, agentId: intent.agentId },
      );
      return { kind: "consumed", check, use: claimed.used };
    });
    this.queue = task.catch(() => undefined);
    return task;
  }

  private async replayOutcome(
    mandateId: string,
    intent: PaymentIntent,
    claim: UseClaim,
    digest: string,
  ): Promise<ConsumeOutcome> {
    const digestMatches = claim.intentDigest === digest;
    await this.ledger?.append(
      "mandate_replayed",
      {
        mandateId,
        useKey: claim.useKey,
        digestMatches,
        originalStatus: claim.status === "settled" ? claim.outcome?.status ?? "unresolved" : "unresolved",
      },
      { intentId: intent.id, agentId: intent.agentId },
    );
    return { kind: "replayed", claim, digestMatches };
  }

  /**
   * Record the terminal outcome of a consumed use so future retries replay
   * it. Call after the executor settles (either way). A use that is never
   * settled stays "pending" and replays as "unresolved" — fail closed.
   */
  async settleUse(
    mandateId: string,
    useKey: string,
    outcome: StoredOutcome,
  ): Promise<void> {
    await this.consumeStore.settle(mandateId, useKey, outcome);
  }

  /**
   * Legacy check-and-consume shape. Retries of an already-consumed intent id
   * come back as ALREADY_CONSUMED (not ok) — callers wanting idempotent
   * replay semantics should use `consumeOnce`.
   */
  async consume(mandateId: string, intent: PaymentIntent): Promise<MandateCheck> {
    const outcome = await this.consumeOnce(mandateId, intent);
    if (outcome.kind === "consumed" || outcome.kind === "rejected") {
      return outcome.check;
    }
    return {
      ok: false,
      code: "ALREADY_CONSUMED",
      message: `intent ${intent.id} already consumed a use of mandate ${mandateId}`,
    };
  }
}

export type ConsumeOutcome =
  | { kind: "consumed"; check: MandateCheck; use: number }
  | { kind: "rejected"; check: MandateCheck }
  | {
      kind: "replayed";
      claim: UseClaim;
      /** False = same intent id, DIFFERENT payment — deny, never replay. */
      digestMatches: boolean;
    };
