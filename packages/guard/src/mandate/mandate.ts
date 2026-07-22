import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from "node:crypto";
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
  return sha256Hex("paygent-mandate-ctx/v1\n" + canonicalJson(context));
}

export interface Mandate {
  id: string;
  /** Human/organization that issued (signed) this mandate. */
  issuer: string;
  agentId: string;
  constraints: MandateConstraints;
  createdAt: string;
  /** Ed25519 signature (base64) over the canonical JSON of the fields above. */
  signature: string;
}

export interface MandateCheck {
  ok: boolean;
  code:
    | "OK"
    | "SIGNATURE_INVALID"
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

function mandatePayload(m: Omit<Mandate, "signature">): Buffer {
  return Buffer.from(canonicalJson(m), "utf8");
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
 * key into an LLM's context.
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
  private readonly privateKey: KeyObject | null;
  private readonly states = new Map<string, MandateState>();
  private readonly consumeStore: ConsumeStore;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    keys: { publicKeyPem: string; privateKeyPem?: string },
    private readonly ledger?: AuditLedger,
    private readonly now: () => Date = () => new Date(),
    opts: { consumeStore?: ConsumeStore } = {},
  ) {
    this.publicKey = createPublicKey(keys.publicKeyPem);
    this.privateKey = keys.privateKeyPem
      ? createPrivateKey(keys.privateKeyPem)
      : null;
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

  /** Issue and sign a new mandate. Requires the private key. */
  async issue(params: {
    issuer: string;
    agentId: string;
    constraints: MandateConstraints;
  }): Promise<Mandate> {
    if (!this.privateKey) {
      throw new Error(
        "MandateManager was constructed without a private key; cannot issue",
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
      id: randomUUID(),
      issuer: params.issuer,
      agentId: params.agentId,
      constraints: params.constraints,
      createdAt: this.now().toISOString(),
    };
    const signature = edSign(null, mandatePayload(unsigned), this.privateKey);
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
    let valid: boolean;
    try {
      valid = edVerify(
        null,
        mandatePayload(unsigned),
        this.publicKey,
        Buffer.from(signature, "base64"),
      );
    } catch {
      // Non-canonicalizable / unverifiable payload -> treat as invalid, never throw.
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
