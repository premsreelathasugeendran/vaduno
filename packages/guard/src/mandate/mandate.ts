import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from "node:crypto";
import { canonicalJson } from "../ledger/hash.js";
import type { AuditLedger } from "../ledger/ledger.js";
import type { PaymentIntent } from "../types.js";
import { merchantMatches } from "../policy/engine.js";
import { parseMs } from "../util/time.js";

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
 * Consumption state lives in memory. For durability across restarts or a
 * second process, back this with a shared AuditLedger and call
 * `hydrateFromLedger()` on startup to rebuild use-counts and revocations from
 * mandate_consumed / mandate_revoked entries. Note: two LIVE processes still
 * need a shared store with a uniqueness constraint to be race-safe — that is
 * out of scope for v0.x and documented as single-process.
 */
export class MandateManager {
  private readonly publicKey: KeyObject;
  private readonly privateKey: KeyObject | null;
  private readonly states = new Map<string, MandateState>();
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    keys: { publicKeyPem: string; privateKeyPem?: string },
    private readonly ledger?: AuditLedger,
    private readonly now: () => Date = () => new Date(),
  ) {
    this.publicKey = createPublicKey(keys.publicKeyPem);
    this.privateKey = keys.privateKeyPem
      ? createPrivateKey(keys.privateKeyPem)
      : null;
  }

  /**
   * Rebuild in-memory consumption/revocation state from the ledger. Idempotent.
   * Call once after construction when using a persistent, shared ledger.
   */
  async hydrateFromLedger(): Promise<void> {
    if (!this.ledger) return;
    const entries = await this.ledger.all();
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

  private checkState(state: MandateState, intent: PaymentIntent): MandateCheck {
    const { mandate } = state;
    const { signature, ...unsigned } = mandate;
    const valid = edVerify(
      null,
      mandatePayload(unsigned),
      this.publicKey,
      Buffer.from(signature, "base64"),
    );
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
    if (state.uses >= mandate.constraints.maxUses) {
      return {
        ok: false,
        code: "USES_EXHAUSTED",
        message: `mandate already used ${state.uses}/${mandate.constraints.maxUses} times`,
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
    return { ok: true, code: "OK", message: "mandate valid" };
  }

  /**
   * Atomic check-and-consume: validation and use-count increment happen in
   * one serialized step, immediately before execution. Two concurrent
   * consumes of a single-use mandate cannot both succeed within one process.
   */
  consume(mandateId: string, intent: PaymentIntent): Promise<MandateCheck> {
    const task = this.queue.then(async (): Promise<MandateCheck> => {
      const state = this.states.get(mandateId);
      if (!state) {
        return {
          ok: false,
          code: "UNKNOWN_MANDATE",
          message: `mandate ${mandateId} is not registered`,
        };
      }
      const check = this.checkState(state, intent);
      if (!check.ok) return check;
      state.uses += 1;
      await this.ledger?.append(
        "mandate_consumed",
        {
          mandateId,
          use: state.uses,
          maxUses: state.mandate.constraints.maxUses,
        },
        { intentId: intent.id, agentId: intent.agentId },
      );
      return check;
    });
    this.queue = task.catch(() => undefined);
    return task;
  }
}
