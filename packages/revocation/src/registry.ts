import type { AuditLedger } from "@vaduno/guard";
import { Bitstring, BitstringError, MINIMUM_ENTRIES } from "./bitstring.js";
import { publishStatusList, type StatusListCredential, type StatusPurpose } from "./status-list.js";
import type { RevocationStore, RevocationRecord, RegistrySnapshot } from "./store.js";
import { MemoryRevocationStore } from "./store.js";

/**
 * The revocation registry: one place to kill an agent's authority.
 *
 * HONEST SCOPE — this is deliberately NOT called a "universal kill switch":
 *  - For mandates Vaduno issues, revocation is INSTANT and GUARANTEED,
 *    because the guard consults the registry at authorization time and fails
 *    closed. Nothing spends under a revoked mandate again.
 *  - For authority Vaduno does NOT mediate (a raw wallet key the agent holds,
 *    a card issued outside Vaduno), revocation is BEST-EFFORT fan-out to each
 *    rail's own revocation API. A neutral registry has no authority over rails
 *    it does not govern, and settled on-chain spend can never be clawed back.
 * Every revocation, every fan-out attempt, and every fan-out FAILURE is
 * recorded in the audit ledger, so the gap between "we asked" and "it took
 * effect" is visible rather than assumed.
 *
 * CRITICAL DESIGN RULE: the local kill (store write + audit) happens inside a
 * serialized queue; rail fan-out happens AFTER, off the queue, under a hard
 * per-rail deadline. A best-effort, non-authoritative rail must never be able
 * to delay — let alone wedge — the authoritative kill path.
 */

export interface RevokeOptions {
  reason?: string;
  /** "revocation" is permanent; "suspension" can be lifted. Default revocation. */
  purpose?: StatusPurpose;
  /** Who ordered it (operator id, "auto:anomaly-detector", …). */
  by?: string;
}

export interface FanOutTarget {
  /** Rail name for audit ("stripe-issuing", "x402", "permit2"). */
  rail: string;
  /**
   * Ask the rail to revoke its own credential. Throwing, rejecting, OR hanging
   * is recorded as a FAILED fan-out — it never blocks or delays the local
   * revocation, which has already taken effect before this is called.
   */
  revoke: (record: RevocationRecord) => Promise<void>;
}

export interface FanOutResult {
  rail: string;
  ok: boolean;
  error?: string;
}

export interface RevocationResult {
  record: RevocationRecord;
  /** Local kill is effective the moment this returns — always true. */
  effectiveLocally: true;
  /**
   * True when no status-list index could be assigned (list full), so this
   * revocation is enforced LOCALLY but is invisible to third parties reading
   * the published list. Rotate to a new list.
   */
  unpublishable: boolean;
  /**
   * Resolves when best-effort rail fan-out finishes. Awaiting it is OPTIONAL —
   * the kill is already in force. Never rejects.
   */
  fanOut: Promise<FanOutResult[]>;
}

export interface RevocationRegistryOptions {
  issuer: string;
  /** Stable id/URL of the published status list. */
  listId: string;
  /** Ed25519 private key used to sign published status lists. */
  privateKeyPem?: string;
  store?: RevocationStore;
  ledger?: AuditLedger;
  /** Entry capacity; W3C minimum (131,072) by default. */
  entries?: number;
  /** Freshness window stamped onto published lists. Default 1h. */
  publishTtlMs?: number;
  fanOut?: FanOutTarget[];
  /** Hard deadline per rail call. Default 5s. A rail that exceeds it is
   * recorded as failed — it cannot stall the kill path. */
  fanOutTimeoutMs?: number;
  now?: () => Date;
}

export class RevocationRegistry {
  private readonly store: RevocationStore;
  private readonly entries: number;
  private readonly now: () => Date;
  private queue: Promise<unknown> = Promise.resolve();
  private lastPublishedVersion = -1;

  constructor(private readonly opts: RevocationRegistryOptions) {
    this.store = opts.store ?? new MemoryRevocationStore();
    this.entries = opts.entries ?? MINIMUM_ENTRIES;
    this.now = opts.now ?? (() => new Date());
    if (this.entries % 8 !== 0 || this.entries <= 0) {
      throw new BitstringError("entries must be a positive multiple of 8");
    }
  }

  /** Serialize mutations so two concurrent revokes cannot lose an update. */
  private run<T>(fn: () => Promise<T>): Promise<T> {
    const task = this.queue.then(fn);
    this.queue = task.then(
      () => undefined,
      () => undefined,
    );
    return task;
  }

  /**
   * Rebuild registry state from a persistent, shared ledger. Without this, a
   * restart silently un-revokes everything AND recycles bit indices (which
   * would make one revocation apply to the wrong mandate). Call once at
   * startup when using a durable ledger with the default in-memory store.
   */
  async hydrateFromLedger(): Promise<void> {
    if (!this.opts.ledger) return;
    const entries = await this.opts.ledger.all();
    for (const e of entries) {
      const d = (e.data ?? {}) as Record<string, unknown>;
      if (e.type === "mandate_index_assigned") {
        const mandateId = d.mandateId;
        const agentId = d.agentId ?? e.agentId;
        if (typeof mandateId === "string" && typeof agentId === "string") {
          // Re-allocate deterministically: replaying assignments in ledger
          // order reproduces the original index sequence.
          await this.store.allocate(mandateId, agentId, this.entries);
        }
      } else if (e.type === "mandate_revoked") {
        const mandateId = d.mandateId;
        if (typeof mandateId !== "string") continue;
        const agentId =
          typeof d.agentId === "string"
            ? d.agentId
            : (e.agentId ?? (await this.store.agentOf(mandateId)));
        if (typeof agentId === "string") {
          await this.store.allocate(mandateId, agentId, this.entries);
        }
        const idx = await this.store.indexOf(mandateId);
        await this.store.revoke({
          mandateId,
          index: typeof d.statusListIndex === "number" ? d.statusListIndex : idx,
          purpose: d.purpose === "suspension" ? "suspension" : "revocation",
          revokedAt: e.timestamp,
          reason: typeof d.reason === "string" ? d.reason : null,
          by: typeof d.by === "string" ? d.by : null,
          agentId: typeof agentId === "string" ? agentId : null,
        });
      } else if (e.type === "mandate_unsuspended") {
        const mandateId = d.mandateId;
        if (typeof mandateId === "string") await this.store.clear(mandateId);
      } else if (e.type === "agent_revoked") {
        const agentId = typeof d.agentId === "string" ? d.agentId : e.agentId;
        if (typeof agentId === "string") {
          await this.store.blockAgent(agentId, {
            reason: typeof d.reason === "string" ? d.reason : null,
            by: typeof d.by === "string" ? d.by : null,
            at: e.timestamp,
            purpose: d.purpose === "suspension" ? "suspension" : "revocation",
          });
        }
      } else if (e.type === "agent_unblocked") {
        const agentId = typeof d.agentId === "string" ? d.agentId : e.agentId;
        if (typeof agentId === "string") await this.store.unblockAgent(agentId);
      } else if (e.type === "status_list_published") {
        const v = d.version;
        if (typeof v === "number") {
          this.lastPublishedVersion = Math.max(this.lastPublishedVersion, v);
        }
      }
    }
  }

  /**
   * Assign (or look up) the status-list index for a mandate, and LINK it to
   * its agent so `revokeAgent` can find it. `agentId` is required: without the
   * link, an agent-wide kill would revoke nothing.
   *
   * Stamp the returned index onto the mandate at issue time so a verifier
   * knows which bit to read.
   */
  assignIndex(mandateId: string, agentId: string): Promise<number> {
    return this.run(async () => {
      const index = await this.store.allocate(mandateId, agentId, this.entries);
      if (index === null) {
        throw new BitstringError(
          `status list is full (${this.entries} entries) — publish a new list`,
          "STATUS_LIST_LENGTH_ERROR",
        );
      }
      await this.opts.ledger?.append(
        "mandate_index_assigned",
        { mandateId, agentId, statusListIndex: index },
        { agentId },
      );
      return index;
    });
  }

  /** Revoke ONE mandate. Local effect is immediate. */
  revokeMandate(mandateId: string, opts: RevokeOptions = {}): Promise<RevocationResult> {
    return this.run(() => this.killLocally({ mandateId, ...opts })).then((r) =>
      this.attachFanOut(r),
    );
  }

  /**
   * Revoke EVERY mandate belonging to an agent — the "kill this agent" action.
   * The agent-level block is recorded FIRST, so even a mid-loop failure leaves
   * the agent unable to spend (the guard checks the block independently of
   * per-mandate records). Also blocks mandates issued to it later.
   */
  revokeAgent(agentId: string, opts: RevokeOptions = {}): Promise<RevocationResult[]> {
    return this.run(async () => {
      const purpose: StatusPurpose = opts.purpose ?? "revocation";
      // Block FIRST: this alone stops all spend by this agent, so a failure
      // partway through the per-mandate loop can never leave it spendable.
      await this.store.blockAgent(agentId, {
        reason: opts.reason ?? null,
        by: opts.by ?? null,
        at: this.now().toISOString(),
        purpose,
      });
      await this.opts.ledger?.append(
        "agent_revoked",
        { agentId, reason: opts.reason ?? null, by: opts.by ?? null, purpose },
        { agentId },
      );
      const mandateIds = await this.store.mandatesFor(agentId);
      const out: Array<Omit<RevocationResult, "fanOut">> = [];
      const failures: Array<{ mandateId: string; error: string }> = [];
      for (const mandateId of mandateIds) {
        try {
          out.push(await this.killLocally({ mandateId, agentId, ...opts }));
        } catch (err) {
          failures.push({
            mandateId,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
      if (failures.length > 0) {
        // The agent block still holds; surface exactly which per-mandate
        // records did not land so an operator can reconcile.
        await this.opts.ledger?.append(
          "agent_revoke_partial",
          { agentId, failures, revoked: out.length },
          { agentId },
        );
      }
      return out;
    }).then((results) => results.map((r) => this.attachFanOut(r)));
  }

  /** Lift a SUSPENSION. Permanent revocations are refused (W3C §2.1). */
  unsuspendMandate(mandateId: string, by?: string): Promise<void> {
    return this.run(async () => {
      const record = await this.store.get(mandateId);
      if (!record) return;
      if (record.purpose !== "suspension") {
        throw new Error(
          `mandate ${mandateId} was REVOKED (permanent), not suspended — it cannot be reinstated`,
        );
      }
      await this.store.clear(mandateId);
      await this.opts.ledger?.append(
        "mandate_unsuspended",
        { mandateId, by: by ?? null },
        record.agentId ? { agentId: record.agentId } : {},
      );
    });
  }

  /**
   * Lift an agent-level SUSPENSION. Refused for a permanent agent revocation,
   * mirroring mandate semantics — otherwise "suspend the agent" would be an
   * irreversible action with a reversible name.
   */
  unblockAgent(agentId: string, by?: string): Promise<void> {
    return this.run(async () => {
      const block = await this.store.getAgentBlock(agentId);
      if (!block) return;
      if (block.purpose !== "suspension") {
        throw new Error(
          `agent ${agentId} was REVOKED (permanent), not suspended — it cannot be reinstated`,
        );
      }
      await this.store.unblockAgent(agentId);
      await this.opts.ledger?.append("agent_unblocked", { agentId, by: by ?? null }, { agentId });
    });
  }

  /**
   * The authoritative kill: store write + audit, inside the queue. NO rail I/O
   * happens here — see the class doc for why that separation is load-bearing.
   */
  private async killLocally(
    params: { mandateId: string; agentId?: string } & RevokeOptions,
  ): Promise<Omit<RevocationResult, "fanOut"> & { alreadyRevoked?: boolean }> {
    const purpose: StatusPurpose = params.purpose ?? "revocation";
    const existing = await this.store.get(params.mandateId);
    if (existing && existing.purpose === "revocation") {
      // Already permanently revoked — idempotent: no second store write, no
      // second audit entry, and (via `alreadyRevoked`) no second fan-out.
      return {
        record: existing,
        effectiveLocally: true,
        unpublishable: existing.index === null,
        alreadyRevoked: true,
      };
    }
    const agentId =
      params.agentId ?? (await this.store.agentOf(params.mandateId)) ?? null;
    let index = await this.store.indexOf(params.mandateId);
    if (index === null) {
      // Allocate even for a mandate that was never registered, so the kill is
      // publishable. Linking only happens when we know the agent.
      index = await this.store.allocate(params.mandateId, agentId, this.entries);
    }
    // A full list must NOT block the kill: revoke locally with a null index
    // and flag that third-party verifiers cannot see it.
    const record: RevocationRecord = {
      mandateId: params.mandateId,
      index,
      purpose,
      revokedAt: this.now().toISOString(),
      reason: params.reason ?? null,
      by: params.by ?? null,
      agentId,
    };
    await this.store.revoke(record);
    await this.opts.ledger?.append(
      "mandate_revoked",
      {
        mandateId: record.mandateId,
        statusListIndex: record.index,
        purpose: record.purpose,
        reason: record.reason,
        by: record.by,
        agentId: record.agentId,
        ...(record.index === null
          ? { unpublishable: true, note: "status list full — revocation is local-only" }
          : {}),
      },
      record.agentId ? { agentId: record.agentId } : {},
    );
    return { record, effectiveLocally: true, unpublishable: record.index === null };
  }

  /**
   * Kick off best-effort fan-out OFF the mutation queue, each rail under a
   * hard deadline. Never rejects; results are audited when they land.
   */
  private attachFanOut(
    base: Omit<RevocationResult, "fanOut"> & { alreadyRevoked?: boolean },
  ): RevocationResult {
    const { alreadyRevoked, ...result } = base;
    const targets = this.opts.fanOut ?? [];
    // A repeat revoke of an already-dead mandate must not re-hit the rails.
    if (targets.length === 0 || alreadyRevoked) {
      return { ...result, fanOut: Promise.resolve([]) };
    }
    const timeoutMs = this.opts.fanOutTimeoutMs ?? 5_000;
    const fanOut = Promise.all(
      targets.map(async (target): Promise<FanOutResult> => {
        let timer: NodeJS.Timeout | undefined;
        try {
          await Promise.race([
            target.revoke(result.record),
            new Promise<never>((_, reject) => {
              // Deliberately NOT unref'd: the promise must always settle so an
              // awaited `fanOut` cannot hang. The wait is bounded by
              // timeoutMs, so this holds the event loop for at most that long.
              timer = setTimeout(
                () => reject(new Error(`timed out after ${timeoutMs}ms`)),
                timeoutMs,
              );
            }),
          ]);
          return { rail: target.rail, ok: true };
        } catch (err) {
          return {
            rail: target.rail,
            ok: false,
            error: err instanceof Error ? err.message : String(err),
          };
        } finally {
          if (timer) clearTimeout(timer);
        }
      }),
    ).then(async (results) => {
      await this.opts.ledger
        ?.append(
          "revocation_fanout",
          { mandateId: result.record.mandateId, results },
          result.record.agentId ? { agentId: result.record.agentId } : {},
        )
        .catch(() => undefined);
      return results;
    });
    // Swallow at the source so an un-awaited fanOut can never crash the
    // process with an unhandled rejection.
    fanOut.catch(() => undefined);
    return { ...result, fanOut };
  }

  /** Is this mandate revoked/suspended right now? (local, authoritative) */
  async isRevoked(mandateId: string): Promise<RevocationRecord | null> {
    return this.store.get(mandateId);
  }

  async isAgentBlocked(agentId: string): Promise<boolean> {
    return this.store.isAgentBlocked(agentId);
  }

  /** Current registry contents — for snapshots, dashboards, and publishing. */
  async snapshot(): Promise<RegistrySnapshot> {
    return this.store.snapshot();
  }

  /**
   * Build and sign the publishable status list. `version` MUST strictly
   * increase — a repeated or lower version lets an attacker serve a stale
   * pre-revocation snapshot that a verifier's rollback floor would accept.
   *
   * Mandates belonging to a BLOCKED agent are included even if no per-mandate
   * revocation was recorded, so an agent-wide kill is visible to third-party
   * verifiers rather than only locally.
   */
  async publish(
    version: number,
    purpose: StatusPurpose = "revocation",
  ): Promise<StatusListCredential> {
    if (!this.opts.privateKeyPem) {
      throw new Error("RevocationRegistry was constructed without privateKeyPem; cannot publish");
    }
    if (!Number.isSafeInteger(version) || version <= this.lastPublishedVersion) {
      throw new Error(
        `status list version must strictly increase: ${version} <= ${this.lastPublishedVersion}`,
      );
    }
    const snap = await this.store.snapshot();
    const bits = new Bitstring(this.entries);
    let unpublishable = 0;
    for (const r of snap.records) {
      if (r.purpose !== purpose) continue;
      if (r.index === null) {
        unpublishable += 1;
        continue;
      }
      bits.set(r.index, true);
    }
    // Agent-wide kills: set every linked mandate's bit so a verifier sees them.
    for (const agentId of snap.blockedAgents) {
      const block = await this.store.getAgentBlock(agentId);
      if (!block || block.purpose !== purpose) continue;
      for (const mandateId of await this.store.mandatesFor(agentId)) {
        const idx = await this.store.indexOf(mandateId);
        if (idx !== null) bits.set(idx, true);
        else unpublishable += 1;
      }
    }
    const credential = publishStatusList(bits, {
      id: this.opts.listId,
      issuer: this.opts.issuer,
      statusPurpose: purpose,
      privateKeyPem: this.opts.privateKeyPem,
      version,
      ...(this.opts.publishTtlMs !== undefined ? { ttlMs: this.opts.publishTtlMs } : {}),
      now: this.now,
    });
    this.lastPublishedVersion = version;
    await this.opts.ledger?.append("status_list_published", {
      listId: credential.id,
      version: credential.version,
      purpose,
      revokedCount: bits.setIndices().length,
      unpublishable,
      validUntil: credential.validUntil,
    });
    return credential;
  }
}
