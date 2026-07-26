import type { StatusPurpose } from "./status-list.js";

export interface RevocationRecord {
  mandateId: string;
  /**
   * Bit position in the published status list, or null when the list was
   * FULL at revocation time. A null index still revokes locally (the guard
   * fails closed on the record's existence); it only means third-party
   * verifiers reading the published list cannot see this one — surfaced as
   * `unpublishable` on the result and in the audit trail.
   */
  index: number | null;
  purpose: StatusPurpose;
  revokedAt: string;
  reason: string | null;
  by: string | null;
  agentId: string | null;
}

export interface AgentBlock {
  reason: string | null;
  by: string | null;
  at: string;
  /** "suspension" blocks are liftable via unblockAgent; "revocation" is not. */
  purpose: StatusPurpose;
}

export interface RegistrySnapshot {
  records: RevocationRecord[];
  blockedAgents: string[];
  /** Highest assigned index + 1. */
  assigned: number;
}

/**
 * Persistence for the registry. The guard reads through this on every
 * authorization, so `get` must be fast and MUST fail closed (throw) rather
 * than return null when it cannot answer — a store outage must not read as
 * "not revoked".
 */
export interface RevocationStore {
  /**
   * Atomically assign the next free index to a mandate and link it to its
   * agent. Returns the existing index if one was already assigned (idempotent),
   * or null if the index space is exhausted. Implementations MUST make the
   * allocate-and-record step atomic — a read-modify-write on `nextIndex` can
   * hand two mandates the same bit, which would make one revocation silently
   * revoke the wrong mandate.
   */
  allocate(
    mandateId: string,
    agentId: string | null,
    capacity: number,
  ): Promise<number | null>;
  /** Index assigned to a mandate, or null if none yet. */
  indexOf(mandateId: string): Promise<number | null>;
  /** Associate a mandate with its agent (idempotent). */
  link(mandateId: string, agentId: string): Promise<void>;
  agentOf(mandateId: string): Promise<string | null>;
  mandatesFor(agentId: string): Promise<string[]>;
  revoke(record: RevocationRecord): Promise<void>;
  /** Lift a suspension. */
  clear(mandateId: string): Promise<void>;
  get(mandateId: string): Promise<RevocationRecord | null>;
  blockAgent(agentId: string, block: AgentBlock): Promise<void>;
  getAgentBlock(agentId: string): Promise<AgentBlock | null>;
  unblockAgent(agentId: string): Promise<void>;
  isAgentBlocked(agentId: string): Promise<boolean>;
  snapshot(): Promise<RegistrySnapshot>;
}

/** In-memory store — single process, tests, demos. Every method runs to
 * completion without an await, so allocation is atomic on one thread. */
export class MemoryRevocationStore implements RevocationStore {
  private readonly indices = new Map<string, number>();
  private readonly records = new Map<string, RevocationRecord>();
  private readonly agents = new Map<string, string>();
  private readonly byAgent = new Map<string, Set<string>>();
  private readonly blocked = new Map<string, AgentBlock>();
  private next = 0;

  async allocate(
    mandateId: string,
    agentId: string | null,
    capacity: number,
  ): Promise<number | null> {
    const existing = this.indices.get(mandateId);
    if (existing !== undefined) {
      if (agentId !== null) this.linkSync(mandateId, agentId);
      return existing;
    }
    if (this.next >= capacity) return null;
    const index = this.next++;
    this.indices.set(mandateId, index);
    if (agentId !== null) this.linkSync(mandateId, agentId);
    return index;
  }

  async indexOf(mandateId: string): Promise<number | null> {
    return this.indices.get(mandateId) ?? null;
  }

  private linkSync(mandateId: string, agentId: string): void {
    this.agents.set(mandateId, agentId);
    const set = this.byAgent.get(agentId);
    if (set) set.add(mandateId);
    else this.byAgent.set(agentId, new Set([mandateId]));
  }

  async link(mandateId: string, agentId: string): Promise<void> {
    this.linkSync(mandateId, agentId);
  }

  async agentOf(mandateId: string): Promise<string | null> {
    return this.agents.get(mandateId) ?? null;
  }

  async mandatesFor(agentId: string): Promise<string[]> {
    return [...(this.byAgent.get(agentId) ?? [])];
  }

  async revoke(record: RevocationRecord): Promise<void> {
    this.records.set(record.mandateId, { ...record });
  }

  async clear(mandateId: string): Promise<void> {
    this.records.delete(mandateId);
  }

  async get(mandateId: string): Promise<RevocationRecord | null> {
    const r = this.records.get(mandateId);
    return r ? { ...r } : null;
  }

  async blockAgent(agentId: string, block: AgentBlock): Promise<void> {
    const existing = this.blocked.get(agentId);
    // Never downgrade a permanent block to a liftable one.
    if (existing?.purpose === "revocation") return;
    this.blocked.set(agentId, { ...block });
  }

  async getAgentBlock(agentId: string): Promise<AgentBlock | null> {
    const b = this.blocked.get(agentId);
    return b ? { ...b } : null;
  }

  async unblockAgent(agentId: string): Promise<void> {
    this.blocked.delete(agentId);
  }

  async isAgentBlocked(agentId: string): Promise<boolean> {
    return this.blocked.has(agentId);
  }

  async snapshot(): Promise<RegistrySnapshot> {
    return {
      records: [...this.records.values()].map((r) => ({ ...r })),
      blockedAgents: [...this.blocked.keys()],
      assigned: this.next,
    };
  }
}
