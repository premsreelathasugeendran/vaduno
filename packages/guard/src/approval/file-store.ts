import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { FileMutex } from "../enforce/file-mutex.js";
import type { FileMutexOpts } from "../enforce/file-mutex.js";
import type {
  ApprovalDecision,
  ApprovalStore,
  PendingApproval,
} from "./approval.js";
import type { ApprovalResponse } from "../types.js";

interface FileShape {
  pending: Record<string, PendingApproval>;
  decisions: Record<string, ApprovalDecision>;
}

let tmpCounter = 0;

/**
 * JSON-file ApprovalStore so a dashboard process and an agent process can share
 * the approval queue on one box.
 *
 * Correctness under the intended two-writer topology (agent + dashboard):
 *  - Writes are serialized in-process (a promise-chain mutex) AND across
 *    processes (an O_EXCL lockfile with stale-lock recovery), so a
 *    read-modify-write cannot lose a concurrent decision.
 *  - Writes are atomic (temp file + rename), so a crash can never leave a torn
 *    JSON file that bricks the queue.
 *  - resolve() only acts on an item that is CURRENTLY pending and never
 *    overwrites an existing decision, so a decision can't be planted for an
 *    id no human has seen, and a decision can't be silently changed.
 *
 * For higher write concurrency, use a transactional/DB-backed store.
 */
export class FileApprovalStore implements ApprovalStore {
  /**
   * Cross-process exclusion is FileMutex — the same primitive the ledger,
   * consume store and spend limiter share. This class used to carry its own
   * inline copy of the lock loop, and that copy drifted exactly as the
   * FileMutex docblock predicts two copies of a subtle lock would: no
   * heartbeat, unconfirmed wall-clock stale reclaim, and a fixed-count/
   * fixed-cadence retry budget (~1s) that starved under Windows CI contention.
   */
  private readonly mutex: FileMutex;

  constructor(
    private readonly filePath: string,
    private readonly now: () => Date = () => new Date(),
    lockOpts: FileMutexOpts = {},
  ) {
    // Preserve this store's historical default staleness (10s, not FileMutex's
    // 30s): approval mutations are short read-modify-writes.
    this.mutex = new FileMutex(`${filePath}.lock`, now, {
      ...lockOpts,
      staleMs: lockOpts.staleMs ?? 10_000,
    });
  }

  private async load(): Promise<FileShape> {
    try {
      const raw = await readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw) as Partial<FileShape>;
      // NULL-PROTOTYPE, load-bearing — the THIRD file store to need it, after
      // FileSpendLimiter and FileConsumeStore (see FileSpendLimiter.load()
      // for the measured divergence and the full argument). Both records are
      // keyed on caller-controlled intentId: on a plain object (JSON.parse's
      // output included) `decisions["__proto__"]` reads back Object.prototype
      // — truthy — so enqueue() silently DROPPED that pending item and no
      // human was ever shown it, while getDecision("toString") returned a
      // FUNCTION with no `.approved`, which the queued handler records as
      // "approval does not match this payment" — a false audit row about a
      // human decision that never existed. The ApprovalStore conformance
      // suite (test/approval-store-conformance.ts) now pins both
      // implementations to Map semantics: an id is DATA here.
      return {
        pending: Object.assign(Object.create(null), parsed.pending),
        decisions: Object.assign(Object.create(null), parsed.decisions),
      };
    } catch (err: unknown) {
      const e = err as NodeJS.ErrnoException;
      if (e.code === "ENOENT") {
        return { pending: Object.create(null), decisions: Object.create(null) };
      }
      // A corrupt file fails closed (callers surface a denial) rather than
      // silently discarding the queue. Atomic writes make this unreachable
      // from our own writes.
      throw new Error(`FileApprovalStore: cannot read ${this.filePath}: ${e.message}`);
    }
  }

  private async atomicSave(data: FileShape): Promise<void> {
    await mkdir(dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp-${process.pid}-${tmpCounter++}`;
    await writeFile(tmp, JSON.stringify(data, null, 2), "utf8");
    await rename(tmp, this.filePath);
  }

  /** Run `fn` holding both FileMutex's in-process queue and the cross-process lock. */
  private mutate<T>(fn: (data: FileShape) => T | Promise<T>): Promise<T> {
    return this.mutex.run(async () => fn(await this.load()));
  }

  async enqueue(pending: PendingApproval): Promise<void> {
    await this.mutate(async (data) => {
      // Already decided? do not re-add. Otherwise register as pending.
      if (!data.decisions[pending.intentId]) {
        data.pending[pending.intentId] = pending;
        await this.atomicSave(data);
      }
    });
  }

  async listPending(): Promise<PendingApproval[]> {
    const data = await this.load();
    return Object.values(data.pending);
  }

  async resolve(intentId: string, response: ApprovalResponse): Promise<void> {
    await this.mutate(async (data) => {
      // Precondition: only decide something a human is actually being shown,
      // and never overwrite a decision that already exists.
      if (data.decisions[intentId]) return;
      const pending = data.pending[intentId];
      if (!pending) return;
      data.decisions[intentId] = {
        ...response,
        decidedAt: this.now().toISOString(),
        ...(pending.fingerprint !== undefined ? { fingerprint: pending.fingerprint } : {}),
      };
      delete data.pending[intentId];
      await this.atomicSave(data);
    });
  }

  async getDecision(intentId: string): Promise<ApprovalDecision | null> {
    const data = await this.load();
    return data.decisions[intentId] ?? null;
  }
}
