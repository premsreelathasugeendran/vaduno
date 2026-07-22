import { mkdir, open, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
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
  private readonly lockPath: string;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly filePath: string,
    private readonly now: () => Date = () => new Date(),
    private readonly lockOpts: { retries?: number; delayMs?: number; staleMs?: number } = {},
  ) {
    this.lockPath = `${filePath}.lock`;
  }

  private async load(): Promise<FileShape> {
    try {
      const raw = await readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw) as Partial<FileShape>;
      return { pending: parsed.pending ?? {}, decisions: parsed.decisions ?? {} };
    } catch (err: unknown) {
      const e = err as NodeJS.ErrnoException;
      if (e.code === "ENOENT") return { pending: {}, decisions: {} };
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

  /** Run `fn` holding both the in-process mutex and the cross-process lock. */
  private mutate<T>(fn: (data: FileShape) => T | Promise<T>): Promise<T> {
    const task = this.queue.then(async () => {
      await this.acquireLock();
      try {
        const data = await this.load();
        const result = await fn(data);
        return result;
      } finally {
        await this.releaseLock();
      }
    });
    this.queue = task.then(
      () => undefined,
      () => undefined,
    );
    return task;
  }

  private async acquireLock(): Promise<void> {
    const retries = this.lockOpts.retries ?? 50;
    const delayMs = this.lockOpts.delayMs ?? 20;
    const staleMs = this.lockOpts.staleMs ?? 10_000;
    await mkdir(dirname(this.lockPath), { recursive: true });
    for (let i = 0; i <= retries; i++) {
      try {
        const fd = await open(this.lockPath, "wx");
        await fd.close();
        return;
      } catch (err: unknown) {
        if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
        // Reclaim a stale lock left by a crashed process.
        try {
          const st = await stat(this.lockPath);
          if (this.now().getTime() - st.mtimeMs > staleMs) {
            await rm(this.lockPath, { force: true });
            continue;
          }
        } catch {
          /* lock vanished between checks; retry immediately */
        }
        await new Promise((r) => setTimeout(r, delayMs));
      }
    }
    throw new Error(`FileApprovalStore: could not acquire lock ${this.lockPath}`);
  }

  private async releaseLock(): Promise<void> {
    await rm(this.lockPath, { force: true });
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
      if (!data.pending[intentId]) return;
      data.decisions[intentId] = {
        ...response,
        decidedAt: this.now().toISOString(),
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
