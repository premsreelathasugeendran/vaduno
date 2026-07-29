import { mkdir, open, readFile, rm, stat } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { dirname } from "node:path";

/**
 * Cross-process advisory mutex over a lockfile, plus an in-process queue.
 *
 * Extracted so the file-backed ConsumeStore and SpendLimiter share ONE
 * implementation. Two copies of a subtle lock is how the two copies drift, and
 * a lock that is subtly wrong in one store is a double-spend in that store.
 *
 * How it is correct for the intended topology (a few cooperating processes on
 * one box):
 *  - `O_EXCL` create is the atomic acquire; the OS decides the winner.
 *  - The lockfile carries an owner TOKEN. `release` deletes it only if the
 *    token is still ours, so a process can never unlock a lock that another
 *    process already reclaimed after treating us as stale.
 *  - `run()` serializes callers inside this process too, so one process's own
 *    concurrent calls queue rather than fight over the file.
 *
 * Residual limit (documented, not hidden): an advisory lockfile cannot bound a
 * stalled holder. If one stalls longer than `staleMs` (default 30s) mid
 * critical-section, another process treats it as dead and reclaims — briefly
 * permitting two holders and a lost update. `staleMs` must exceed any real
 * stall; a >30s stall means the process is effectively dead. For hard
 * multi-INSTANCE guarantees use a transactional store whose constraint spans
 * the budget (Postgres).
 */
export interface FileMutexOpts {
  retries?: number;
  delayMs?: number;
  staleMs?: number;
}

/**
 * errno values that mean "someone else holds the lock, retry" rather than
 * "this is broken, give up".
 *
 * EEXIST is the POSIX answer. Windows also produces EPERM (and sometimes
 * EACCES) when the lockfile is in a delete-pending state: another process has
 * unlinked it but an open handle remains, so an O_EXCL create is refused with
 * a *permission* error rather than an existence one. Treating that as fatal
 * turns ordinary lock contention into a thrown reserve — which, on this code
 * path, is a denied payment.
 *
 * Found by the SpendLimiter conformance suite on Windows CI: 10 parallel
 * reserves across two handles contend far harder than anything the consume
 * store's tests did, so this survived from 0.1.0 until something hammered it.
 */
const CONTENDED = new Set(["EEXIST", "EPERM", "EACCES"]);

export class FileMutex {
  private queue: Promise<unknown> = Promise.resolve();
  private token = "";

  constructor(
    private readonly lockPath: string,
    private readonly now: () => Date = () => new Date(),
    private readonly opts: FileMutexOpts = {},
  ) {}

  /** Run `fn` holding both the in-process queue slot and the cross-process lock. */
  run<T>(fn: () => T | Promise<T>): Promise<T> {
    const task = this.queue.then(async () => {
      await this.acquire();
      try {
        return await fn();
      } finally {
        await this.release();
      }
    });
    // Keep the chain alive regardless of outcome so one failure does not wedge
    // every later caller.
    this.queue = task.then(
      () => undefined,
      () => undefined,
    );
    return task;
  }

  private async acquire(): Promise<void> {
    const retries = this.opts.retries ?? 50;
    const delayMs = this.opts.delayMs ?? 20;
    const staleMs = this.opts.staleMs ?? 30_000;
    const token = randomUUID();
    let lastCode = "";
    await mkdir(dirname(this.lockPath), { recursive: true });
    for (let i = 0; i <= retries; i++) {
      try {
        const fd = await open(this.lockPath, "wx");
        try {
          await fd.writeFile(token, "utf8");
        } finally {
          await fd.close();
        }
        this.token = token;
        return;
      } catch (err: unknown) {
        lastCode = (err as NodeJS.ErrnoException).code ?? "";
        if (!CONTENDED.has(lastCode)) throw err;
        // Reclaim a lock left by a crashed process, but only once it is stale,
        // so a live holder mid-work is not stolen from. A racing reclaimer may
        // recreate it; the loser simply retries.
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
    // Naming the errno matters: EPERM/EACCES here may be genuine contention
    // (delete-pending on Windows) OR a real permissions problem on the
    // directory, and those need very different fixes.
    throw new Error(
      `FileMutex: could not acquire lock ${this.lockPath} after ${retries} retries` +
        (lastCode ? ` (last errno ${lastCode})` : ""),
    );
  }

  private async release(): Promise<void> {
    const mine = this.token;
    this.token = "";
    if (!mine) return;
    try {
      const cur = await readFile(this.lockPath, "utf8");
      if (cur === mine) await rm(this.lockPath, { force: true });
    } catch {
      /* already gone */
    }
  }
}
