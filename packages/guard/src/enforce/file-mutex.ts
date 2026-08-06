import { mkdir, open, readFile, rm, stat, utimes } from "node:fs/promises";
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
 * LIVENESS IS PROVED BY A HEARTBEAT, NOT BY A SUBTRACTION. Stale reclaim has
 * to exist — a crashed holder must not wedge the system forever — and it is
 * the ONE mechanism that can put two holders inside at once, which on this
 * primitive means a forked ledger, a double spend, a blown cap, or a lifted
 * freeze. It used to rest on a single WALL-CLOCK subtraction,
 * `now() - lockfile.mtimeMs > staleMs`, against an mtime written once at
 * creation and never refreshed. Two ways that admitted a second holder, both
 * reproduced in test/file-mutex.test.ts against the pre-fix code:
 *  - a holder whose critical section merely OUTLASTS `staleMs` is
 *    indistinguishable from a dead one, because the only evidence was the
 *    creation time;
 *  - a FORWARD CLOCK JUMP larger than `staleMs` — an NTP correction, a VM
 *    resume — instantly ages every live lock on the box past the threshold,
 *    with nothing anomalous about the holder or the load. Exactly the shape of
 *    a failure that happens once and never reproduces.
 * So: a holder REFRESHES the lockfile's mtime every `staleMs/3` while it
 * works, and a reclaimer never deletes on first sight — it records the mtime,
 * waits a confirmation window, re-stats, and reclaims only if nothing
 * refreshed it in between. A live holder's heartbeat lands in that window and
 * aborts the reclaim; a dead holder's never does, so crash recovery is
 * unchanged. Wall-clock staleness is now a NECESSARY condition, no longer a
 * sufficient one.
 *
 * Residual limit (documented, not hidden): a holder that is alive but whose
 * EVENT LOOP is blocked cannot heartbeat, so a synchronous stall longer than
 * `staleMs` plus the confirmation window is still reclaimable. That is a
 * process which cannot make progress anyway. For hard multi-INSTANCE
 * guarantees use a transactional store whose constraint spans the invariant
 * (Postgres).
 */
export interface FileMutexOpts {
  retries?: number;
  delayMs?: number;
  staleMs?: number;
}

/** Heartbeat period: comfortably inside staleMs, so a live lock never ages out. */
const HEARTBEAT_DIVISOR = 3;

/**
 * How long a stale-looking lock must sit UNREFRESHED before it is deleted.
 * One heartbeat period plus slack, so a live holder is guaranteed at least one
 * chance to prove itself inside the window.
 */
function confirmWindowMs(staleMs: number): number {
  return Math.max(50, Math.ceil(staleMs / HEARTBEAT_DIVISOR) + 50);
}

/**
 * Elapsed-time source for the confirmation window. Deliberately NOT the
 * injected `now()`: that is the wall clock, and the whole point of the window
 * is to survive a wall-clock jump that made a live lock look stale. A jump
 * that satisfies the staleness test must not also satisfy the confirmation.
 */
function monotonicMs(): number {
  return Number(process.hrtime.bigint() / 1_000_000n);
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
  /** Live-holder heartbeat timer; see the class docblock. */
  private beat: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly lockPath: string,
    private readonly now: () => Date = () => new Date(),
    private readonly opts: FileMutexOpts = {},
  ) {}

  /** Run `fn` holding both the in-process queue slot and the cross-process lock. */
  run<T>(fn: () => T | Promise<T>): Promise<T> {
    const task = this.queue.then(async () => {
      await this.acquire();
      this.startHeartbeat();
      try {
        return await fn();
      } finally {
        this.stopHeartbeat();
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

  /**
   * Keep the lockfile's mtime fresh while we hold it, so a rival can tell a
   * LIVE holder from a dead one. Without this, mtime records only when the
   * lock was created, and "held for longer than staleMs" reads identically to
   * "abandoned" — which is how a second holder got in. Errors are swallowed:
   * a missed beat only risks a reclaim, which the confirmation window below
   * still has to agree to, and throwing here would take down a critical
   * section that is doing real work.
   */
  private startHeartbeat(): void {
    const staleMs = this.opts.staleMs ?? 30_000;
    const period = Math.max(10, Math.floor(staleMs / HEARTBEAT_DIVISOR));
    this.beat = setInterval(() => {
      const t = new Date();
      void utimes(this.lockPath, t, t).catch(() => undefined);
    }, period);
    // Never hold the process open for a heartbeat.
    (this.beat as { unref?: () => void }).unref?.();
  }

  private stopHeartbeat(): void {
    if (this.beat !== null) {
      clearInterval(this.beat);
      this.beat = null;
    }
  }

  private async acquire(): Promise<void> {
    const retries = this.opts.retries ?? 50;
    const delayMs = this.opts.delayMs ?? 20;
    const staleMs = this.opts.staleMs ?? 30_000;
    const confirmMs = confirmWindowMs(staleMs);
    const token = randomUUID();
    let lastCode = "";
    /**
     * The mtime a stale-looking lock had when we first flagged it, and when we
     * flagged it. Reclaim requires BOTH that it still looks stale and that
     * nothing refreshed it across the confirmation window — a live holder's
     * heartbeat lands there and moves mtime, which cancels the reclaim.
     */
    let flagged: { mtimeMs: number; atMs: number } | null = null;
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
        // Reclaim a lock left by a crashed process — but never on first sight,
        // and never on a wall-clock subtraction alone. See the class docblock:
        // both a long-but-live critical section and a forward clock jump made
        // that test true for a lock whose holder was very much alive.
        try {
          const st = await stat(this.lockPath);
          const looksStale = this.now().getTime() - st.mtimeMs > staleMs;
          if (!looksStale) {
            flagged = null;
          } else if (flagged === null || flagged.mtimeMs !== st.mtimeMs) {
            // First sighting, or the holder heartbeat since we last looked:
            // (re)start the confirmation window rather than deleting.
            flagged = { mtimeMs: st.mtimeMs, atMs: monotonicMs() };
          } else if (monotonicMs() - flagged.atMs >= confirmMs) {
            // Stale, and UNTOUCHED for a full confirmation window measured on
            // a monotonic clock (so the same jump that made it look stale
            // cannot also fast-forward the confirmation). Nobody is heartbeating
            // it: treat it as abandoned. A racing reclaimer may recreate it;
            // the loser simply retries.
            await rm(this.lockPath, { force: true });
            flagged = null;
            continue;
          }
        } catch {
          /* lock vanished between checks; retry immediately */
          flagged = null;
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
