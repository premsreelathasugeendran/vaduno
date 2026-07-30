import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type {
  ReserveRequest,
  ReserveResult,
  SpendLimiter,
} from "../types.js";
import { FileMutex, type FileMutexOpts } from "./file-mutex.js";
import { firstViolatedWindow, scopeKey, type SpendRecord } from "./spend-limiter.js";

interface FileShape {
  /** Keyed by reservationId. */
  reservations: Record<string, SpendRecord>;
}

let tmpCounter = 0;

/**
 * JSON-file SpendLimiter so a few cooperating processes on ONE BOX share one
 * budget. This is what makes a $50/day cap actually hold when you run two
 * workers — with the in-memory limiter they are two separate $50 budgets and
 * the pair spends $100.
 *
 * The correctness argument is the whole point: window evaluation and the
 * reservation insert happen as ONE step while holding the cross-process lock.
 * A caller that read totals and then reserved would have reintroduced exactly
 * the check-then-act race this class exists to close — which is why `windows`
 * is an argument to `reserve()` and not something the caller pre-checks.
 *
 * Crash behaviour is deliberately biased toward over-holding: a reservation
 * written but never settled survives as "reserved" and keeps counting against
 * the cap. Losing a charge from the count is unrecoverable; holding budget
 * that was never spent is merely annoying, and `release()` fixes it when the
 * caller can prove the rail did not run.
 *
 * Residual limit: see FileMutex — an advisory lockfile cannot bound a stalled
 * holder. For hard multi-INSTANCE guarantees use a transactional store.
 */
export class FileSpendLimiter implements SpendLimiter {
  private readonly mutex: FileMutex;

  constructor(
    private readonly filePath: string,
    now: () => Date = () => new Date(),
    lockOpts: FileMutexOpts = {},
  ) {
    this.mutex = new FileMutex(`${filePath}.lock`, now, lockOpts);
  }

  private async load(): Promise<FileShape> {
    try {
      const raw = await readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw) as Partial<FileShape>;
      return { reservations: parsed.reservations ?? {} };
    } catch (err: unknown) {
      const e = err as NodeJS.ErrnoException;
      if (e.code === "ENOENT") return { reservations: {} };
      // A corrupt file fails closed (reserve throws -> guard denies) rather
      // than forgetting spend. Atomic writes make this unreachable from our
      // own writes.
      throw new Error(`FileSpendLimiter: cannot read ${this.filePath}: ${e.message}`);
    }
  }

  private async atomicSave(data: FileShape): Promise<void> {
    await mkdir(dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp-${process.pid}-${tmpCounter++}`;
    await writeFile(tmp, JSON.stringify(data, null, 2), "utf8");
    await rename(tmp, this.filePath);
  }

  async reserve(req: ReserveRequest): Promise<ReserveResult> {
    return this.mutex.run(async () => {
      const data = await this.load();

      const existing = data.reservations[req.reservationId];
      if (existing) {
        // A retry of the same intent must not consume budget twice.
        return {
          ok: true as const,
          reservationId: req.reservationId,
          replayed: true,
          state: existing.state,
        };
      }

      const key = scopeKey(req.scope, req.currency);
      const inScope = Object.values(data.reservations).filter(
        (r) => scopeKey(r.scope, r.currency) === key,
      );
      const violated = firstViolatedWindow(
        req.windows,
        inScope,
        req.amountMinor,
        req.nowMs,
      );
      if (violated) return { ok: false as const, ...violated };

      data.reservations[req.reservationId] = {
        reservationId: req.reservationId,
        scope: req.scope,
        currency: req.currency,
        amountMinor: req.amountMinor,
        ms: req.nowMs,
        state: "reserved",
      };
      await this.atomicSave(data);
      return { ok: true as const, reservationId: req.reservationId, replayed: false };
    });
  }

  async commit(reservationId: string): Promise<void> {
    await this.mutex.run(async () => {
      const data = await this.load();
      const r = data.reservations[reservationId];
      if (!r || r.state === "committed") return;
      r.state = "committed";
      await this.atomicSave(data);
    });
  }

  async release(reservationId: string): Promise<void> {
    await this.mutex.run(async () => {
      const data = await this.load();
      const r = data.reservations[reservationId];
      if (!r) return;
      // Releasing committed spend would un-count real money. Refuse.
      if (r.state === "committed") return;
      delete data.reservations[reservationId];
      await this.atomicSave(data);
    });
  }

  async pruneBefore(beforeMs: number): Promise<number> {
    return this.mutex.run(async () => {
      const data = await this.load();
      let removed = 0;
      for (const [id, r] of Object.entries(data.reservations)) {
        if (r.ms < beforeMs) {
          delete data.reservations[id];
          removed += 1;
        }
      }
      if (removed > 0) await this.atomicSave(data);
      return removed;
    });
  }

  /** NOTE: the first argument is the SCOPE (policy id), not an agent id. */
  async totalsSince(
    scope: string,
    sinceIso: string,
    currency: string,
  ): Promise<{ totalMinor: number; count: number }> {
    const since = Date.parse(sinceIso);
    const data = await this.load();
    const key = scopeKey(scope, currency);
    let totalMinor = 0;
    let count = 0;
    for (const r of Object.values(data.reservations)) {
      if (scopeKey(r.scope, r.currency) !== key) continue;
      if (!Number.isFinite(since) || r.ms <= since) continue;
      totalMinor += r.amountMinor;
      count += 1;
    }
    return { totalMinor, count };
  }
}
