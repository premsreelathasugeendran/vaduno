import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { ClaimResult, ConsumeStore, StoredOutcome, UseClaim } from "./consume-store.js";
import { FileMutex, type FileMutexOpts } from "./file-mutex.js";

interface FileShape {
  /** Keyed by `${mandateId.length}:${mandateId}:${useKey}` (injective). */
  claims: Record<string, UseClaim>;
}

let tmpCounter = 0;

/**
 * JSON-file ConsumeStore so a few cooperating processes on ONE BOX share a
 * mandate's consume-once registry — the uniqueness AND budget constraints
 * live in the file, evaluated under a cross-process lock.
 *
 * Correctness under the intended topology:
 *  - claim() does duplicate-check + maxUses-count + insert as ONE step while
 *    holding the lock, so two processes racing a mandate — even with DIFFERENT
 *    intent ids — cannot jointly exceed maxUses (the check-then-act TOCTOU is
 *    closed by counting inside the same locked section that writes).
 *  - The lock carries an owner TOKEN: releaseLock only deletes the lockfile if
 *    it still holds our token, so a process can never unlock a lock another
 *    process reclaimed.
 *  - Writes are atomic (temp file + rename); a claim written but unsettled
 *    survives a crash as "pending" and keeps counting as a use.
 *  - settle() never overwrites an existing outcome (first write wins).
 *
 * Residual limit (documented, not hidden): a lockfile is advisory. If a holder
 * STALLS longer than `staleMs` (default 30s) mid-critical-section, another
 * process treats it as dead and reclaims — briefly permitting two holders and
 * a lost update. `staleMs` must exceed any real stall; a >30s stall means the
 * process is effectively dead. For hard multi-INSTANCE guarantees use a
 * transactional store whose UNIQUE/CHECK constraint spans the budget (Postgres).
 */
export class FileConsumeStore implements ConsumeStore {
  private readonly mutex: FileMutex;

  constructor(
    private readonly filePath: string,
    now: () => Date = () => new Date(),
    lockOpts: FileMutexOpts = {},
  ) {
    this.mutex = new FileMutex(`${filePath}.lock`, now, lockOpts);
  }

  private key(mandateId: string, useKey: string): string {
    return `${mandateId.length}:${mandateId}:${useKey}`;
  }

  private async load(): Promise<FileShape> {
    try {
      const raw = await readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw) as Partial<FileShape>;
      return { claims: parsed.claims ?? {} };
    } catch (err: unknown) {
      const e = err as NodeJS.ErrnoException;
      if (e.code === "ENOENT") return { claims: {} };
      // A corrupt registry fails closed (claims error -> guard denies) rather
      // than forgetting consumed uses. Atomic writes make this unreachable
      // from our own writes.
      throw new Error(`FileConsumeStore: cannot read ${this.filePath}: ${e.message}`);
    }
  }

  private async atomicSave(data: FileShape): Promise<void> {
    await mkdir(dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp-${process.pid}-${tmpCounter++}`;
    await writeFile(tmp, JSON.stringify(data, null, 2), "utf8");
    await rename(tmp, this.filePath);
  }

  private countFor(data: FileShape, mandateId: string): number {
    let n = 0;
    for (const c of Object.values(data.claims)) {
      if (c.mandateId === mandateId) n += 1;
    }
    return n;
  }

  /** Run `fn` holding both the in-process queue slot and the cross-process lock. */
  private mutate<T>(fn: (data: FileShape) => T | Promise<T>): Promise<T> {
    return this.mutex.run(async () => {
      const data = await this.load();
      return fn(data);
    });
  }

  async claim(claim: UseClaim, maxUses: number): Promise<ClaimResult> {
    return this.mutate<ClaimResult>(async (data) => {
      const k = this.key(claim.mandateId, claim.useKey);
      const existing = data.claims[k];
      if (existing) return { winner: false, reason: "duplicate", existing };
      // Budget check against the lock-held, freshly-loaded data — atomic with
      // the write below, so a concurrent process cannot also pass this gate.
      const used = this.countFor(data, claim.mandateId);
      if (used >= maxUses) return { winner: false, reason: "exhausted", used };
      data.claims[k] = { ...claim, status: "pending" };
      await this.atomicSave(data);
      return { winner: true, used: used + 1 };
    });
  }

  async settle(mandateId: string, useKey: string, outcome: StoredOutcome): Promise<void> {
    await this.mutate(async (data) => {
      const k = this.key(mandateId, useKey);
      const existing = data.claims[k];
      if (!existing || existing.status === "settled") return;
      data.claims[k] = { ...existing, status: "settled", outcome };
      await this.atomicSave(data);
    });
  }

  async get(mandateId: string, useKey: string): Promise<UseClaim | null> {
    const data = await this.load();
    return data.claims[this.key(mandateId, useKey)] ?? null;
  }

  async pruneMandates(mandateIds: readonly string[]): Promise<number> {
    const dead = new Set(mandateIds);
    return this.mutate(async (data) => {
      let removed = 0;
      for (const [k, c] of Object.entries(data.claims)) {
        if (dead.has(c.mandateId)) {
          delete data.claims[k];
          removed += 1;
        }
      }
      if (removed > 0) await this.atomicSave(data);
      return removed;
    });
  }

  async countClaims(mandateId: string): Promise<number> {
    return this.countFor(await this.load(), mandateId);
  }
}
