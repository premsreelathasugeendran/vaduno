import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { FileMutex, type FileMutexOpts } from "@vaduno/guard";

/**
 * Shared emergency-freeze state — the CROSS-PROCESS half of the kill switch.
 *
 * `guard.freeze()` is an in-memory flag on one guard instance: correct inside
 * that process (it flips synchronously, before the first await) and invisible
 * to every other live process. Measured, not theorized: guard A calls
 * freeze("credentials leaked"), A denies, guard B EXECUTES — for B's whole
 * lifetime, because nothing pushes the flag to B and nothing lets B poll it.
 *
 * A FreezeStore is the shared answer: ONE global row
 * `{ epoch, frozen, reason, by, at }` in a backend every guard process can
 * reach, consulted on the authorization path via
 * `createFreezeCheck(store)` (see guard-hook.ts) through the guard's EXISTING
 * `revocationCheck` seam. Freezing the store binds every wired process's very
 * next authorization; no push, no poll loop, no restart.
 *
 * THE TWO FREEZES ARE INDEPENDENT, ON PURPOSE:
 *  - `guard.freeze(reason)` — local, synchronous, zero dependencies. Still the
 *    right tool for a single-process guard, and still what an in-executor
 *    "this charge looks hostile" stop should call first.
 *  - `store.freeze(reason)` — shared. Binds every process wired to the store.
 *  A local freeze does NOT write the shared store, and a shared (CAS) unfreeze
 *  does NOT clear a peer's local flag — an operator who wants both must issue
 *  both. Wiring them together implicitly would require exactly the deferred
 *  cross-process write ordering that made the local freeze subtle to get
 *  right; keeping them explicit keeps each one simple enough to be correct.
 *
 * EPOCH FENCING — the "cancel a freeze you never saw" hazard: operator One
 * reads the state (frozen at epoch e1) and decides to lift it. Meanwhile
 * operator Two freezes AGAIN for a new incident (epoch e2). One's unfreeze,
 * fenced on e1, must be REFUSED — applying it would silently lift a freeze One
 * never evaluated. So every freeze bumps a monotonic epoch, and
 * `unfreeze(expectedEpoch)` is a compare-and-set that refuses a stale fence
 * and changes nothing when it refuses. Same discipline as the status-list
 * version floor.
 *
 * AVAILABILITY POSTURE — TOTAL STOP, stated loudly: `createFreezeCheck` turns
 * ANY store error into a denial (the guard's revocationCheck wrapper does the
 * same), so an unreachable freeze store denies EVERY payment on every wired
 * guard. That is the correct direction for a spend firewall — "no money moves"
 * is recoverable, "money moved during the outage" is not — and it matches the
 * revocation registry's stance exactly. But it makes the freeze store a HARD
 * AVAILABILITY DEPENDENCY for all payments. Deploy it like one. There is
 * deliberately no negative cache and no fail-open mode; serving a cached "not
 * frozen" while the backend is down is precisely how an attacker who can knock
 * the backend over would disable the kill switch.
 *
 * NON-CUSTODIAL BOUNDARY: a freeze only DENIES A NEW AUTHORIZATION, before the
 * budget is reserved and before the executor runs. It never recalls, pauses,
 * or redirects a payment already handed to the rail — that power is exactly
 * the custody Vaduno must never hold.
 */
export interface FreezeState {
  /**
   * Monotonic: EVERY freeze — and every applied unfreeze — moves it forward,
   * never backward. This is the fence `unfreeze(expectedEpoch)` compares
   * against.
   */
  epoch: number;
  frozen: boolean;
  /**
   * Operational evidence, not decoration: the peer processes' denials carry
   * it, so an operator debugging a stopped fleet sees "credentials leaked",
   * not a generic no. A freeze with an empty reason never blanks a live one.
   */
  reason: string | null;
  /** Who pulled the switch, if the caller said. */
  by: string | null;
  /** ISO timestamp of the last freeze, null when unfrozen. */
  at: string | null;
}

export type UnfreezeResult =
  | { ok: true }
  | {
      /**
       * Refused — the shared epoch is not the one the operator looked at
       * (someone froze again in between). A refusal changes NOTHING.
       */
      ok: false;
      code: "STALE_EPOCH";
    };

export interface FreezeStore {
  /**
   * Freeze, bumping the epoch. Returns the state AFTER the freeze so the
   * caller holds the fence a later unfreeze must present. An empty/whitespace
   * reason never blanks a live one (falls back to the existing reason, then
   * "frozen") — a sloppy automated freeze("") must not erase the incident
   * evidence an operator's denial messages depend on.
   */
  freeze(reason: string, by?: string | null): Promise<FreezeState>;
  /**
   * Compare-and-set: applies ONLY if the shared epoch still equals
   * `expectedEpoch` — the operator lifts the freeze they LOOKED AT, never one
   * that moved under them. An applied unfreeze also bumps the epoch and
   * clears the reason. A refusal changes nothing.
   */
  unfreeze(expectedEpoch: number): Promise<UnfreezeResult>;
  /**
   * Current shared state. MUST THROW when the backend cannot answer — never
   * return a default or a cached value. The guard converts the throw into a
   * denial; a store that answers "not frozen" during an outage has disabled
   * the kill switch (see the availability posture above).
   */
  read(): Promise<FreezeState>;
}

const UNFROZEN: FreezeState = { epoch: 0, frozen: false, reason: null, by: null, at: null };

function nextFrozenState(
  prev: FreezeState,
  reason: string,
  by: string | null,
  at: string,
): FreezeState {
  const trimmed = reason.trim();
  return {
    epoch: prev.epoch + 1,
    frozen: true,
    // Never downgrade: freeze("") keeps the live reason. "frozen" as the
    // last-resort default mirrors hydrateFromLedger's fallback.
    reason: trimmed.length > 0 ? trimmed : (prev.reason ?? "frozen"),
    by,
    at,
  };
}

/**
 * In-memory FreezeStore — single process, tests, demos.
 *
 * Every mutation is ONE SYNCHRONOUS BODY: no await between reading the row
 * and replacing it, so JS single-threading makes the epoch bump and the CAS
 * atomic. That discipline is load-bearing (same rule MemoryLedgerStore.append
 * documents) — an await inside freeze() or unfreeze() would let a concurrent
 * caller interleave between the compare and the set.
 *
 * A memory store is only shared by handles in ONE process, so on its own it
 * does not make freeze cross-process — it exists as the reference semantics,
 * for tests, and for wiring several guard instances inside one process.
 */
export class MemoryFreezeStore implements FreezeStore {
  private state: FreezeState = { ...UNFROZEN };

  constructor(private readonly now: () => Date = () => new Date()) {}

  async freeze(reason: string, by: string | null = null): Promise<FreezeState> {
    this.state = nextFrozenState(this.state, reason, by, this.now().toISOString());
    return { ...this.state };
  }

  async unfreeze(expectedEpoch: number): Promise<UnfreezeResult> {
    if (expectedEpoch !== this.state.epoch) return { ok: false, code: "STALE_EPOCH" };
    this.state = { epoch: this.state.epoch + 1, frozen: false, reason: null, by: null, at: null };
    return { ok: true };
  }

  async read(): Promise<FreezeState> {
    return { ...this.state };
  }
}

let tmpCounter = 0;

/**
 * JSON-file FreezeStore so a few cooperating processes on ONE BOX share the
 * kill switch — the same topology (and the same `FileMutex` O_EXCL +
 * owner-token lockfile) as FileConsumeStore, FileSpendLimiter and
 * JsonlLedgerStore.
 *
 * Correctness under that topology:
 *  - freeze() and unfreeze() run load → compute → atomic save (temp file +
 *    rename) while HOLDING the cross-process lock, so the epoch compare and
 *    the write cannot interleave with another process's — the CAS holds
 *    across processes, not just within one.
 *  - read() takes no lock: the atomic rename means a reader sees the old
 *    bytes or the new bytes, never a torn write.
 *  - A file that exists but cannot be parsed THROWS — which the guard turns
 *    into a denial. A corrupt kill switch must read as "unknown", never as
 *    "not frozen". Only a file that does not exist yet reads as the initial
 *    unfrozen state (epoch 0).
 *
 * Residual limit (inherited from FileMutex, documented there): the lock is
 * advisory — a holder stalled past `staleMs` (default 30s) is treated as dead
 * and reclaimed, briefly permitting two holders. For hard multi-INSTANCE
 * guarantees use `PostgresFreezeStore` (@vaduno/postgres), whose
 * `UPDATE … WHERE epoch = $expected` is the compare-and-set.
 */
export class FileFreezeStore implements FreezeStore {
  private readonly mutex: FileMutex;

  constructor(
    private readonly filePath: string,
    private readonly now: () => Date = () => new Date(),
    lockOpts: FileMutexOpts = {},
  ) {
    this.mutex = new FileMutex(`${filePath}.lock`, now, lockOpts);
  }

  private async load(): Promise<FreezeState> {
    let raw: string;
    try {
      raw = await readFile(this.filePath, "utf8");
    } catch (err: unknown) {
      const e = err as NodeJS.ErrnoException;
      // Never-created is the one honest "unfrozen" default; anything else
      // (permissions, IO) is an outage and must fail closed via the throw.
      if (e.code === "ENOENT") return { ...UNFROZEN };
      throw new Error(`FileFreezeStore: cannot read ${this.filePath}: ${e.message}`);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error(
        `FileFreezeStore: ${this.filePath} is corrupt — freeze state is UNKNOWN (fail closed)`,
      );
    }
    const s = parsed as Partial<FreezeState> | null;
    if (
      s === null ||
      typeof s !== "object" ||
      !Number.isSafeInteger(s.epoch) ||
      (s.epoch as number) < 0 ||
      typeof s.frozen !== "boolean"
    ) {
      // A validly-parsed file with the wrong shape is just as unknown as a
      // corrupt one. Refusing here is what keeps a doctored file from
      // reading as "not frozen".
      throw new Error(
        `FileFreezeStore: ${this.filePath} has an invalid shape — freeze state is UNKNOWN (fail closed)`,
      );
    }
    return {
      epoch: s.epoch as number,
      frozen: s.frozen,
      reason: typeof s.reason === "string" ? s.reason : null,
      by: typeof s.by === "string" ? s.by : null,
      at: typeof s.at === "string" ? s.at : null,
    };
  }

  private async atomicSave(state: FreezeState): Promise<void> {
    await mkdir(dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp-${process.pid}-${tmpCounter++}`;
    await writeFile(tmp, JSON.stringify(state, null, 2), "utf8");
    await rename(tmp, this.filePath);
  }

  async freeze(reason: string, by: string | null = null): Promise<FreezeState> {
    return this.mutex.run(async () => {
      const next = nextFrozenState(await this.load(), reason, by, this.now().toISOString());
      await this.atomicSave(next);
      return next;
    });
  }

  async unfreeze(expectedEpoch: number): Promise<UnfreezeResult> {
    return this.mutex.run<UnfreezeResult>(async () => {
      const current = await this.load();
      // The compare and the set both happen under the lock — a peer's fresh
      // freeze cannot slip between them and be silently lifted.
      if (expectedEpoch !== current.epoch) return { ok: false, code: "STALE_EPOCH" };
      await this.atomicSave({
        epoch: current.epoch + 1,
        frozen: false,
        reason: null,
        by: null,
        at: null,
      });
      return { ok: true };
    });
  }

  async read(): Promise<FreezeState> {
    return this.load();
  }
}
