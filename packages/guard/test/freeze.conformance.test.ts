/**
 * Wires the freeze conformance suite to the real FreezeStore backends.
 *
 * THE FIX UNDER TEST: `@vaduno/revocation` now ships a `FreezeStore` (one
 * global row { epoch, frozen, reason, by, at }) and `createFreezeCheck(store)`
 * — wired into each guard through the EXISTING `revocationCheck` seam, which
 * the guard already runs inside the critical section, after human approval and
 * immediately before the budget reservation, and already converts ANY throw
 * into a denial. VadunoGuard itself is UNCHANGED: zero lines. That is the
 * design's central claim, and this file is where it is held to account — if a
 * guard change were needed, this harness could not be written without one.
 *
 * Each handle below is constructed exactly as a separate process would
 * construct it: its own guard, its own audit ledger (the suite forbids
 * smuggling freeze state through a shared ledger), and — for the file backend
 * — its own store object minted from the shared path. The harness `freeze()`
 * does what a real operator does: write the SHARED store, and also flip the
 * local flag of the one process they are standing in (`guard.freeze()`), so
 * the suite exercises the two mechanisms coexisting. The local flip is not
 * what makes the peer deny — delete it and only the freezing handle's own
 * fast-path denial changes; the peer's denial rides entirely on the store.
 *
 * Backends wired here: Memory (the store object IS the resource — the
 * memory-cell exception the suite documents) and File (per-handle
 * `FileFreezeStore` over one shared path — several processes on one box).
 * Postgres gets its harness in packages/postgres/test/conformance.test.ts,
 * env-gated on VADUNO_TEST_POSTGRES_URL like every other Postgres suite.
 */
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { VadunoGuard } from "../src/guard.js";
import { AuditLedger } from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import {
  FileFreezeStore,
  MemoryFreezeStore,
  type FreezeState,
  type FreezeStore,
  type UnfreezeResult,
} from "../../revocation/src/freeze-store.js";
import { createFreezeCheck } from "../../revocation/src/guard-hook.js";
import type { FreezeConformanceHandle } from "./freeze.conformance.js";
import { runFreezeConformance } from "./freeze.conformance.js";
import { makePolicy } from "./helpers.js";

/**
 * One guard process over a store: the production wiring, verbatim. The check
 * rides the revocationCheck seam — compose with `allChecks(...)` when a
 * revocation registry is also in play.
 */
function processOver(
  store: FreezeStore,
  ledger?: AuditLedger,
): FreezeConformanceHandle {
  const guard = new VadunoGuard({
    policy: makePolicy(),
    // Per-handle ledger, per the suite contract: freeze state must ride the
    // freeze resource, never be smuggled through a shared audit ledger.
    ledger: ledger ?? new AuditLedger(new MemoryLedgerStore()),
    revocationCheck: createFreezeCheck(store),
  });
  return {
    guard,
    freeze: async (reason) => {
      const snap = await store.freeze(reason);
      // The operator's other hand: flip the local flag of the ONE process
      // they are standing in. Independent of the store by design — see the
      // docblock above and freeze-store.ts.
      await guard.freeze(reason);
      return snap;
    },
    unfreeze: async (expectedEpoch) => {
      const outcome = await store.unfreeze(expectedEpoch);
      // Only an APPLIED unfreeze touches the local flag; a stale refusal
      // must leave every process denying.
      if (outcome.ok) await guard.unfreeze();
      return outcome;
    },
    read: () => store.read(),
  };
}

/**
 * Outage tap for the memory backend: delegates every call to the real
 * MemoryFreezeStore and throws when severed. The wrapper (not the inner
 * store) is the shared resource object, so the semantics under test stay the
 * production store's — the tap only simulates the backend being unreachable,
 * which an in-process memory cell cannot otherwise be.
 */
class SeverableFreezeStore implements FreezeStore {
  private severed = false;
  private readonly inner = new MemoryFreezeStore();

  private assertReachable(): void {
    if (this.severed) throw new Error("freeze backend unreachable (simulated outage)");
  }

  freeze(reason: string): Promise<FreezeState> {
    this.assertReachable();
    return this.inner.freeze(reason);
  }

  unfreeze(expectedEpoch: number): Promise<UnfreezeResult> {
    this.assertReachable();
    return this.inner.unfreeze(expectedEpoch);
  }

  read(): Promise<FreezeState> {
    this.assertReachable();
    return this.inner.read();
  }

  sever(): void {
    this.severed = true;
  }

  restore(): void {
    this.severed = false;
  }
}

// Memory: the store object IS the backing resource — no second process can
// exist, so several handles over one object is the honest analogue of
// "several processes". Every OTHER backend must mint per-handle stores from
// a shared descriptor instead.
runFreezeConformance<SeverableFreezeStore>("MemoryFreezeStore", {
  freshResource: () => new SeverableFreezeStore(),
  handle: (store, opts) => processOver(store, opts?.ledger),
  breakResource: (store) => store.sever(),
  healResource: (store) => store.restore(),
});

/** The file backend's shared resource: a PATH, plus outage bookkeeping. */
interface FileFreezeResource {
  path: string;
  /** Bytes as they stood before breakResource, null = file did not exist. */
  saved: string | null;
}

// File: the PATH is the backing resource. Every handle mints its own
// FileFreezeStore, exactly as two processes on one box would — which is why a
// queue or cache hidden in the store object cannot save a broken design here.
// The outage simulation corrupts the FILE, not a wrapper: an unparseable
// freeze file must read as "unknown" (throw → the guard denies), never as
// "not frozen" — so the break exercises the production fail-closed path
// itself rather than a test seam.
runFreezeConformance<FileFreezeResource>("FileFreezeStore", {
  freshResource: async () => {
    const dir = await mkdtemp(join(tmpdir(), "vaduno-freeze-conf-"));
    return { path: join(dir, "freeze.json"), saved: null };
  },
  handle: (r, opts) => processOver(new FileFreezeStore(r.path), opts?.ledger),
  breakResource: async (r) => {
    try {
      r.saved = await readFile(r.path, "utf8");
    } catch {
      r.saved = null; // never written yet — heal restores by deleting
    }
    await writeFile(r.path, "{ this is not the freeze state", "utf8");
  },
  healResource: async (r) => {
    if (r.saved === null) await rm(r.path, { force: true });
    else await writeFile(r.path, r.saved, "utf8");
  },
  dispose: (r) => rm(dirname(r.path), { recursive: true, force: true }),
});
