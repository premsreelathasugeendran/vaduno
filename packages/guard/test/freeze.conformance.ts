/**
 * Conformance suite: the EMERGENCY FREEZE across TWO GUARD PROCESSES.
 *
 * Run against TWO INDEPENDENT GUARD HANDLES OVER ONE SHARED FREEZE RESOURCE.
 * That is the entire point and it is not negotiable — every assertion here
 * passes trivially against a single handle, which is exactly how the defect
 * survived to 0.3.0: guard A calls freeze("credentials leaked") → A denies,
 * guard B EXECUTES, for B's whole lifetime. `this.frozen` is an instance
 * field; there is no push and no pull, and the only ledger→freeze bridge
 * (hydrateFromLedger) is one-shot, so an operator cannot even poll it.
 *
 * WHY A RESOURCE, NOT A STORE OBJECT: the real collision is two processes on
 * one BACKEND (a row, a file, a table) — two processes never share a store
 * object. A harness that hands every handle the same store object is defeated
 * by the most dangerous naive fix: a queue or cache hidden inside the shared
 * object serializes the handles that share it and leaves the cross-process
 * defect untouched, green tests and all. So `handle()` mints its own view
 * from the shared descriptor wherever the backend has one. Only a backend
 * whose store object IS the resource (memory) may share the object — same
 * rule as ledger-concurrency.conformance.ts, for the same reason.
 *
 * WHY EVERY HANDLE GETS ITS OWN AUDIT LEDGER (harness contract): freeze
 * propagation must ride the FREEZE resource and nothing else. A shared audit
 * ledger would let a design that polls the ledger for the last
 * guard_frozen/guard_unfrozen record sneak through parts of this suite — and
 * that design is one of the two this suite exists to kill: it inherits the
 * ledger's own concurrency problems, offers no epoch to fence an unfreeze
 * against (killed by the STALE EPOCH test), and cannot fail closed distinctly
 * (a ledger outage and "never frozen" look identical). The other naive design
 * — keep the in-memory flag, add a broadcast push — is killed twice: the
 * VERY-NEXT-CALL test never sleeps, so propagation delay is fatal; and the
 * THROWING-STORE test makes a missed push read as what it is, an unknown, not
 * "not frozen".
 *
 * FAIL-CLOSED is asserted, not assumed: a freeze backend that cannot answer
 * must deny on EVERY handle. This is the property the revocation registry
 * already has (an unreachable registry denies) and local freeze lacks.
 *
 * THE MONEY-PATH BOUNDARY is also pinned here: a freeze that lands while a
 * payment is already inside the executor must NOT recall it. Vaduno decides
 * BEFORE and records AFTER; the power to yank back an in-flight charge is
 * exactly the custody this project must never hold. What the freeze must do
 * is kill the NEXT authorization — on every handle.
 */
import { describe, expect, it } from "vitest";
import { AuditLedger } from "../src/ledger/ledger.js";
import type {
  ExpectedTip,
  LedgerAppendResult,
  LedgerEntry,
  LedgerStore,
} from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import type { VadunoGuard } from "../src/guard.js";
import type { GuardResult, PaymentIntent } from "../src/types.js";
import { makeIntent } from "./helpers.js";

/** The shared freeze state as any handle sees it. One global row, no more. */
export interface FreezeSnapshot {
  /**
   * Monotonic: EVERY freeze (and every applied unfreeze) moves it, never
   * backward. This is the fence an operator's unfreeze compares against —
   * the same compare-and-set discipline as the status-list version floor and
   * the revocation registry's strictly-increasing version.
   */
  epoch: number;
  frozen: boolean;
  reason: string | null;
}

export type UnfreezeOutcome =
  | { ok: true }
  | {
      /** Refused — most importantly when `expectedEpoch` is stale. */
      ok: false;
      code: string;
    };

/** One guard process, as the harness constructs it over the shared resource. */
export interface FreezeConformanceHandle {
  /**
   * A guard wired the way THIS backend's operator would wire it, configured
   * to allow the suite's makeIntent() USD intents (no mandate, no approval)
   * while unfrozen.
   */
  guard: VadunoGuard;
  /**
   * Freeze via this handle: whatever an operator standing in this process can
   * actually do. Must at minimum write the shared resource. Returns the state
   * AFTER the freeze (so the suite can fence unfreezes on its epoch).
   */
  freeze(reason: string): Promise<FreezeSnapshot>;
  /**
   * Compare-and-set: applies ONLY if the shared epoch still equals
   * `expectedEpoch` — the operator lifts the freeze they LOOKED AT, never one
   * that moved under them. A refusal must change nothing.
   */
  unfreeze(expectedEpoch: number): Promise<UnfreezeOutcome>;
  /** Read the shared state as this handle sees it, for assertions. */
  read(): Promise<FreezeSnapshot>;
}

export interface FreezeConformanceHarness<R> {
  /**
   * A fresh, UNFROZEN backing RESOURCE — the thing two processes would
   * actually share: a file path, a table, a pool. For a memory backend the
   * cell object itself is the resource; nothing else qualifies.
   */
  freshResource(): Promise<R> | R;
  /**
   * A NEW guard handle over that resource, constructed exactly as a separate
   * process would construct it: its own guard, its OWN audit ledger (see the
   * docblock — a shared ledger smuggles freeze state through the wrong
   * channel), and, wherever the backend permits, its own store object minted
   * from the descriptor. Never return a cached handle.
   *
   * `opts.ledger` lets the suite inject an instrumented ledger (the
   * mid-hydrate test); when absent, mint a fresh private one.
   */
  handle(
    resource: R,
    opts?: { ledger?: AuditLedger },
  ): Promise<FreezeConformanceHandle> | FreezeConformanceHandle;
  /**
   * Make EVERY subsequent read of the shared freeze resource THROW, on every
   * handle, until healResource(). Simulates the backend being unreachable —
   * the case that must deny, not allow.
   */
  breakResource(resource: R): Promise<void> | void;
  /** Undo breakResource. Optional; the post-outage recovery check is skipped without it. */
  healResource?(resource: R): Promise<void> | void;
  /** Cleanup, if the resource holds a file or connection. */
  dispose?(resource: R): Promise<void> | void;
}

/**
 * A denial is only a freeze denial if it SAYS so, with the reason attached —
 * an operator debugging a stopped fleet needs "GUARD_FROZEN: credentials
 * leaked", not a generic no.
 */
function expectFrozenDenial<T>(result: GuardResult<T>, reasonFragment?: string): void {
  expect(result.status).toBe("denied");
  if (result.status !== "denied") return;
  expect(result.policyResult.reasons.map((r) => r.code)).toContain("GUARD_FROZEN");
  if (reasonFragment !== undefined) {
    expect(
      result.policyResult.reasons.map((r) => r.message).join(" | "),
    ).toContain(reasonFragment);
  }
}

/** A rail spy: the suite's proof of which payments actually ran. */
function railSpy(): {
  calls: string[];
  executor: (intent: PaymentIntent) => Promise<string>;
} {
  const calls: string[] = [];
  return {
    calls,
    executor: async (intent) => {
      calls.push(intent.id);
      return "charged";
    },
  };
}

/**
 * Ledger whose READS resolve only after open() — writes pass straight
 * through. This parks hydrateFromLedger() mid-flight in its exact danger
 * shape: the snapshot is READ before the freeze lands and APPLIED after,
 * which is the stale-snapshot clobber a snapshot-based freeze design cannot
 * survive. Suite-owned and backend-agnostic: it gates the HYDRATE timing,
 * not the freeze backend under test.
 */
class GatedLedgerStore implements LedgerStore {
  private readonly inner: LedgerStore = new MemoryLedgerStore();
  private readonly released: Promise<void>;
  private release!: () => void;

  constructor() {
    this.released = new Promise((resolve) => {
      this.release = resolve;
    });
  }

  open(): void {
    this.release();
  }

  append(entry: LedgerEntry, expected: ExpectedTip): Promise<LedgerAppendResult> {
    return this.inner.append(entry, expected);
  }

  async last(): Promise<LedgerEntry | null> {
    const snapshot = await this.inner.last();
    await this.released;
    return snapshot;
  }

  async all(): Promise<LedgerEntry[]> {
    const snapshot = await this.inner.all();
    await this.released;
    return snapshot;
  }
}

export function runFreezeConformance<R>(
  name: string,
  harness: FreezeConformanceHarness<R>,
): void {
  describe(`freeze conformance: ${name}`, () => {
    async function open(opts?: { ledgerForFirst?: AuditLedger }) {
      const resource = await harness.freshResource();
      const a = await harness.handle(
        resource,
        opts?.ledgerForFirst ? { ledger: opts.ledgerForFirst } : undefined,
      );
      const b = await harness.handle(resource);
      return {
        resource,
        a,
        b,
        dispose: () => harness.dispose?.(resource),
      };
    }

    it("baseline: two fresh handles over one resource both authorize", async () => {
      // Proves the suite CAN fail: a harness whose guards deny by default
      // (or whose resource starts frozen) would make every assertion below
      // vacuous.
      const { a, b, dispose } = await open();
      const rail = railSpy();
      expect((await a.guard.execute(makeIntent(), rail.executor)).status).toBe("executed");
      expect((await b.guard.execute(makeIntent(), rail.executor)).status).toBe("executed");
      expect((await a.read()).frozen).toBe(false);
      expect(rail.calls).toHaveLength(2);
      await dispose();
    });

    it("THE DEFECT: A freezes; B's VERY NEXT execute() denies GUARD_FROZEN — no sleep, no restart, no hydrate", async () => {
      // "Very next call, no sleep" is literal and deliberate: this test never
      // yields to a timer, so ANY eventual-consistency design — broadcast,
      // pubsub, poll-on-interval — fails it. The freeze an operator issues
      // during an incident ("credentials leaked") must bind every peer's next
      // authorization, not their next-but-eventually.
      const { a, b, dispose } = await open();
      const rail = railSpy();

      // B is demonstrably live (and any cache a naive design keeps is now
      // primed with "not frozen").
      expect((await b.guard.execute(makeIntent(), rail.executor)).status).toBe("executed");

      const snap = await a.freeze("credentials leaked");
      expect(snap.frozen).toBe(true);

      // A denying is NOT the defect — the process an operator stands in has
      // always denied. It is asserted so a harness whose freeze() does
      // nothing at all cannot pass by accident.
      expectFrozenDenial(await a.guard.execute(makeIntent(), rail.executor));

      // THE TEETH. Measured before any fix: this returns "executed".
      expectFrozenDenial(
        await b.guard.execute(makeIntent(), rail.executor),
        "credentials leaked",
      );

      // Only the pre-freeze charge ever reached the rail.
      expect(rail.calls).toHaveLength(1);
      await dispose();
    });

    it("unfreeze with a STALE EPOCH is refused; the freeze keeps binding every handle until the CURRENT epoch lifts it", async () => {
      // The attack: operator One reads the state (epoch e1, reason "creds
      // leaked") and decides to unfreeze. Meanwhile operator Two freezes
      // AGAIN for a new incident (epoch e2). One's unfreeze — fenced on the
      // state One actually saw — must be REFUSED, or it silently lifts a
      // freeze One never evaluated. A ledger-poll design has no epoch to
      // fence against and cannot express this refusal at all.
      const { a, b, dispose } = await open();
      const rail = railSpy();

      const s1 = await a.freeze("credentials leaked");
      const s2 = await a.freeze("rotation incomplete — second key exposed");
      // Every freeze bumps the monotonic epoch: the fence exists.
      expect(s2.epoch).toBeGreaterThan(s1.epoch);

      const refused = await a.unfreeze(s1.epoch);
      expect(refused.ok).toBe(false);

      // A refusal changes NOTHING.
      const after = await a.read();
      expect(after.frozen).toBe(true);
      expect(after.epoch).toBe(s2.epoch);

      // And the peer is still bound by it.
      expectFrozenDenial(await b.guard.execute(makeIntent(), rail.executor));

      // The CURRENT epoch, seen and fenced, lifts it — from EITHER handle.
      const lifted = await b.unfreeze(s2.epoch);
      expect(lifted.ok).toBe(true);
      expect((await b.read()).frozen).toBe(false);
      expect((await b.guard.execute(makeIntent(), rail.executor)).status).toBe("executed");
      expect(rail.calls).toHaveLength(1);
      await dispose();
    });

    it("a freeze store that THROWS denies on BOTH handles — unreachable is never 'not frozen'", async () => {
      // This kills every cached and every fail-open design in one move. Both
      // handles have just authorized successfully, so any last-known-good
      // cache holds "not frozen" — and serving that cached answer while the
      // backend is down is precisely the fail-open this suite forbids. An
      // attacker who can knock the freeze backend over must not thereby
      // disable the kill switch. Same property the revocation registry
      // already has; local freeze lacks it entirely.
      const { resource, a, b, dispose } = await open();
      const rail = railSpy();

      expect((await a.guard.execute(makeIntent(), rail.executor)).status).toBe("executed");
      expect((await b.guard.execute(makeIntent(), rail.executor)).status).toBe("executed");

      await harness.breakResource(resource);

      // No exact code pinned (the guard's revocation wrapper reports
      // REVOCATION_CHECK_FAILED; a dedicated freeze path may name it
      // differently) — but the STATUS is not negotiable, and the rail must
      // not have run.
      expect((await a.guard.execute(makeIntent(), rail.executor)).status).toBe("denied");
      expect((await b.guard.execute(makeIntent(), rail.executor)).status).toBe("denied");
      expect(rail.calls).toHaveLength(2);

      if (harness.healResource) {
        // The outage denial was unavailability, not a phantom freeze: once
        // the backend answers again — and says unfrozen — payments resume.
        await harness.healResource(resource);
        expect((await b.guard.execute(makeIntent(), rail.executor)).status).toBe("executed");
      }
      await dispose();
    });

    it("a freeze issued while a peer is MID-HYDRATE survives the hydrate", async () => {
      // The clobber shape: B's hydrate snapshot is READ before the freeze
      // lands and APPLIED after. 0.3.0's epoch stamp already stops the
      // snapshot overwriting B's OWN freeze flag; this test pins the
      // cross-process half — the freeze lives in the shared resource, so no
      // amount of stale-snapshot application on B may un-bind it. A design
      // that derives freeze state from a ledger snapshot fails here on
      // ordering alone.
      const gated = new GatedLedgerStore();
      // Suite-injected instrumentation: handle `a` hydrates over the gated
      // ledger; handle `b` plays the peer that pulls the switch.
      const { a, b, dispose } = await open({
        ledgerForFirst: new AuditLedger(gated),
      });
      const rail = railSpy();

      // `a` holds the gated ledger: park its hydrate mid-flight, snapshot
      // already read (empty, unfrozen), completion pending.
      const hydrating = a.guard.hydrateFromLedger();

      // The freeze lands while that hydrate is in the air — issued from the
      // OTHER process.
      const snap = await b.freeze("credentials leaked");
      expect(snap.frozen).toBe(true);

      gated.open();
      await hydrating; // empty private ledger: verifies clean, restores nothing

      // The shared resource still says frozen…
      expect((await a.read()).frozen).toBe(true);
      // …and the hydrated handle's next authorization obeys it.
      expectFrozenDenial(
        await a.guard.execute(makeIntent(), rail.executor),
        "credentials leaked",
      );
      expect(rail.calls).toHaveLength(0);
      await dispose();
    });

    it("freeze() never downgrades a live reason, and peers are denied WITH the reason", async () => {
      // The attack: a second, sloppier freeze (an automated monitor calling
      // freeze("") behind the operator's back) must not blank "credentials
      // leaked" out of the state — the reason is operational evidence, and
      // the peer's denial must carry it, or the operator debugging a stopped
      // fleet cannot tell an incident from a glitch.
      const { a, b, dispose } = await open();
      const rail = railSpy();

      const first = await a.freeze("credentials leaked");
      const second = await a.freeze("");

      expect(second.frozen).toBe(true);
      // Still a freeze, still fenced: the epoch moved…
      expect(second.epoch).toBeGreaterThan(first.epoch);
      // …but the substantive reason survived the empty overwrite.
      expect(second.reason ?? "").toContain("credentials leaked");
      expect((await b.read()).reason ?? "").toContain("credentials leaked");

      expectFrozenDenial(
        await b.guard.execute(makeIntent(), rail.executor),
        "credentials leaked",
      );
      expect(rail.calls).toHaveLength(0);
      await dispose();
    });

    it("MONEY-PATH BOUNDARY: a freeze cannot recall a payment already inside the executor — it kills the NEXT authorization", async () => {
      // The non-custodial invariant, asserted from the freeze side. Once the
      // executor is invoked the money is in the rail's hands; a freeze that
      // could yank it back would require exactly the in-flight payment
      // control Vaduno must never hold. So: the in-flight charge COMPLETES
      // and is reported truthfully — and the very next authorization on the
      // same handle denies. Deny the next, never claw back the current.
      const { a, b, dispose } = await open();
      const rail = railSpy();

      let midFlight: FreezeSnapshot | null = null;
      const result = await b.guard.execute(makeIntent(), async () => {
        // The freeze arrives — from the other process — while this charge is
        // already executing.
        midFlight = await a.freeze("charge in flight looks hostile");
        return "charged";
      });

      expect(midFlight!.frozen).toBe(true);
      // Not recalled, not reclassified: the rail ran and the result says so.
      expect(result.status).toBe("executed");
      if (result.status === "executed") expect(result.value).toBe("charged");

      // The freeze's actual power: the NEXT authorization dies.
      expectFrozenDenial(
        await b.guard.execute(makeIntent(), rail.executor),
        "charge in flight looks hostile",
      );
      expect(rail.calls).toHaveLength(0);
      await dispose();
    });
  });
}
