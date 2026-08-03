/**
 * FreezeStore semantics + createFreezeCheck, at the unit level.
 *
 * The cross-process ENFORCEMENT claim — "A freezes, B's very next execute()
 * denies" — is pinned by the conformance suite in
 * packages/guard/test/freeze.conformance.ts, run against Memory, File and
 * (env-gated) Postgres backends. What lives here is the store contract itself
 * and the check's verdicts, so a semantics regression is named by a small
 * test instead of a seven-test conformance failure.
 */
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { PaymentIntent } from "@vaduno/guard";
import {
  FileFreezeStore,
  MemoryFreezeStore,
  allChecks,
  createFreezeCheck,
  type FreezeStore,
} from "../src/index.js";

function intent(): PaymentIntent {
  return {
    id: "intent-1",
    agentId: "agent-1",
    merchant: { id: "openai", url: "https://api.openai.com" },
    amount: { amountMinor: 500, currency: "USD" },
    rail: "mock",
    requestedAt: new Date().toISOString(),
  };
}

describe("createFreezeCheck", () => {
  it("denies GUARD_FROZEN with the reason when the shared store says frozen", async () => {
    // The reason is operational evidence: an operator debugging a stopped
    // fleet needs "credentials leaked" in the denial, not a generic no.
    const store = new MemoryFreezeStore();
    await store.freeze("credentials leaked");
    const verdict = await createFreezeCheck(store)(intent());
    expect(verdict.allowed).toBe(false);
    if (!verdict.allowed) {
      expect(verdict.code).toBe("GUARD_FROZEN");
      expect(verdict.message).toContain("credentials leaked");
    }
  });

  it("allows when the store says unfrozen", async () => {
    const verdict = await createFreezeCheck(new MemoryFreezeStore())(intent());
    expect(verdict.allowed).toBe(true);
  });

  it("denies when the store THROWS — unreachable is never 'not frozen'", async () => {
    // The attack: knock the freeze backend over, then spend. The check must
    // convert the outage into a denial, or the kill switch is disableable
    // by anyone who can cause an outage.
    const dead: FreezeStore = {
      freeze: () => Promise.reject(new Error("down")),
      unfreeze: () => Promise.reject(new Error("down")),
      read: () => Promise.reject(new Error("backend unreachable")),
    };
    const verdict = await createFreezeCheck(dead)(intent());
    expect(verdict.allowed).toBe(false);
    if (!verdict.allowed) {
      expect(verdict.code).toBe("FREEZE_CHECK_FAILED");
      expect(verdict.message).toContain("backend unreachable");
    }
  });

  it("composes with allChecks: the freeze denial wins even when every other check allows", async () => {
    const store = new MemoryFreezeStore();
    await store.freeze("incident");
    const composed = allChecks(async () => ({ allowed: true }), createFreezeCheck(store));
    const verdict = await composed(intent());
    expect(verdict.allowed).toBe(false);
    if (!verdict.allowed) expect(verdict.code).toBe("GUARD_FROZEN");
  });
});

describe("MemoryFreezeStore", () => {
  it("every freeze bumps the monotonic epoch — the fence an unfreeze compares against", async () => {
    const store = new MemoryFreezeStore();
    const s1 = await store.freeze("first");
    const s2 = await store.freeze("second");
    expect(s1.frozen).toBe(true);
    expect(s2.epoch).toBeGreaterThan(s1.epoch);
  });

  it("unfreeze with a stale epoch is refused and changes NOTHING; the current epoch lifts", async () => {
    // The hazard: operator One decides to unfreeze based on the state they
    // read; operator Two freezes again in between. One's stale fence must
    // not silently lift a freeze One never evaluated.
    const store = new MemoryFreezeStore();
    const s1 = await store.freeze("first incident");
    const s2 = await store.freeze("second incident");

    const refused = await store.unfreeze(s1.epoch);
    expect(refused.ok).toBe(false);
    const after = await store.read();
    expect(after.frozen).toBe(true);
    expect(after.epoch).toBe(s2.epoch);

    const lifted = await store.unfreeze(s2.epoch);
    expect(lifted.ok).toBe(true);
    const final = await store.read();
    expect(final.frozen).toBe(false);
    // An applied unfreeze also moves the epoch — it is a state change too,
    // and a later stale freeze-era fence must not match it.
    expect(final.epoch).toBeGreaterThan(s2.epoch);
  });

  it("freeze('') never blanks a live reason; an unfreeze clears it", async () => {
    // The attack: an automated monitor calling freeze("") behind the
    // operator's back must not erase the incident evidence.
    const store = new MemoryFreezeStore();
    await store.freeze("credentials leaked");
    const overwritten = await store.freeze("   ");
    expect(overwritten.reason).toBe("credentials leaked");

    const state = await store.read();
    await store.unfreeze(state.epoch);
    // After a clean lift there is no live reason to preserve: a reasonless
    // freeze falls back to the "frozen" default, not to stale evidence.
    const refrozen = await store.freeze("");
    expect(refrozen.reason).toBe("frozen");
  });
});

describe("FileFreezeStore", () => {
  let dir: string | null = null;

  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
    dir = null;
  });

  async function freshPath(): Promise<string> {
    dir = await mkdtemp(join(tmpdir(), "vaduno-freeze-"));
    return join(dir, "freeze.json");
  }

  it("a freeze written by one store instance is read by another over the same path", async () => {
    // The cross-process claim in miniature: two store OBJECTS over one file
    // are two processes on one box.
    const path = await freshPath();
    const a = new FileFreezeStore(path);
    const b = new FileFreezeStore(path);
    await a.freeze("credentials leaked");
    const seen = await b.read();
    expect(seen.frozen).toBe(true);
    expect(seen.reason).toBe("credentials leaked");
  });

  it("the epoch CAS holds ACROSS instances: a stale fence from one refuses after the other refroze", async () => {
    const path = await freshPath();
    const a = new FileFreezeStore(path);
    const b = new FileFreezeStore(path);
    const s1 = await a.freeze("first incident");
    const s2 = await b.freeze("second incident");

    const refused = await a.unfreeze(s1.epoch);
    expect(refused.ok).toBe(false);
    expect((await b.read()).frozen).toBe(true);

    const lifted = await a.unfreeze(s2.epoch);
    expect(lifted.ok).toBe(true);
    expect((await b.read()).frozen).toBe(false);
  });

  it("a file that never existed reads as the initial unfrozen state, epoch 0", async () => {
    const store = new FileFreezeStore(await freshPath());
    const state = await store.read();
    expect(state).toEqual({ epoch: 0, frozen: false, reason: null, by: null, at: null });
  });

  it("a CORRUPT file throws — never reads as 'not frozen'", async () => {
    // The attack: damage (or doctor) the freeze file so the switch reads as
    // off. Unknown must fail closed; the guard turns this throw into a
    // denial.
    const path = await freshPath();
    await writeFile(path, "{ not json", "utf8");
    const store = new FileFreezeStore(path);
    await expect(store.read()).rejects.toThrow(/fail closed/);
    await expect(store.freeze("x")).rejects.toThrow(/fail closed/);
    await expect(store.unfreeze(0)).rejects.toThrow(/fail closed/);
  });

  it("a parseable file with an invalid SHAPE is just as unknown as a corrupt one", async () => {
    // e.g. a truncated or hand-edited row: {"epoch":"nope"} parses fine and
    // proves nothing about freeze state.
    const path = await freshPath();
    await writeFile(path, JSON.stringify({ epoch: "nope", frozen: "yes" }), "utf8");
    await expect(new FileFreezeStore(path).read()).rejects.toThrow(/invalid shape/);
  });
});
