import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FileMutex } from "../src/enforce/file-mutex.js";

/**
 * FileMutex is the cross-process exclusion under FOUR correctness properties:
 * the ledger's compare-and-append (a fork), the consume store (a double
 * spend), the spend limiter (a cap bypass), and the revocation freeze store.
 * Two simultaneous holders breaks all four, silently. It had no test.
 *
 * THE ONE MECHANISM THAT CAN PRODUCE TWO HOLDERS is stale reclaim: a lock
 * older than `staleMs` is treated as abandoned and deleted so a crashed
 * process cannot wedge the system forever. That decision used to rest on a
 * single WALL-CLOCK subtraction, `now() - lockfile.mtimeMs > staleMs`, against
 * an mtime that a live holder never refreshed. Consequences:
 *
 *  - A FORWARD CLOCK JUMP of more than staleMs — an NTP correction, a VM
 *    resume, a manual set — instantly ages EVERY live lock past the
 *    threshold, and the next acquirer deletes a lock whose holder is mid
 *    critical section. Nothing about the load or the holder is anomalous; the
 *    clock moved. This is precisely the shape of a failure that happens once
 *    and never reproduces.
 *  - Even without a jump, "the holder has held it for 30s" was inferred from
 *    a timestamp written once at creation, so a slow-but-alive holder was
 *    indistinguishable from a dead one.
 *
 * THE FIX, in two parts that only work together:
 *  1. HEARTBEAT — a holder refreshes the lockfile's mtime while it works, so
 *     mtime means "the holder was alive this recently" rather than "the lock
 *     was created this long ago".
 *  2. CONFIRMED RECLAIM — a stale-looking lock is not deleted on first sight.
 *     The reclaimer records its mtime, waits, re-stats, and reclaims only if
 *     nothing refreshed it. A live holder's heartbeat lands in that window and
 *     aborts the reclaim; a dead holder's never does, so crash recovery is
 *     unchanged.
 */

let dir: string;
let lockPath: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "vaduno-mutex-"));
  lockPath = join(dir, "x.lock");
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("FileMutex never admits two simultaneous holders", () => {
  it("a rival whose WALL CLOCK jumped past staleMs must not reclaim a LIVE lock", async () => {
    // A holds the lock for 400ms. B is a separate "process" (its own FileMutex
    // over the same path) whose clock reads 10 minutes ahead — far past the
    // 200ms staleMs configured here. Under the old rule B computes
    // now - mtimeMs = 600_000 > 200, deletes A's lock, and walks in.
    const jump = 10 * 60_000;
    const a = new FileMutex(lockPath, () => new Date(), { staleMs: 200 });
    const b = new FileMutex(lockPath, () => new Date(Date.now() + jump), {
      staleMs: 200,
      retries: 200,
      delayMs: 10,
    });

    let aInside = false;
    let overlapped = false;

    const aRun = a.run(async () => {
      aInside = true;
      await sleep(400);
      aInside = false;
    });
    // Let A get in first.
    await sleep(30);
    const bRun = b.run(async () => {
      if (aInside) overlapped = true;
    });

    await Promise.all([aRun, bRun]);
    expect(overlapped).toBe(false);
  });

  it("a rival with a NORMAL clock never reclaims a live lock either", async () => {
    const a = new FileMutex(lockPath, () => new Date(), { staleMs: 100 });
    const b = new FileMutex(lockPath, () => new Date(), {
      staleMs: 100,
      retries: 200,
      delayMs: 10,
    });
    let aInside = false;
    let overlapped = false;
    const aRun = a.run(async () => {
      aInside = true;
      // Deliberately longer than staleMs: a slow-but-alive holder must not be
      // mistaken for a dead one.
      await sleep(500);
      aInside = false;
    });
    await sleep(20);
    const bRun = b.run(async () => {
      if (aInside) overlapped = true;
    });
    await Promise.all([aRun, bRun]);
    expect(overlapped).toBe(false);
  });

  it("a live holder refreshes the lock's mtime — the heartbeat is observable", async () => {
    const a = new FileMutex(lockPath, () => new Date(), { staleMs: 120 });
    let first = 0;
    let last = 0;
    await a.run(async () => {
      first = (await stat(lockPath)).mtimeMs;
      await sleep(400);
      last = (await stat(lockPath)).mtimeMs;
    });
    expect(last).toBeGreaterThan(first);
  });

  it("a genuinely ABANDONED lock is still reclaimed — crash recovery holds", async () => {
    // No holder: a lockfile left by a dead process. Nothing refreshes it, so
    // the confirmed reclaim proceeds and the waiter gets in.
    const orphan = new FileMutex(lockPath, () => new Date(), { staleMs: 50 });
    // Acquire and abandon: take the lock, then drop the reference without
    // releasing, exactly as a crash would.
    await (orphan as unknown as { acquire(): Promise<void> }).acquire();

    const b = new FileMutex(lockPath, () => new Date(), {
      staleMs: 50,
      retries: 400,
      delayMs: 10,
    });
    let ran = false;
    await b.run(async () => {
      ran = true;
    });
    expect(ran).toBe(true);
  });

  it("mutual exclusion holds under contention from many rivals", async () => {
    const mutexes = Array.from(
      { length: 6 },
      () =>
        new FileMutex(lockPath, () => new Date(), {
          staleMs: 5_000,
          retries: 500,
          delayMs: 5,
        }),
    );
    let inside = 0;
    let maxInside = 0;
    await Promise.all(
      Array.from({ length: 24 }, (_, i) =>
        mutexes[i % mutexes.length]!.run(async () => {
          inside += 1;
          maxInside = Math.max(maxInside, inside);
          await sleep(2);
          inside -= 1;
        }),
      ),
    );
    expect(maxInside).toBe(1);
  });
});
