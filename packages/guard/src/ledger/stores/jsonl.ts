import { appendFile, mkdir, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { FileMutex, type FileMutexOpts } from "../../enforce/file-mutex.js";
import { GENESIS_HASH } from "../ledger.js";
import type {
  ExpectedTip,
  LedgerAppendResult,
  LedgerEntry,
  LedgerStore,
} from "../ledger.js";

/**
 * One JSON entry per line, append-only — a local flight-recorder file that
 * several processes on one box may write.
 *
 * CONCURRENT WRITERS (0.3.0): append() is compare-and-append under a
 * FileMutex — the same O_EXCL + owner-token lockfile primitive that
 * FileConsumeStore and FileSpendLimiter share. The tip is RE-READ UNDER THE
 * LOCK, compared to the caller's expected tip, and the line is written only on
 * a match, so two instances — in one process or two — serialize instead of
 * forking the chain, and a loser is told the real tip to re-chain onto.
 * Residual, inherited from FileMutex and documented there: a holder that
 * stalls past `staleMs` (default 30s) mid-append is treated as dead and
 * reclaimed, briefly permitting two holders — a stall that long means the
 * process is effectively dead, but it is a window, not a proof.
 * (Before 0.3.0 this store had no lock at all and a second writer forked the
 * file; the docblock's advice then was "run one writer per ledger".)
 *
 * CACHING: none, deliberately. Every read path (all(), last()) re-reads the
 * file from disk. An earlier version cached the parsed chain and invalidated
 * it on stat().size changes, but a byte-length-preserving edit to the file
 * leaves the size unchanged, so a long-lived instance kept serving the
 * pre-tamper chain — verify() said ok:true about bytes it never looked at,
 * and even verify(retainedHead) was defeated because the stale chain still
 * ended at the retained head. No cheap freshness signal closes this: mtime
 * has coarse granularity and is trivially forgeable (utimes), and a content
 * hash costs the full read it was meant to avoid. A security-labelled API
 * returning a false "ok" is worse than a slow one, so reads pay for the
 * truth. The only retained in-memory state is `dirEnsured`, which is not
 * chain data and self-heals via the ENOENT retry in writeLine().
 *
 * THIS DOCBLOCK USED TO SAY "use SupabaseLedgerStore for shared ledgers", back
 * when NO store here survived a second writer. Both halves of that are fixed
 * in 0.3.0: every store is now compare-and-append (Supabase via its
 * primary-key + unique prev_hash constraints, this one via the lock above).
 */
export class JsonlLedgerStore implements LedgerStore {
  private dirEnsured = false;
  private readonly mutex: FileMutex;

  constructor(
    private readonly filePath: string,
    lockOpts: FileMutexOpts = {},
  ) {
    this.mutex = new FileMutex(`${filePath}.lock`, () => new Date(), lockOpts);
  }

  private async ensureDir(): Promise<void> {
    if (this.dirEnsured) return;
    await mkdir(dirname(this.filePath), { recursive: true });
    this.dirEnsured = true;
  }

  private async load(): Promise<LedgerEntry[]> {
    try {
      const raw = await readFile(this.filePath, "utf8");
      return raw
        .split("\n")
        .filter((line) => line.trim().length > 0)
        .map((line) => JSON.parse(line) as LedgerEntry);
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  private async writeLine(entry: LedgerEntry): Promise<void> {
    await this.ensureDir();
    const line = JSON.stringify(entry) + "\n";
    try {
      await appendFile(this.filePath, line, "utf8");
    } catch (err: unknown) {
      // Directory vanished mid-run: don't trust the cached "ensured" flag —
      // recreate and retry once before giving up (append is fail-closed above).
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        this.dirEnsured = false;
        await this.ensureDir();
        await appendFile(this.filePath, line, "utf8");
      } else {
        throw err;
      }
    }
  }

  append(entry: LedgerEntry, expected: ExpectedTip): Promise<LedgerAppendResult> {
    return this.mutex.run(async () => {
      // RE-READ UNDER THE LOCK. The tip observed before acquisition may be a
      // rival's victim: comparing against anything read outside the lock
      // reintroduces the check-then-act gap the lock exists to close.
      const entries = await this.load();
      const tail = entries.length > 0 ? entries[entries.length - 1]! : null;
      const tipSeq = tail ? tail.seq : -1;
      const tipHash = tail ? tail.hash : GENESIS_HASH;
      if (tipSeq !== expected.prevSeq || tipHash !== expected.prevHash) {
        return {
          ok: false as const,
          tip: tail ? { seq: tail.seq, hash: tail.hash } : null,
        };
      }
      await this.writeLine(entry);
      return { ok: true as const };
    });
  }

  async last(): Promise<LedgerEntry | null> {
    const entries = await this.load();
    return entries.length > 0 ? entries[entries.length - 1]! : null;
  }

  async all(): Promise<LedgerEntry[]> {
    return this.load();
  }
}
