import { appendFile, mkdir, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { LedgerEntry, LedgerStore } from "../ledger.js";

/**
 * One JSON entry per line, append-only. Suited to a single-process agent
 * writing a local flight-recorder file.
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
 * chain data and self-heals via the ENOENT retry in append().
 *
 * append() itself never reads: it only appends bytes. Chain linkage is safe
 * because AuditLedger.append derives prevHash from last(), which now always
 * reflects the real file — a write from a second instance is observed and
 * extended, not forked over. Concurrent writers are still unsafe (no file
 * lock) and unsupported — and "writers" means AuditLedger INSTANCES: two
 * instances in one process race exactly like two processes do.
 *
 * THIS DOCBLOCK USED TO SAY "use SupabaseLedgerStore for shared ledgers". That
 * was false, and corrected in 0.3.0. `AuditLedger.append` derives
 * `seq = last.seq + 1` inside a promise queue that is scoped to ONE PROCESS,
 * and `supabase/schema.sql` declares `seq bigint primary key` — so two writers
 * both read seq N, both compute N+1, and one insert collides. Worse, on the
 * final `execution_result` append that rejection is swallowed into
 * `auditDegraded`: money moved, the record was dropped, and `verify()` still
 * reports the chain intact because the winning row legitimately occupies that
 * seq.
 *
 * NO ledger store in this project is safe for concurrent writers today. Run one
 * writer per ledger. See docs/SECURITY-MODEL.md.
 */
export class JsonlLedgerStore implements LedgerStore {
  private dirEnsured = false;

  constructor(private readonly filePath: string) {}

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

  async append(entry: LedgerEntry): Promise<void> {
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

  async last(): Promise<LedgerEntry | null> {
    const entries = await this.load();
    return entries.length > 0 ? entries[entries.length - 1]! : null;
  }

  async all(): Promise<LedgerEntry[]> {
    return this.load();
  }
}
