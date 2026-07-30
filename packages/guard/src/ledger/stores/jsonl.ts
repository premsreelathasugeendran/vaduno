import { appendFile, mkdir, readFile, stat } from "node:fs/promises";
import { dirname } from "node:path";
import type { LedgerEntry, LedgerStore } from "../ledger.js";

/**
 * One JSON entry per line, append-only. Suited to a single-process agent
 * writing a local flight-recorder file.
 *
 * Single-writer: if the file changes on disk behind this instance's back
 * (another process/instance appended), the cache is reloaded before the next
 * append so two instances on one file cannot silently fork the hash chain.
 * Concurrent writers from separate processes are still unsafe (no file lock)
 * and unsupported.
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
  private cache: LedgerEntry[] | null = null;
  /** Byte size of the file as last observed by this instance. */
  private knownSize = 0;
  private dirEnsured = false;

  constructor(private readonly filePath: string) {}

  private async ensureDir(): Promise<void> {
    if (this.dirEnsured) return;
    await mkdir(dirname(this.filePath), { recursive: true });
    this.dirEnsured = true;
  }

  private async currentSize(): Promise<number> {
    try {
      return (await stat(this.filePath)).size;
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return 0;
      throw err;
    }
  }

  private async load(): Promise<LedgerEntry[]> {
    if (this.cache) {
      // Reload if the file grew/changed under us since we last read it.
      const size = await this.currentSize();
      if (size === this.knownSize) return this.cache;
      this.cache = null;
    }
    try {
      const raw = await readFile(this.filePath, "utf8");
      this.knownSize = Buffer.byteLength(raw, "utf8");
      this.cache = raw
        .split("\n")
        .filter((line) => line.trim().length > 0)
        .map((line) => JSON.parse(line) as LedgerEntry);
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        this.cache = [];
        this.knownSize = 0;
      } else {
        throw err;
      }
    }
    return this.cache!;
  }

  async append(entry: LedgerEntry): Promise<void> {
    const entries = await this.load();
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
    entries.push(entry);
    this.knownSize += Buffer.byteLength(line, "utf8");
  }

  async last(): Promise<LedgerEntry | null> {
    const entries = await this.load();
    return entries.length > 0 ? entries[entries.length - 1]! : null;
  }

  async all(): Promise<LedgerEntry[]> {
    return [...(await this.load())];
  }
}
