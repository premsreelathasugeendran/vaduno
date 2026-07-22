import { appendFile, readFile, stat } from "node:fs/promises";
import type { LedgerEntry, LedgerStore } from "../ledger.js";

/**
 * One JSON entry per line, append-only. Suited to a single-process agent
 * writing a local flight-recorder file.
 *
 * Single-writer: if the file changes on disk behind this instance's back
 * (another process/instance appended), the cache is reloaded before the next
 * append so two instances on one file cannot silently fork the hash chain.
 * Concurrent writers from separate processes are still unsafe (no file lock)
 * and unsupported — use SupabaseLedgerStore for shared ledgers.
 */
export class JsonlLedgerStore implements LedgerStore {
  private cache: LedgerEntry[] | null = null;
  /** Byte size of the file as last observed by this instance. */
  private knownSize = 0;

  constructor(private readonly filePath: string) {}

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
    const line = JSON.stringify(entry) + "\n";
    await appendFile(this.filePath, line, "utf8");
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
