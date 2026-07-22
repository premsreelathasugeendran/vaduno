import type { LedgerEntry, LedgerStore } from "../ledger.js";

/** In-memory store — tests, demos, ephemeral agents. */
export class MemoryLedgerStore implements LedgerStore {
  private entries: LedgerEntry[] = [];

  async append(entry: LedgerEntry): Promise<void> {
    this.entries.push(entry);
  }

  async last(): Promise<LedgerEntry | null> {
    return this.entries.length > 0
      ? this.entries[this.entries.length - 1]!
      : null;
  }

  async all(): Promise<LedgerEntry[]> {
    return [...this.entries];
  }
}
