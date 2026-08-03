import { GENESIS_HASH } from "../ledger.js";
import type {
  ExpectedTip,
  LedgerAppendResult,
  LedgerEntry,
  LedgerStore,
} from "../ledger.js";

/** In-memory store — tests, demos, ephemeral agents. */
export class MemoryLedgerStore implements LedgerStore {
  private entries: LedgerEntry[] = [];

  /**
   * LOAD-BEARING: the tail comparison and the push are ONE SYNCHRONOUS BODY
   * with no `await` between them, so JS single-threading makes the
   * compare-and-append atomic with no lock. Deliberately NOT declared `async`:
   * inserting an `await` between the compare and the push is the one-keyword
   * edit that reopens the concurrent-writer fork, and on a non-async method
   * that edit no longer compiles.
   */
  append(entry: LedgerEntry, expected: ExpectedTip): Promise<LedgerAppendResult> {
    const tail =
      this.entries.length > 0 ? this.entries[this.entries.length - 1]! : null;
    const tipSeq = tail ? tail.seq : -1;
    const tipHash = tail ? tail.hash : GENESIS_HASH;
    if (tipSeq !== expected.prevSeq || tipHash !== expected.prevHash) {
      return Promise.resolve({
        ok: false,
        tip: tail ? { seq: tail.seq, hash: tail.hash } : null,
      });
    }
    this.entries.push(entry);
    return Promise.resolve({ ok: true });
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
