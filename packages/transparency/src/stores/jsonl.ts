import { appendFile, mkdir, open, readFile, truncate } from "node:fs/promises";
import { dirname } from "node:path";
import type { TreeStore } from "../tree.js";

const LEAF_LINE = /^[0-9a-f]{64}$/;

/**
 * One leaf hash per line, append-only. Suited to a single-process agent
 * keeping its transparency tree next to its JSONL ledger file.
 *
 * Every line must be a 64-char lowercase-hex sha256. An UNTERMINATED final
 * line is treated as a torn tail from a crash mid-append and repaired on
 * load: a complete hash gets its missing newline; partial garbage is
 * truncated away (the mirror re-appends the lost leaf from the ledger, so
 * the tree heals). A malformed line anywhere ELSE is corruption and fails
 * closed with an error — better no tree than a wrong one.
 *
 * CACHING: none, deliberately (same reasoning as JsonlLedgerStore, but
 * strictly worse here: every line is fixed-length hex, so EVERY single-
 * character edit preserves the file's byte length and a size-checked cache
 * never notices). all() re-reads and re-validates the file on every call, so
 * heads and proofs always commit to the bytes actually on disk. append()
 * keeps only an O(1) tail probe instead of a full re-read: it checks the
 * final byte for a newline and runs the full load()/repair only when a torn
 * tail is present, because appending onto a torn line would corrupt both
 * records. That probe is a freshness check against the real file, not a
 * cache — no read result is ever remembered across calls; the only retained
 * state is `dirEnsured`, which is not tree data and self-heals via the
 * ENOENT retry in append().
 *
 * Single-writer, same contract as JsonlLedgerStore; concurrent writers (even
 * two TransparencyLog instances over one file) are unsupported and can
 * interleave.
 */
export class JsonlTreeStore implements TreeStore {
  private dirEnsured = false;

  constructor(private readonly filePath: string) {}

  private async ensureDir(): Promise<void> {
    if (this.dirEnsured) return;
    await mkdir(dirname(this.filePath), { recursive: true });
    this.dirEnsured = true;
  }

  private async load(): Promise<string[]> {
    try {
      let raw = await readFile(this.filePath, "utf8");
      // Torn tail from a crash mid-append (no trailing newline): repair it.
      if (raw.length > 0 && !raw.endsWith("\n")) {
        const tail = raw.slice(raw.lastIndexOf("\n") + 1).replace(/\r$/, "");
        if (LEAF_LINE.test(tail)) {
          // The hash made it to disk, the newline didn't. Complete the record.
          await appendFile(this.filePath, "\n", "utf8");
          raw += "\n";
        } else {
          // Partial garbage: cut back to the last complete line. The mirror
          // re-appends the lost leaf from the ledger on its next sync.
          const keep = raw.lastIndexOf("\n") + 1;
          await truncate(this.filePath, Buffer.byteLength(raw.slice(0, keep), "utf8"));
          raw = raw.slice(0, keep);
        }
      }
      const lines = raw
        .split("\n")
        .map((line) => line.replace(/\r$/, ""))
        .filter((line) => line.length > 0);
      for (let i = 0; i < lines.length; i++) {
        if (!LEAF_LINE.test(lines[i]!)) {
          throw new Error(
            `${this.filePath}: line ${i + 1} is not a leaf hash — tree file is corrupted`,
          );
        }
      }
      return lines;
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  /**
   * True when the file's final byte is "\n" (or the file is empty/absent —
   * nothing to repair). Reads exactly one byte so append() stays O(1); the
   * full O(n) load()/repair runs only on the rare crash-recovery path.
   */
  private async tailIsTerminated(): Promise<boolean> {
    let fh;
    try {
      fh = await open(this.filePath, "r");
      const size = (await fh.stat()).size;
      if (size === 0) return true;
      const buf = Buffer.alloc(1);
      await fh.read(buf, 0, 1, size - 1);
      return buf[0] === 0x0a;
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return true;
      throw err;
    } finally {
      await fh?.close();
    }
  }

  async append(leafHashHex: string): Promise<void> {
    if (!LEAF_LINE.test(leafHashHex)) {
      throw new Error(`refusing to append non-hash leaf line: ${leafHashHex.slice(0, 80)}`);
    }
    if (!(await this.tailIsTerminated())) {
      await this.load(); // load() repairs the torn tail before we extend the file
    }
    await this.ensureDir();
    const line = leafHashHex + "\n";
    try {
      await appendFile(this.filePath, line, "utf8");
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        this.dirEnsured = false;
        await this.ensureDir();
        await appendFile(this.filePath, line, "utf8");
      } else {
        throw err;
      }
    }
  }

  async all(): Promise<string[]> {
    return this.load();
  }
}
