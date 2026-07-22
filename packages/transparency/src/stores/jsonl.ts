import { appendFile, mkdir, readFile, stat, truncate } from "node:fs/promises";
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
 * Single-writer, same contract as JsonlLedgerStore: the cache reloads if the
 * file changed on disk; concurrent writers (even two TransparencyLog
 * instances over one file) are unsupported and can interleave.
 */
export class JsonlTreeStore implements TreeStore {
  private cache: string[] | null = null;
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

  private async load(): Promise<string[]> {
    if (this.cache) {
      const size = await this.currentSize();
      if (size === this.knownSize) return this.cache;
      this.cache = null;
    }
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
      this.knownSize = Buffer.byteLength(raw, "utf8");
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
      this.cache = lines;
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

  async append(leafHashHex: string): Promise<void> {
    if (!LEAF_LINE.test(leafHashHex)) {
      throw new Error(`refusing to append non-hash leaf line: ${leafHashHex.slice(0, 80)}`);
    }
    const hashes = await this.load(); // load() also repairs any torn tail
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
    hashes.push(leafHashHex);
    this.knownSize += Buffer.byteLength(line, "utf8");
  }

  async all(): Promise<string[]> {
    return [...(await this.load())];
  }
}
