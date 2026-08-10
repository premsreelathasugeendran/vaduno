/**
 * Passive hook observer — records what Claude Code ACTUALLY sends, and blocks
 * nothing.
 *
 * WHY THIS EXISTS: `@vaduno/agent`'s Claude Agent SDK binding was written from
 * the documented hook contract and has never run in a live session. Its README
 * says so. This script is step one of removing that caveat: capture the real
 * PreToolUse / PostToolUse payloads from a running host, so the binding can be
 * checked against observation rather than against a reading.
 *
 * SAFETY: it appends one JSON line per invocation and exits 0 with no stdout.
 * An empty PreToolUse response is "no opinion" — the tool proceeds under the
 * host's normal permission rules. This cannot deny, allow, or alter anything;
 * if it crashes, the worst case is a missing log line.
 */
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const logPath = join(here, "observed-payloads.jsonl");

let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => {
  raw += c;
});
process.stdin.on("end", () => {
  try {
    mkdirSync(dirname(logPath), { recursive: true });
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      parsed = { PARSE_FAILED: true, raw: raw.slice(0, 4000) };
    }
    appendFileSync(
      logPath,
      JSON.stringify({
        observedAt: new Date().toISOString(),
        // Record the SHAPE separately from the values: the shape is what the
        // binding depends on, and it is what may have drifted.
        topLevelKeys: parsed && typeof parsed === "object" ? Object.keys(parsed) : null,
        payload: parsed,
      }) + "\n",
      "utf8",
    );
  } catch {
    // Never let an observer break a session. Silence is correct here.
  }
  // No stdout, exit 0 => no opinion. The tool call proceeds normally.
  process.exit(0);
});
