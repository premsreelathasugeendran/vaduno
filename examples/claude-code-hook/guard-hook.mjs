/**
 * A REAL Vaduno spend firewall, wired into a live Claude Code session.
 *
 * This is the honest end of the "never run against anything live" caveat. It
 * uses the published `@vaduno/agent` binding against the actual hook contract,
 * observed rather than assumed (see observe.mjs and the payloads it records).
 *
 * WHAT IT GOVERNS: a fictional `buy_credits` tool. Nothing here moves money —
 * the point is that the DECISION path runs inside a host this repo does not
 * control, on that host's real payload shapes, and that a deny actually stops a
 * tool from executing.
 *
 * WHAT IT DOES NOT TOUCH: every other tool. `resolve()` returns null for those
 * and the binding emits NO OPINION — an empty object, so the host's own
 * permission rules decide exactly as they would without this hook. Returning
 * "allow" there would silently switch those rules off, which is what this
 * package did before a live session caught it.
 */
import { readFileSync, appendFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  AuditLedger,
  JsonlLedgerStore,
  FileSpendLimiter,
  VadunoGuard,
} from "@vaduno/guard";
import { bindClaudeAgentSdk, createSpendHooks } from "@vaduno/agent";

const here = dirname(fileURLToPath(import.meta.url));
const stateDir = join(here, ".state");
const log = (msg) =>
  appendFileSync(join(here, "guard-hook.log"), `${new Date().toISOString()} ${msg}\n`, "utf8");

// $2.00/day, $0.50/txn. Deliberately small so the cap is easy to hit on purpose.
const guard = new VadunoGuard({
  policy: {
    id: "claude-code-session",
    version: 1,
    currency: "USD",
    limits: { perTransactionMinor: 50, perDayMinor: 200 },
    merchants: { allow: ["openai.com"] },
  },
  ledger: new AuditLedger(new JsonlLedgerStore(join(stateDir, "ledger.jsonl"))),
  // File-backed so the cap survives across hook invocations — each one is a
  // SEPARATE PROCESS, which is exactly the cross-process case the in-memory
  // limiter cannot hold.
  limiter: new FileSpendLimiter(join(stateDir, "limiter.json")),
});

const hooks = createSpendHooks({
  guard,
  resolve(call) {
    // PROOF PROBE. This host has no payment tool, so to demonstrate that a
    // Vaduno deny actually STOPS a real tool, one narrowly-marked Bash command
    // is treated as a $99 payment — over the $0.50 per-transaction cap, so it
    // must be denied. The marker is deliberately unmistakable: no real command
    // contains it, so ordinary work is untouched.
    if (call.toolName === "Bash") {
      const cmd = String((call.input ?? {}).command ?? "").trim();
      // EXACT match, and this is the point, not pedantry. The first version
      // used `cmd.includes(marker)` and promptly denied the git commit whose
      // MESSAGE described the marker — a resolver so greedy it blocked
      // legitimate work that merely mentioned a payment.
      //
      // Both directions of resolver error are real: too narrow and a spending
      // tool escapes the cap entirely; too broad and the firewall becomes an
      // outage. The README warns about the first. This is the second, found by
      // being bitten.
      if (cmd !== "echo VADUNO_PAYMENT_PROBE") return null;
      return {
        id: `probe-${Date.now()}`,
        agentId: "claude-code",
        merchant: { id: "openai", url: "https://api.openai.com/v1/credits" },
        amount: { amountMinor: 9_900, currency: "USD" },
        category: "api-credits",
        rail: "mock",
        requestedAt: new Date().toISOString(),
      };
    }
    if (call.toolName !== "buy_credits") return null; // not our business
    const input = call.input ?? {};
    return {
      id: String(input.orderId ?? `order-${Date.now()}`),
      agentId: "claude-code",
      merchant: { id: "openai", url: "https://api.openai.com/v1/credits" },
      amount: { amountMinor: Number(input.cents ?? 0), currency: "USD" },
      category: "api-credits",
      rail: "mock",
      requestedAt: new Date().toISOString(),
    };
  },
});

const sdk = bindClaudeAgentSdk(hooks);

let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => (raw += c));
process.stdin.on("end", async () => {
  let event;
  try {
    event = JSON.parse(raw);
  } catch {
    // Unparseable input is not a licence to allow. Say nothing and let the
    // host decide — the same posture as any other error on this path.
    process.exit(0);
  }

  try {
    const name = event.hook_event_name;
    if (name === "PreToolUse") {
      const out = await sdk.preToolUse(event);
      const decision = out?.hookSpecificOutput?.permissionDecision;
      if (decision) log(`PreToolUse ${event.tool_name} -> ${decision}`);
      // An empty object is "no opinion" and must be emitted as such.
      process.stdout.write(JSON.stringify(out));
    } else if (name === "PostToolUse") {
      await sdk.postToolUse(event);
    } else if (name === "PostToolUseFailure") {
      // Failures never arrive at PostToolUse. Without this the authorization
      // would hold budget until its window aged out.
      await sdk.postToolUseFailure(event);
      log(`PostToolUseFailure ${event.tool_name}: ${event.error ?? "interrupted"}`);
    }
  } catch (err) {
    // A crash in the firewall must never read as approval. Emit nothing:
    // no opinion, host rules apply, and the failure is recorded.
    log(`HOOK ERROR: ${err instanceof Error ? err.stack : String(err)}`);
  }
  process.exit(0);
});
