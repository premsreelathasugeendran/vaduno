import type { SpendDecision, SpendHooks, ToolCall } from "./hooks.js";

/**
 * Binding for the Claude Agent SDK's `PreToolUse` / `PostToolUse` hooks.
 *
 * HONEST STATUS: the wire shapes below are taken from the documented hook
 * contract and have **not been run against a live Claude Agent SDK session**.
 * They are isolated in this file precisely so that if the contract has drifted,
 * the fix is a few lines here rather than anywhere near the policy path — and
 * so the untested surface is small enough to read in one sitting.
 *
 * The decision itself comes from `createSpendHooks`, which is framework-free
 * and fully tested. Everything here is translation.
 */

/** Subset of the PreToolUse hook input this binding reads. */
export interface PreToolUseInput {
  tool_name: string;
  tool_input: unknown;
}

/** Subset of the PostToolUse hook input this binding reads. */
export interface PostToolUseInput {
  tool_name: string;
  tool_input: unknown;
  /** Present on success; absent or error-shaped on failure. */
  tool_response?: unknown;
}

export interface PreToolUseOutput {
  hookSpecificOutput: {
    hookEventName: "PreToolUse";
    permissionDecision: "allow" | "deny" | "ask";
    permissionDecisionReason: string;
  };
}

const allow = (reason: string): PreToolUseOutput => ({
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "allow",
    permissionDecisionReason: reason,
  },
});

const deny = (reason: string): PreToolUseOutput => ({
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "deny",
    permissionDecisionReason: reason,
  },
});

/**
 * Track which intent id belongs to which in-flight tool call, so PostToolUse
 * can settle the right authorization.
 *
 * Keyed on the tool call's identity rather than a closure because the two hooks
 * are separate invocations. In a long-lived process you may prefer to key this
 * off your own request context; a Map is enough for a single session and is
 * bounded by the number of CONCURRENT payments, not total.
 */
export interface InFlight {
  remember(key: string, intentId: string, mandateId?: string): void;
  take(key: string): { intentId: string; mandateId?: string } | null;
}

export function memoryInFlight(): InFlight {
  const m = new Map<string, { intentId: string; mandateId?: string }>();
  return {
    remember(key, intentId, mandateId) {
      m.set(key, mandateId === undefined ? { intentId } : { intentId, mandateId });
    },
    take(key) {
      const v = m.get(key) ?? null;
      if (v) m.delete(key);
      return v;
    },
  };
}

/** Key identifying one pending tool call, matching PostToolUse to its authorization. */
function callKey(toolName: string, input: unknown): string {
  return `${toolName} ${stableStringify(input)}`;
}

/**
 * Order-stable, total serialization.
 *
 * Plain `JSON.stringify` is NOT good enough here, for two reasons found by
 * probing rather than by reading:
 *
 *  1. It is order-sensitive. `{id,amount}` and `{amount,id}` stringify
 *     differently, so a host that rebuilds `tool_input` between the two hooks
 *     loses the match — the authorization is then never settled and quietly
 *     holds budget until its window rolls off. The cap starves rather than
 *     overspends, so it is the safe failure, but it is still a failure.
 *  2. It THROWS on BigInt and on circular structures. A throw here would happen
 *     AFTER the budget was reserved, so it would escape the hook holding real
 *     money — and a host that reads a throwing hook as "no opinion" would then
 *     run the tool anyway.
 *
 * So: sort keys recursively, and never throw.
 */
function stableStringify(value: unknown, seen: Set<unknown> = new Set()): string {
  if (value === null || value === undefined) return "null";
  const t = typeof value;
  if (t === "string") return JSON.stringify(value);
  if (t === "number") return Number.isFinite(value as number) ? String(value) : "null";
  if (t === "boolean") return String(value);
  if (t === "bigint") return `"${String(value)}n"`;
  if (t === "function" || t === "symbol") return `"[${t}]"`;

  if (seen.has(value)) return '"[circular]"';
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((v) => stableStringify(v, seen)).join(",")}]`;
    }
    const obj = value as Record<string, unknown>;
    const parts = Object.keys(obj)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k], seen)}`);
    return `{${parts.join(",")}}`;
  } finally {
    seen.delete(value);
  }
}

export interface ClaudeAgentBinding {
  preToolUse(input: PreToolUseInput): Promise<PreToolUseOutput>;
  postToolUse(input: PostToolUseInput): Promise<void>;
}

export function bindClaudeAgentSdk(
  hooks: SpendHooks,
  inFlight: InFlight = memoryInFlight(),
): ClaudeAgentBinding {
  return {
    async preToolUse(input) {
      const call: ToolCall = { toolName: input.tool_name, input: input.tool_input };
      let decision: SpendDecision;
      try {
        decision = await hooks.decide(call);
      } catch (err) {
        // A hook that throws must not read as approval. Anything unexpected on
        // this path denies — the entire premise is that the model is not
        // trusted to decide, so neither is a crash.
        return deny(
          `vaduno: spend check failed, denying: ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      }

      if (decision.kind === "not-a-payment") {
        // No opinion. Returning "allow" here would OVERRIDE other permission
        // rules, so say nothing stronger than necessary.
        return allow("vaduno: not a spending tool");
      }
      if (decision.kind === "deny") {
        return deny(`vaduno: ${decision.code} — ${decision.reason}`);
      }

      inFlight.remember(
        callKey(input.tool_name, input.tool_input),
        decision.intentId,
        decision.mandateId,
      );
      return allow(`vaduno: authorized (intent ${decision.intentId})`);
    },

    async postToolUse(input) {
      const pending = inFlight.take(callKey(input.tool_name, input.tool_input));
      // Nothing pending means this tool was never authorized by us — a
      // non-payment tool, or a call that PreToolUse denied. Settling it would
      // invent a payment that never happened.
      if (!pending) return;

      const failed = looksLikeFailure(input.tool_response);
      await hooks.settled(pending.intentId, {
        ok: !failed,
        ...(failed ? { error: describeFailure(input.tool_response) } : {}),
        ...(pending.mandateId !== undefined ? { mandateId: pending.mandateId } : {}),
      });
    },
  };
}

/**
 * Best-effort read of whether a tool response represents a failure.
 *
 * Biased toward "succeeded", and that is the safe direction here: a spend
 * reported as executed stays counted against the cap, while one wrongly
 * reported as failed ALSO stays counted (burn-on-failure). Neither reading
 * frees budget, so an ambiguous response cannot inflate what an agent may
 * spend.
 */
function looksLikeFailure(response: unknown): boolean {
  if (response === undefined || response === null) return false;
  if (typeof response === "object") {
    const r = response as Record<string, unknown>;
    if (r.is_error === true || r.isError === true) return true;
    if (typeof r.error === "string" && r.error.length > 0) return true;
  }
  return false;
}

function describeFailure(response: unknown): string {
  if (response && typeof response === "object") {
    const r = response as Record<string, unknown>;
    if (typeof r.error === "string") return r.error;
  }
  return "tool reported an error";
}
