import type { SpendDecision, SpendHooks, ToolCall } from "./hooks.js";

/**
 * Binding for a Claude Agent SDK host's tool hooks.
 *
 * STATUS: the shapes below were OBSERVED against a live Claude Code session —
 * a passive hook recorded real `PreToolUse`, `PostToolUse` and tool-failure
 * payloads, and this file was corrected against them. Through 0.5.0 it was
 * written from documentation alone, and the drift that found was not cosmetic:
 *
 *   1. A non-payment tool returned `permissionDecision: "allow"`, which
 *      short-circuits the host's own permission evaluation. Registered with a
 *      `*` matcher, the spend firewall auto-approved every other tool in the
 *      session. Now returns `{}` — no opinion.
 *   2. A FAILED tool never reaches `postToolUse` at all; it raises a separate
 *      failure event carrying `error`. The failure heuristic here could
 *      therefore never fire, and a failed payment was never settled.
 *   3. Every event carries `tool_use_id`, the host's own correlation id —
 *      better than the input fingerprint this used to rely on.
 *
 * Those are exactly the kind of mismatch that a green test suite cannot catch,
 * because the suite and the code shared one wrong assumption about the host.
 * The observation harness lives in `examples/cli-agent-hook`; re-run it when
 * a host version changes.
 *
 * The decision itself comes from `createSpendHooks`, which is framework-free
 * and tested independently of any host. Everything here is translation.
 */

/** Subset of the PreToolUse hook input this binding reads. */
export interface PreToolUseInput {
  tool_name: string;
  tool_input: unknown;
  /**
   * The host's own correlation id, present on every hook event. OBSERVED live
   * on Claude Code. Prefer it over matching on the tool input — see `callKey`.
   */
  tool_use_id?: string;
}

/** Subset of the PostToolUse hook input this binding reads. */
export interface PostToolUseInput {
  tool_name: string;
  tool_input: unknown;
  tool_use_id?: string;
  /** The tool's result. A FAILED tool does not arrive here at all. */
  tool_response?: unknown;
}

/**
 * A tool that FAILED. Observed live: this is a SEPARATE event carrying `error`
 * and NO `tool_response` — failures never reach PostToolUse.
 */
export interface PostToolUseFailureInput {
  tool_name: string;
  tool_input: unknown;
  tool_use_id?: string;
  /** e.g. "Exit code 9". */
  error?: string;
  /** True when the user interrupted rather than the tool erroring. */
  is_interrupt?: boolean;
}

export interface PreToolUseOutput {
  hookSpecificOutput: {
    hookEventName: "PreToolUse";
    permissionDecision: "allow" | "deny" | "ask";
    permissionDecisionReason: string;
  };
}

/** No opinion: emit nothing and let the host's own permission rules decide. */
export type PreToolUseNoOpinion = Record<string, never>;

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
  preToolUse(input: PreToolUseInput): Promise<PreToolUseOutput | PreToolUseNoOpinion>;
  postToolUse(input: PostToolUseInput): Promise<void>;
  /**
   * Register this on the host's tool-FAILURE event. Without it a failed
   * payment tool is never settled and its authorization holds budget until the
   * rolling window ages out — the safe direction, but not what the docs
   * promise.
   */
  postToolUseFailure(input: PostToolUseFailureInput): Promise<void>;
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
        // NO OPINION — an empty object, not an "allow".
        //
        // This shipped as `allow(...)` through 0.5.0, with a comment saying
        // that allow would override other permission rules and must be avoided
        // — and then returning allow anyway. Observed live: a `permissionDecision`
        // of "allow" SHORT-CIRCUITS the host's normal permission evaluation. So
        // a `*`-matcher registration of this binding auto-approved every
        // non-payment tool in the session: a spend firewall that silently
        // switched off the permission prompts around it.
        return {};
      }
      if (decision.kind === "deny") {
        return deny(`vaduno: ${decision.code} — ${decision.reason}`);
      }

      inFlight.remember(correlationKey(input), decision.intentId, decision.mandateId);
      return allow(`vaduno: authorized (intent ${decision.intentId})`);
    },

    async postToolUse(input) {
      const pending = inFlight.take(correlationKey(input));
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

    async postToolUseFailure(input) {
      // Observed live: a failed tool NEVER reaches postToolUse. It arrives here
      // instead, carrying `error` and no `tool_response`. Before this handler
      // existed the authorization was simply never settled — it held budget
      // until its rolling window aged out. Over-hold rather than overspend, so
      // the safe direction, but not what the README promised.
      const pending = inFlight.take(correlationKey(input));
      if (!pending) return;

      await hooks.settled(pending.intentId, {
        // Burn on failure, deliberately: a tool that failed may still have
        // moved money before it failed, and an interrupt says even less about
        // whether the rail was reached. Freeing budget here is the one
        // direction that could overspend.
        ok: false,
        error:
          input.error ??
          (input.is_interrupt ? "interrupted before completion" : "tool failed"),
        ...(pending.mandateId !== undefined ? { mandateId: pending.mandateId } : {}),
      });
    },
  };
}

/**
 * How a pending authorization is matched from one hook event to the next.
 *
 * OBSERVED live on Claude Code: every event — PreToolUse, PostToolUse and the
 * failure event — carries `tool_use_id`, the host's own correlation id. That is
 * strictly better than fingerprinting the tool input, which this binding used
 * to do exclusively: it is stable, unique per call, and immune to a host that
 * re-serializes `tool_input` between events.
 *
 * The input fingerprint stays as the fallback for hosts that send no id.
 */
function correlationKey(input: {
  tool_name: string;
  tool_input: unknown;
  tool_use_id?: string;
}): string {
  return input.tool_use_id !== undefined
    ? `id:${input.tool_use_id}`
    : callKey(input.tool_name, input.tool_input);
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
