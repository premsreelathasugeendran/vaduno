import type { PaymentIntent, VadunoGuard } from "@vaduno/guard";

/**
 * Spend-firewall hooks for agent frameworks.
 *
 * Every framework's tool-approval hook is DECIDE-ONLY: it is handed a pending
 * tool call, returns allow or deny, and the framework runs the tool itself.
 * Claude Agent SDK `PreToolUse`, Vercel AI SDK `toolApproval`, OpenAI Agents
 * `needsApproval`, LangChain `wrapToolCall` — all the same shape. None of them
 * can use `guard.execute(intent, executor)`, which requires the guard to own
 * the call.
 *
 * So this binds to `authorize()` / `settle()` instead:
 *
 *   before the tool runs → authorize → allow or deny
 *   after the tool runs  → settle    → executed or failed
 *
 * DELIBERATELY FRAMEWORK-AGNOSTIC. The decision logic below has no import from
 * any framework and is fully tested without one; each binding is a thin
 * translation of the same `SpendDecision`. That split exists because a hook
 * signature is the part most likely to drift, and when it does, the fix should
 * be ten lines in one adapter rather than a re-audit of the policy path.
 */

/** What the guard decided about a pending tool call. */
export type SpendDecision =
  | {
      /** Not a spending tool — the guard has no opinion, let it through. */
      kind: "not-a-payment";
    }
  | {
      /** Budget reserved. The framework may run the tool; settle afterwards. */
      kind: "allow";
      intentId: string;
      /** Present when a mandate authorized this spend; pass back to `settled`. */
      mandateId?: string;
    }
  | {
      kind: "deny";
      /** Machine-readable policy code, e.g. PER_DAY_LIMIT_EXCEEDED. */
      code: string;
      reason: string;
    };

export interface SpendHooksOptions {
  guard: VadunoGuard;
  /**
   * Turn a pending tool call into a PaymentIntent, or return null when the tool
   * does not spend money.
   *
   * YOU write this, because only you know which of your tools move money and
   * how much. Returning null means "not my business" — the guard allows it
   * without recording anything, so do NOT use null as a way to skip a check on
   * a tool that does spend.
   *
   * The intent's `id` is the settlement key. Use a value that is stable for one
   * logical payment and unique across payments: reuse means the second call is
   * treated as a replay and will NOT run the rail again.
   */
  resolve: (call: ToolCall) => PaymentIntent | null | Promise<PaymentIntent | null>;
  /**
   * Called when `resolve` throws. Default: DENY.
   *
   * A resolver that throws means you cannot tell what this tool is about to
   * spend, and allowing an unknown spend is the one outcome a spend firewall
   * must never produce. Override only if you are certain the failure is benign.
   */
  onResolveError?: (err: unknown, call: ToolCall) => SpendDecision;
}

export interface ToolCall {
  toolName: string;
  input: unknown;
}

export interface SpendHooks {
  /** Decide whether a pending tool call may run. */
  decide(call: ToolCall): Promise<SpendDecision>;
  /**
   * Report what happened. Call for every ALLOWED call, including failures —
   * an unsettled authorization keeps holding budget until its window rolls off.
   */
  settled(
    intentId: string,
    outcome: { ok: boolean; error?: string; mandateId?: string },
  ): Promise<void>;
}

/**
 * Exported for tests only — deliberately NOT re-exported from the package
 * index. The "failed" branch is reachable only via a mandate's consume-once
 * registry (the spend limiter reports a settled-failed reservation as
 * `unresolved`, since a failed rail may still have charged), so testing it
 * through the public path alone would leave one of the three strings unproven.
 */
export function replayReason(
  intentId: string,
  original: "executed" | "failed" | "unresolved",
): { code: string; reason: string } {
  if (original === "executed") {
    return {
      code: "ALREADY_EXECUTED",
      reason: `intent ${intentId} was already paid; the tool was not run again`,
    };
  }
  if (original === "failed") {
    return {
      code: "ALREADY_ATTEMPTED",
      reason: `intent ${intentId} was already attempted and failed; retry with a NEW intent id rather than reusing this one`,
    };
  }
  return {
    code: "INTENT_UNRESOLVED",
    // Either still in flight, or its first attempt never reported back (e.g. a
    // crash mid-payment). Money may or may not have moved — that is exactly why
    // it must not be re-run, and why the message must not claim either way.
    reason: `intent ${intentId} is already outstanding and its outcome is unknown; reconcile it before retrying, and use a new intent id`,
  };
}

export function createSpendHooks(opts: SpendHooksOptions): SpendHooks {
  const { guard, resolve } = opts;
  const onResolveError =
    opts.onResolveError ??
    ((err: unknown): SpendDecision => ({
      kind: "deny",
      code: "INTENT_RESOLVE_FAILED",
      // Fail closed. An unresolvable tool call is an unknown spend.
      reason: `could not determine what this tool would spend: ${
        err instanceof Error ? err.message : String(err)
      }`,
    }));

  return {
    async decide(call) {
      let intent: PaymentIntent | null;
      try {
        intent = await resolve(call);
      } catch (err) {
        return onResolveError(err, call);
      }
      if (intent === null) return { kind: "not-a-payment" };

      const result = await guard.authorize(intent);

      if (result.status === "authorized") {
        return {
          kind: "allow",
          intentId: result.intentId,
          ...(result.mandateId ? { mandateId: result.mandateId } : {}),
        };
      }

      if (result.status === "replayed") {
        // This intent id was already consumed. Allowing the tool would run the
        // rail a second time, which is precisely what consume-once prevents.
        //
        // The three original states are NOT interchangeable and the model reads
        // this string: telling it a payment "already executed" when the first
        // attempt is merely outstanding would invite it to report success for a
        // charge that may never have happened.
        return { kind: "deny", ...replayReason(result.intentId, result.original.status) };
      }

      const first =
        "policyResult" in result ? result.policyResult?.reasons?.[0] : undefined;
      return {
        kind: "deny",
        code: first?.code ?? result.status.toUpperCase(),
        reason: first?.message ?? `guard returned ${result.status}`,
      };
    },

    async settled(intentId, outcome) {
      await guard.settle(intentId, {
        status: outcome.ok ? "executed" : "failed",
        ...(outcome.error !== undefined ? { error: outcome.error } : {}),
        ...(outcome.mandateId !== undefined ? { mandateId: outcome.mandateId } : {}),
      });
    },
  };
}
