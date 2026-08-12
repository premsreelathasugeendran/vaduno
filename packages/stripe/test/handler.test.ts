import { describe, expect, it, vi } from "vitest";
import { createStripeAuthorizationHandler } from "../src/handler.js";
import { fakeAuthEvent, makeGuard, mockStripe, raw } from "./helpers.js";

function setup(policyOver = {}, over = {}) {
  const { guard, ledger } = makeGuard(policyOver);
  const handler = createStripeAuthorizationHandler({
    guard,
    stripe: mockStripe(),
    webhookSecret: "whsec_test",
    apiVersion: "2026-06-24.dahlia",
    ...over,
  });
  return { guard, ledger, handler };
}

function body(res: { body: string }) {
  return JSON.parse(res.body) as { approved: boolean; metadata?: Record<string, string>; received?: boolean };
}

describe("createStripeAuthorizationHandler", () => {
  it("approves a within-limits authorization and records the full trail", async () => {
    const { handler, ledger } = setup();
    const res = await handler(raw(fakeAuthEvent({ amount: 900 })), "good");
    expect(res.status).toBe(200);
    expect(res.headers["Stripe-Version"]).toBe("2026-06-24.dahlia");
    expect(body(res).approved).toBe(true);

    const types = (await ledger.all()).map((e) => e.type);
    expect(types).toEqual(["intent_received", "policy_decision", "execution_started", "execution_result"]);
    expect((await ledger.verify()).ok).toBe(true);
  });

  it("declines over the per-transaction limit and does not count the spend", async () => {
    const { handler, ledger } = setup({ limits: { perTransactionMinor: 2_000, perDayMinor: 20_000 } });
    const res = await handler(raw(fakeAuthEvent({ amount: 5_000 })), "good");
    expect(body(res).approved).toBe(false);
    expect(body(res).metadata?.vaduno_reasons).toContain("PER_TXN_LIMIT_EXCEEDED");
    const exec = (await ledger.all()).find((e) => e.type === "execution_result");
    expect(exec).toBeUndefined(); // never executed
  });

  it("reads pending_request.amount, not the top-level 0", async () => {
    // top-level amount is 0; pending_request says 9000 (> 5000 cap) -> decline.
    const { handler } = setup();
    const res = await handler(raw(fakeAuthEvent({ amount: 9_000 })), "good");
    expect(body(res).approved).toBe(false);
  });

  it("enforces the rolling daily window across Issuing approvals", async () => {
    const { handler } = setup({ limits: { perTransactionMinor: 8_000, perDayMinor: 10_000 } });
    expect(body(await handler(raw(fakeAuthEvent({ amount: 6_000 })), "good")).approved).toBe(true);
    // 6000 + 6000 = 12000 > 10000/day
    expect(body(await handler(raw(fakeAuthEvent({ amount: 6_000 })), "good")).approved).toBe(false);
  });

  it("is idempotent: a retried delivery returns the same answer and counts once", async () => {
    const { handler, ledger } = setup();
    const ev = fakeAuthEvent({ id: "iauth_dupe", amount: 900 });
    const first = await handler(raw(ev), "good");
    const second = await handler(raw(ev), "good");
    expect(first.body).toBe(second.body);
    const execs = (await ledger.all()).filter((e) => e.type === "execution_result");
    expect(execs.length).toBe(1); // recorded once
  });

  it("rejects a bad signature without invoking the guard", async () => {
    const { handler, ledger } = setup();
    const res = await handler(raw(fakeAuthEvent()), "bad");
    expect(res.status).toBe(400);
    expect(await ledger.all()).toHaveLength(0);
  });

  it("declines while the guard is frozen", async () => {
    const { guard, handler } = setup();
    await guard.freeze("incident");
    const res = await handler(raw(fakeAuthEvent({ amount: 100 })), "good");
    expect(body(res).approved).toBe(false);
    expect(body(res).metadata?.vaduno_reasons).toContain("GUARD_FROZEN");
  });

  it("declines a blocked category", async () => {
    const { handler } = setup({ categories: { block: ["gambling"] } });
    const res = await handler(raw(fakeAuthEvent({ amount: 500, category: "gambling" })), "good");
    expect(body(res).approved).toBe(false);
    expect(body(res).metadata?.vaduno_reasons).toContain("CATEGORY_BLOCKED");
  });

  it("declines when the rail is not allowlisted", async () => {
    const { handler } = setup({ rails: { allow: ["x402"] } });
    const res = await handler(raw(fakeAuthEvent({ amount: 500 })), "good");
    expect(body(res).approved).toBe(false);
    expect(body(res).metadata?.vaduno_reasons).toContain("RAIL_NOT_ALLOWED");
  });

  it("acks non-request events and fires onReconcile", async () => {
    const onReconcile = vi.fn();
    const { handler } = setup({}, { onReconcile });
    const ev = { id: "evt_x", type: "issuing_transaction.created", data: { object: { id: "ipi_1" } } };
    const res = await handler(JSON.stringify(ev), "good");
    expect(res.status).toBe(200);
    expect(body(res).received).toBe(true);
    await new Promise((r) => setTimeout(r, 5));
    expect(onReconcile).toHaveBeenCalledOnce();
  });

  it("never throws on the request path — malformed pending_request declines", async () => {
    const { handler } = setup();
    const ev = fakeAuthEvent();
    (ev.data.object as { pending_request: unknown }).pending_request = null;
    const res = await handler(raw(ev), "good");
    expect(res.status).toBe(200);
    expect(body(res).approved).toBe(false); // NaN amount -> INVALID_AMOUNT
  });

  it("declines a currency mismatch (policy USD vs card EUR)", async () => {
    const { handler } = setup();
    const res = await handler(raw(fakeAuthEvent({ amount: 500, currency: "eur" })), "good");
    expect(body(res).approved).toBe(false);
    expect(body(res).metadata?.vaduno_reasons).toContain("CURRENCY_MISMATCH");
  });

  it("calls onDecision with the outcome", async () => {
    const onDecision = vi.fn();
    const { handler } = setup({}, { onDecision });
    await handler(raw(fakeAuthEvent({ amount: 900 })), "good");
    expect(onDecision).toHaveBeenCalledOnce();
    expect(onDecision.mock.calls[0]![0]).toMatchObject({ approved: true, status: "executed" });
  });

  it("a throwing onDecision cannot reject the handler (stays fail-safe, returns a decision)", async () => {
    const { handler } = setup({}, {
      onDecision: () => {
        throw new Error("metrics blew up");
      },
    });
    const res = await handler(raw(fakeAuthEvent({ amount: 900 })), "good");
    expect(res.status).toBe(200);
    expect(body(res).approved).toBe(true);
  });

  it("coalesces concurrent duplicate deliveries: guard runs once, counted once, same answer", async () => {
    const { handler, ledger } = setup({ limits: { perTransactionMinor: 6_000, perDayMinor: 10_000 } });
    const ev = fakeAuthEvent({ id: "iauth_race", amount: 6_000 });
    // Two concurrent deliveries of the SAME authorization id.
    const [a, b] = await Promise.all([handler(raw(ev), "good"), handler(raw(ev), "good")]);
    expect(body(a).approved).toBe(body(b).approved); // same answer
    const execs = (await ledger.all()).filter((e) => e.type === "execution_result");
    expect(execs.length).toBe(1); // spend counted exactly once, not twice
  });

  it("declines in-window when the decision exceeds the deadline", async () => {
    // A guard whose ledger append blocks longer than the deadline.
    const { guard } = makeGuard();
    const slowGuard = {
      execute: () => new Promise(() => {}), // never resolves
    } as unknown as typeof guard;
    const handler = createStripeAuthorizationHandler({
      guard: slowGuard,
      stripe: mockStripe(),
      webhookSecret: "whsec_test",
      apiVersion: "2026-06-24.dahlia",
      decisionTimeoutMs: 40,
    });
    const res = await handler(raw(fakeAuthEvent({ amount: 900 })), "good");
    expect(res.status).toBe(200);
    expect(body(res).approved).toBe(false);
    expect(body(res).metadata?.vaduno_reasons).toContain("DECISION_TIMEOUT");
  });

  it("REGRESSION: a HUNG idempotency store get() cannot block handle() past the deadline", async () => {
    // decisionTimeoutMs bounds the WHOLE request path, not just guard.execute.
    // If an external DecisionStore's get() stalls (network partition, dead
    // Redis), the response must still come back in-window and fail closed —
    // otherwise Stripe's account default decides, which may APPROVE.
    const { guard } = makeGuard();
    const hungGet = {
      get: () => new Promise<never>(() => {}), // never settles
      set: async () => undefined,
    };
    const handler = createStripeAuthorizationHandler({
      guard,
      stripe: mockStripe(),
      webhookSecret: "whsec_test",
      apiVersion: "2026-06-24.dahlia",
      decisionTimeoutMs: 50,
      idempotencyStore: hungGet,
    });
    const res = await resolvesWithin(
      handler(raw(fakeAuthEvent({ amount: 900 })), "good"),
      500, // 10x the deadline — plenty of slack, still far under Stripe's ~2s
      "get-hang",
    );
    expect(res.status).toBe(200);
    expect(body(res).approved).toBe(false); // fail closed, never the account default
  });

  it("REGRESSION: a HUNG idempotency store set() cannot swallow an already-computed decision", async () => {
    // The guard has already DECLINED (99,999 >> perTransactionMinor 5,000);
    // a hung set() must not keep that answer from ever reaching Stripe.
    const { guard } = makeGuard();
    const hungSet = {
      get: async () => null,
      set: () => new Promise<never>(() => {}), // never settles
    };
    const handler = createStripeAuthorizationHandler({
      guard,
      stripe: mockStripe(),
      webhookSecret: "whsec_test",
      apiVersion: "2026-06-24.dahlia",
      decisionTimeoutMs: 50,
      idempotencyStore: hungSet,
    });
    const res = await resolvesWithin(
      handler(raw(fakeAuthEvent({ amount: 99_999 })), "good"),
      500,
      "set-hang",
    );
    expect(res.status).toBe(200);
    expect(body(res).approved).toBe(false);
    expect(body(res).metadata?.vaduno_reasons).toContain("PER_TXN_LIMIT_EXCEEDED");
  });

  it("a SLOW-but-working set() is still awaited (bounded, not fire-and-forget)", async () => {
    // Multi-instance retry dedupe wants the record written before we answer
    // when the store is merely slow — only a HUNG store gets cut loose.
    const { guard } = makeGuard();
    let setDone = false;
    const slowSet = {
      get: async () => null,
      set: () =>
        new Promise<void>((r) =>
          setTimeout(() => {
            setDone = true;
            r();
          }, 30),
        ),
    };
    const handler = createStripeAuthorizationHandler({
      guard,
      stripe: mockStripe(),
      webhookSecret: "whsec_test",
      apiVersion: "2026-06-24.dahlia",
      decisionTimeoutMs: 1000,
      idempotencyStore: slowSet,
    });
    const res = await handler(raw(fakeAuthEvent({ amount: 900 })), "good");
    expect(body(res).approved).toBe(true);
    expect(setDone).toBe(true); // the answer waited for the (in-budget) write
  });
});

/** Resolve p's value if it settles within ms; otherwise fail the test loudly. */
async function resolvesWithin<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  const sentinel = Symbol("timeout");
  const won = await Promise.race([
    p,
    new Promise<typeof sentinel>((r) => setTimeout(() => r(sentinel), ms)),
  ]);
  if (won === sentinel) {
    throw new Error(`${label}: handle() still pending after ${ms}ms (blocked past the deadline)`);
  }
  return won as T;
}
