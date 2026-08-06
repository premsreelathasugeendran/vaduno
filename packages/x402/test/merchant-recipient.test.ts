import { describe, expect, it, vi } from "vitest";
import { createX402Fetch } from "../src/fetch.js";
import { X402RequirementRefusedError } from "../src/errors.js";
import { makeGuard, mockServer } from "./helpers.js";
import { mockServerV2 } from "./helpers-v2.js";

/**
 * THE HOST-PATTERN FALSE ASSURANCE, ON THE RAIL WHERE IT IS PROVABLY FALSE.
 *
 * `merchants.allow: ["host:api.example.com"]` READS as "only pay this
 * merchant". On x402 it does not mean that, and cannot: the protocol
 * DECOUPLES the recipient from the resource host — `payTo` is an arbitrary
 * address the server names in its 402, and the EIP-712 authorization the
 * payer signs commits to `payTo`, never to the URL. The adapter derives
 * `merchant.url` honestly (per request, from the origin it actually contacts
 * and origin-matched against the server's `resource` claim), so a host pattern
 * DOES police the endpoint reached — it simply says nothing about where the
 * money goes.
 *
 * Measured before this gate: a policy of `merchants.allow: ["host:api.example.com"]`
 * against a server on api.example.com naming `payTo: 0xATTACKER…` PAID, 200 OK.
 * Every policy control the operator wrote was satisfied.
 *
 * THE GOVERNING PRINCIPLE: a field is policeable iff the authorization's
 * digest commits to it. `payTo` is committed; the request URL is not. So an
 * allowlist whose ONLY entries are host-form polices an uncommitted field
 * while reading as a recipient control — and the adapter, which knows this
 * rail's commitment structure, refuses that configuration rather than
 * silently honoring it.
 *
 * NOT refused: a policy with no `merchants` block at all (the operator made no
 * merchant claim), or one carrying at least one `id:` entry (a real recipient
 * constraint — host entries then layer endpoint precision on top).
 */

const ATTACKER = "0xAtTaCkErAtTaCkErAtTaCkErAtTaCkErAtTaCkEr";

describe("a host-only merchant allowlist is refused on x402 (v1)", () => {
  it("host-only allow + attacker payTo => RECIPIENT_UNGATED, before pay()", async () => {
    const server = mockServer({ payTo: ATTACKER });
    const { guard } = makeGuard({
      merchants: { allow: ["host:api.example.com"] },
    });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({ guard, agentId: "a", pay, fetch: server.fetch });

    const err = await x402("https://api.example.com/data").catch((e) => e);
    expect(err).toBeInstanceOf(X402RequirementRefusedError);
    expect((err as X402RequirementRefusedError).code).toBe("RECIPIENT_UNGATED");
    expect(pay).not.toHaveBeenCalled();
    expect(server.paidCalls()).toBe(0);
  });

  it("a bare dotted host pattern is host-form too, and is refused the same way", async () => {
    const server = mockServer({ payTo: ATTACKER });
    const { guard } = makeGuard({ merchants: { allow: ["api.example.com"] } });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({ guard, agentId: "a", pay, fetch: server.fetch });
    const err = await x402("https://api.example.com/data").catch((e) => e);
    expect((err as X402RequirementRefusedError).code).toBe("RECIPIENT_UNGATED");
    expect(pay).not.toHaveBeenCalled();
  });

  it("an id: entry ALONGSIDE a host entry does not rescue it — allow is disjunctive", async () => {
    // The sharp case. ["host:api.example.com", "id:0x…dEaD"] reads as "this
    // host, this recipient", but `allow` is OR: the host pattern matches, so
    // the attacker payTo is admitted and the `id:` entry is decoration.
    // Verified against the pre-gate code: this configuration PAID 200 OK.
    const server = mockServer({ payTo: ATTACKER });
    const { guard } = makeGuard({
      merchants: {
        allow: ["host:api.example.com", "id:0x000000000000000000000000000000000000dEaD"],
      },
    });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({ guard, agentId: "a", pay, fetch: server.fetch });
    const err = await x402("https://api.example.com/data").catch((e) => e);
    expect((err as X402RequirementRefusedError).code).toBe("RECIPIENT_UNGATED");
    expect(pay).not.toHaveBeenCalled();
  });

  it("an id:-only allowlist is accepted, and the guard then denies the wrong payee", async () => {
    const server = mockServer({ payTo: ATTACKER });
    const { guard } = makeGuard({
      merchants: { allow: ["id:0x000000000000000000000000000000000000dEaD"] },
    });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({ guard, agentId: "a", pay, fetch: server.fetch });
    const err = await x402("https://api.example.com/data").catch((e) => e);
    expect((err as { name: string }).name).toBe("X402PaymentBlockedError");
    expect(pay).not.toHaveBeenCalled();
  });

  it("host patterns in merchants.BLOCK are untouched — matching there only denies", async () => {
    const server = mockServer();
    const { guard } = makeGuard({
      merchants: {
        allow: [`id:${server.requirement.payTo.toLowerCase()}`],
        block: ["host:evil.example.com"],
      },
    });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({ guard, agentId: "a", pay, fetch: server.fetch });
    expect((await x402("https://api.example.com/data")).status).toBe(200);
  });

  it("the honest payee still settles under an id: allowlist", async () => {
    const server = mockServer();
    const { guard } = makeGuard({
      merchants: { allow: [`id:${server.requirement.payTo.toLowerCase()}`] },
    });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({ guard, agentId: "a", pay, fetch: server.fetch });
    expect((await x402("https://api.example.com/data")).status).toBe(200);
    expect(server.paidCalls()).toBe(1);
  });

  it("no merchants block at all is NOT refused — the operator made no merchant claim", async () => {
    const server = mockServer({ payTo: ATTACKER });
    const { guard } = makeGuard({ merchants: undefined });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({ guard, agentId: "a", pay, fetch: server.fetch });
    expect((await x402("https://api.example.com/data")).status).toBe(200);
  });

  it("the explicit opt-out accepts host-only policing", async () => {
    const server = mockServer({ payTo: ATTACKER });
    const { guard } = makeGuard({ merchants: { allow: ["host:api.example.com"] } });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({
      guard,
      agentId: "a",
      pay,
      fetch: server.fetch,
      allowHostOnlyMerchantPolicy: true,
    });
    expect((await x402("https://api.example.com/data")).status).toBe(200);
  });

  it("the gate reads the LIVE policy: setPolicy() to a host-only allowlist re-closes payment", async () => {
    const server = mockServer();
    const { guard } = makeGuard({
      merchants: { allow: [`id:${server.requirement.payTo.toLowerCase()}`] },
    });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({ guard, agentId: "a", pay, fetch: server.fetch });
    expect((await x402("https://api.example.com/data")).status).toBe(200);

    await guard.setPolicy({
      id: "x402-policy",
      version: 2,
      currency: "USDC",
      limits: { perTransactionMinor: 5_000_000 },
      networks: { allow: ["base-sepolia"] },
      merchants: { allow: ["host:api.example.com"] },
    });
    const err = await x402("https://api.example.com/data").catch((e) => e);
    expect((err as X402RequirementRefusedError).code).toBe("RECIPIENT_UNGATED");
  });
});

describe("the same gate holds on the v2 carrier", () => {
  it("host-only allow => RECIPIENT_UNGATED before the v2 payer runs", async () => {
    const server = mockServerV2({ payTo: ATTACKER });
    const { guard } = makeGuard({ merchants: { allow: ["host:api.example.com"] } });
    const pay = vi.fn(async () => "payload");
    const x402 = createX402Fetch({
      guard,
      agentId: "a",
      pay: async () => "unused",
      fetch: server.fetch,
      v2: { pay },
    });
    const err = await x402("https://api.example.com/data").catch((e) => e);
    expect(err).toBeInstanceOf(X402RequirementRefusedError);
    expect((err as X402RequirementRefusedError).code).toBe("RECIPIENT_UNGATED");
    expect(pay).not.toHaveBeenCalled();
  });
});
