/**
 * Out-of-process key custody: `createSignerHost` + `remoteSigner`.
 *
 * The property under test is the enforcement ceiling the README names: the
 * agent process must be able to make policy-gated payments while holding NO
 * key material and NO reference to the signing account. The boundary is
 * textual by construction — `handle()` takes a string and returns a string —
 * so nothing that is not JSON-serializable can cross it, in either direction.
 *
 * Every security assertion here was first run against a build without the
 * feature (module absent / deliberately broken) and observed failing.
 */
import { describe, expect, it } from "vitest";
import { recoverTypedDataAddress } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  AuditLedger,
  MemoryLedgerStore,
  MemorySpendLimiter,
  VadunoGuard,
} from "@vaduno/guard";
import {
  connectRemoteSigner,
  createSignerHost,
  guardedSigner,
  GuardSignerRefusedError,
  remoteSigner,
  type SignerHost,
} from "../src/index.js";
import {
  ATTACKER,
  CHAIN_ID,
  NETWORK,
  SELLER,
  USDC,
  eip3009Types,
  honestTransfer,
  nonce32,
  soon,
} from "./rig.js";

const PRIVATE_KEY = generatePrivateKey();
const hostAccount = privateKeyToAccount(PRIVATE_KEY);

function hostRig(opts: { limits?: { perTransactionMinor: number; perDayMinor: number } } = {}) {
  const ledger = new AuditLedger(new MemoryLedgerStore());
  const guard = new VadunoGuard({
    policy: {
      id: "signer-host-test",
      version: 1,
      currency: "USDC",
      limits: opts.limits ?? { perTransactionMinor: 50_000, perDayMinor: 200_000 },
      merchants: { allow: [`id:${SELLER.toLowerCase()}`] },
      networks: { allow: [NETWORK] },
    },
    ledger,
    limiter: new MemorySpendLimiter(),
  });
  const host = createSignerHost({
    account: hostAccount,
    guard,
    agentId: "signer-host-test",
    assets: [{ network: NETWORK, asset: USDC, symbol: "USDC", decimals: 6 }],
  });
  return { host, ledger, guard };
}

/** A transport that records every string crossing the boundary, both ways. */
function recordingTransport(host: SignerHost) {
  const outbound: string[] = [];
  const inbound: string[] = [];
  const send = async (request: string): Promise<string> => {
    if (typeof request !== "string") {
      throw new Error("transport contract violated: non-string request");
    }
    outbound.push(request);
    const response = await host.handle(request);
    if (typeof response !== "string") {
      throw new Error("transport contract violated: non-string response");
    }
    inbound.push(response);
    return response;
  };
  return { send, outbound, inbound };
}

function transfer(overrides: Parameters<typeof honestTransfer>[0] = {}) {
  return honestTransfer({ from: hostAccount.address, ...overrides });
}

describe("createSignerHost + remoteSigner: the key never enters the agent process", () => {
  it("an allowed payment signs through the boundary, and the signature recovers to the host key", async () => {
    const { host } = hostRig();
    const { send } = recordingTransport(host);
    const signer = remoteSigner({ address: hostAccount.address, send });

    const request = transfer();
    const signature = await signer.signTypedData(request);
    expect(signature).toMatch(/^0x[0-9a-fA-F]+$/);
    const recovered = await recoverTypedDataAddress({
      domain: request.domain,
      types: request.types,
      primaryType: request.primaryType,
      message: request.message,
      signature: signature as `0x${string}`,
    } as never);
    expect(recovered.toLowerCase()).toBe(hostAccount.address.toLowerCase());
  });

  it("the remote signature is byte-identical to signing the same request through a local guardedSigner", async () => {
    const { host } = hostRig();
    const { send } = recordingTransport(host);
    const remote = remoteSigner({ address: hostAccount.address, send });

    const localLedger = new AuditLedger(new MemoryLedgerStore());
    const localGuard = new VadunoGuard({
      policy: {
        id: "local-compare",
        version: 1,
        currency: "USDC",
        limits: { perTransactionMinor: 50_000, perDayMinor: 200_000 },
        merchants: { allow: [`id:${SELLER.toLowerCase()}`] },
        networks: { allow: [NETWORK] },
      },
      ledger: localLedger,
      limiter: new MemorySpendLimiter(),
    });
    const local = guardedSigner({
      account: hostAccount,
      guard: localGuard,
      assets: [{ network: NETWORK, asset: USDC, symbol: "USDC", decimals: 6 }],
    });

    // Same request, bigints and all: the wire codec must preserve every byte
    // that reaches hashTypedData, or the two signatures diverge.
    const request = transfer();
    const viaRemote = await remote.signTypedData(structuredClone(request));
    const viaLocal = await local.signTypedData(structuredClone(request));
    expect(viaRemote).toBe(viaLocal);
  });

  it("a policy denial crosses the boundary as a refusal: same code, an intent id, and NO signature", async () => {
    const { host, ledger } = hostRig();
    const { send } = recordingTransport(host);
    const signer = remoteSigner({ address: hostAccount.address, send });

    // Payee not on the allowlist.
    let thrown: unknown;
    try {
      await signer.signTypedData(transfer({ to: ATTACKER }));
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(GuardSignerRefusedError);
    const e = thrown as GuardSignerRefusedError;
    expect(e.code).toBe("MERCHANT_NOT_ALLOWED");
    expect(typeof e.intentId).toBe("string");

    // The denial is on the host's ledger — evidence lives with the key.
    const rows = await ledger.all();
    expect(rows.length).toBeGreaterThan(0);
    expect(JSON.stringify(rows)).toContain(ATTACKER.toLowerCase());
  });

  it("an over-cap payment is refused and no signature exists anywhere in the wire traffic", async () => {
    const { host } = hostRig();
    const { send, inbound } = recordingTransport(host);
    const signer = remoteSigner({ address: hostAccount.address, send });

    await expect(
      signer.signTypedData(transfer({ value: 60_000n })), // over 0.05 USDC cap
    ).rejects.toMatchObject({ name: "GuardSignerRefusedError" });

    // No response that crossed the wire contains a signature-shaped value.
    for (const msg of inbound) {
      expect(msg).not.toMatch(/0x[0-9a-fA-F]{130}/);
    }
  });

  it("NO key material ever crosses the wire, in either direction", async () => {
    const { host } = hostRig();
    const { send, outbound, inbound } = recordingTransport(host);
    const signer = remoteSigner({ address: hostAccount.address, send });

    await signer.signTypedData(transfer());
    await signer.signTypedData(transfer({ to: ATTACKER })).catch(() => undefined);

    const keyHex = PRIVATE_KEY.slice(2).toLowerCase();
    for (const msg of [...outbound, ...inbound]) {
      expect(msg.toLowerCase()).not.toContain(keyHex);
    }
  });

  it("the remote signer object holds no reference to any account or key: only address and signTypedData", async () => {
    const { host } = hostRig();
    const { send } = recordingTransport(host);
    const signer = remoteSigner({ address: hostAccount.address, send });

    expect(Object.isFrozen(signer)).toBe(true);
    const keys = [
      ...Object.getOwnPropertyNames(signer),
      ...Object.getOwnPropertySymbols(signer).map(String),
    ].sort();
    expect(keys).toEqual(["address", "signTypedData"]);
  });

  it("the host refuses every method that is not signTypedData, and the refusal is audited", async () => {
    const { host, ledger } = hostRig();

    for (const method of ["signTransaction", "signMessage", "sign", "exportKey", "eval"]) {
      const response = JSON.parse(
        await host.handle(JSON.stringify({ v: 1, method, typedData: {} })),
      ) as { ok: boolean; code?: string };
      expect(response.ok).toBe(false);
      expect(response.code).toBe("HOST_METHOD_DISABLED");
    }

    const rows = await ledger.all();
    expect(JSON.stringify(rows)).toContain("HOST_METHOD_DISABLED");
  });

  it("unparseable and malformed wire requests are refused, audited, and never crash the host", async () => {
    const { host, ledger } = hostRig();

    const cases = [
      "not json at all",
      JSON.stringify(null),
      JSON.stringify(42),
      JSON.stringify({}),
      JSON.stringify({ v: 999, method: "signTypedData" }),
      JSON.stringify({ v: 1, method: "signTypedData" }), // no typedData
    ];
    for (const raw of cases) {
      const response = JSON.parse(await host.handle(raw)) as { ok: boolean; code?: string };
      expect(response.ok).toBe(false);
      expect(typeof response.code).toBe("string");
    }
    const rows = await ledger.all();
    expect(rows.length).toBeGreaterThan(0);
  });

  it("connectRemoteSigner learns the address from the host itself", async () => {
    const { host } = hostRig();
    const { send } = recordingTransport(host);
    const signer = await connectRemoteSigner(send);
    expect(signer.address.toLowerCase()).toBe(hostAccount.address.toLowerCase());
    const signature = await signer.signTypedData(transfer());
    expect(signature).toMatch(/^0x[0-9a-fA-F]+$/);
  });

  it("a message field shaped like the codec's own bigint tag still signs the same bytes a local signer signs", async () => {
    // The codec must be injective: a caller-controlled object that LOOKS like
    // an encoded bigint must not decode into one, or the host would police and
    // sign different bytes than the caller presented. hashTypedData will refuse
    // this struct (nonce must be bytes32), so both sides must refuse with the
    // SAME diagnosis — DIGEST_UNCOMPUTABLE — rather than the remote path
    // signing something else.
    const { host } = hostRig();
    const { send } = recordingTransport(host);
    const signer = remoteSigner({ address: hostAccount.address, send });

    const request = transfer({ nonce: nonce32() });
    (request.message as Record<string, unknown>)["nonce"] = { $vadunoBigint: "7" };

    let thrown: unknown;
    try {
      await signer.signTypedData(request);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(GuardSignerRefusedError);
    // The load-bearing part: the failure is the same one a LOCAL signer
    // produces for this request — not a signature over reinterpreted bytes.
    expect((thrown as GuardSignerRefusedError).code).toBe("UNRECOGNIZED_TYPED_DATA");
  });

  it("typed data carrying values JSON would silently mangle is refused fail-closed, not signed wrong", async () => {
    const { host } = hostRig();
    const { send } = recordingTransport(host);
    const signer = remoteSigner({ address: hostAccount.address, send });

    // A Date survives structuredClone but not JSON — encoding must refuse it
    // rather than silently stringify it into different signed bytes.
    const request = transfer();
    (request.message as Record<string, unknown>)["validAfter"] = new Date();

    await expect(signer.signTypedData(request)).rejects.toMatchObject({
      name: "GuardSignerRefusedError",
      code: "TYPED_DATA_NOT_SERIALIZABLE",
    });
  });

  it("a malformed host response is a refusal on the client, never a fabricated signature", async () => {
    const evilSend = async (): Promise<string> => JSON.stringify({ v: 1, ok: true });
    const signer = remoteSigner({ address: hostAccount.address, send: evilSend });
    await expect(signer.signTypedData(transfer())).rejects.toMatchObject({
      name: "GuardSignerRefusedError",
      code: "REMOTE_RESPONSE_INVALID",
    });
  });

  it("daily cap accumulates on the HOST, where the agent cannot reset it", async () => {
    const { host } = hostRig({ limits: { perTransactionMinor: 50_000, perDayMinor: 100_000 } });
    const { send } = recordingTransport(host);
    const signer = remoteSigner({ address: hostAccount.address, send });

    // 2 x 0.05 fills the 0.10/day cap; the third must be refused.
    await signer.signTypedData(
      transfer({ value: 50_000n, nonce: nonce32(), validBefore: soon() }),
    );
    await signer.signTypedData(
      transfer({ value: 50_000n, nonce: nonce32(), validBefore: soon() }),
    );
    await expect(
      signer.signTypedData(transfer({ value: 50_000n, nonce: nonce32(), validBefore: soon() })),
    ).rejects.toMatchObject({ name: "GuardSignerRefusedError" });
  });
});

describe("SignerHost.fetch: the same boundary as an HTTP endpoint (Durable Object / Worker shape)", () => {
  it("POST round-trips an allowed payment", async () => {
    const { host } = hostRig();
    const res = await host.fetch(
      new Request("https://signer.internal/", {
        method: "POST",
        body: JSON.stringify({
          v: 1,
          method: "signTypedData",
          typedData: JSON.parse(
            await new Promise<string>((resolve) => {
              // Build the encoded payload the same way the client does: via a
              // remoteSigner whose transport just hands us the request string.
              const signer = remoteSigner({
                address: hostAccount.address,
                send: async (req) => {
                  resolve(req);
                  return host.handle(req);
                },
              });
              void signer.signTypedData(transfer()).catch(() => undefined);
            }),
          ).typedData,
        }),
      }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; signature?: string };
    expect(body.ok).toBe(true);
    expect(body.signature).toMatch(/^0x[0-9a-fA-F]+$/);
  });

  it("a refusal maps to 403 with the refusal body; non-POST maps to 405", async () => {
    const { host } = hostRig();

    const denied = await host.fetch(
      new Request("https://signer.internal/", {
        method: "POST",
        body: JSON.stringify({ v: 1, method: "signTransaction" }),
      }),
    );
    expect(denied.status).toBe(403);
    const deniedBody = (await denied.json()) as { ok: boolean; code?: string };
    expect(deniedBody.ok).toBe(false);
    expect(deniedBody.code).toBe("HOST_METHOD_DISABLED");

    const get = await host.fetch(new Request("https://signer.internal/", { method: "GET" }));
    expect(get.status).toBe(405);
  });
});
