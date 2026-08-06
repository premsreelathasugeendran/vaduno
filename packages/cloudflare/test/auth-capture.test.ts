/**
 * Collector-aliased auth-capture, cross-checked against the REAL shipped
 * scheme: `@x402/evm`'s AuthCaptureEvmScheme signs an EIP-3009 authorization
 * whose `to` is a hardcoded token-collector contract, never the merchant, and
 * the true payee exists only inside the opaque nonce. These tests run the
 * genuine scheme (never a hand-built imitation) so the nonce re-derivation is
 * proven against the bytes the SDK actually produces.
 */
import { describe, expect, it } from "vitest";
import { AuthCaptureEvmScheme } from "@x402/evm";
import { GuardSignerRefusedError } from "../src/index.js";
import {
  ATTACKER,
  CHAIN_ID,
  EIP3009_TOKEN_COLLECTOR,
  SELLER,
  USDC,
  realAccount,
  rig,
  tag,
} from "./rig.js";

interface CapturedRun {
  requirements: Record<string, unknown>;
  typedData: unknown;
  salt: string;
}

/** Run the genuine shipped scheme against a recording signer. */
async function genuineRun(overrides: {
  payTo?: string;
  feeRecipient?: string;
  maxFeeBps?: number;
} = {}): Promise<CapturedRun> {
  const payTo = overrides.payTo ?? ATTACKER;
  let captured: unknown = null;
  const recorder = {
    address: realAccount.address,
    async signTypedData(t: never): Promise<`0x${string}`> {
      captured = t;
      return realAccount.signTypedData(t);
    },
  };
  const requirements = {
    scheme: "auth-capture",
    network: `eip155:${CHAIN_ID}`,
    amount: "10000",
    payTo,
    asset: USDC,
    maxTimeoutSeconds: 300,
    extra: {
      name: "USDC",
      version: "2",
      captureAuthorizer: payTo,
      feeRecipient: overrides.feeRecipient ?? payTo,
      captureDeadline: Math.floor(Date.now() / 1000) + 86_400,
      refundDeadline: Math.floor(Date.now() / 1000) + 172_800,
      minFeeBps: 0,
      maxFeeBps: overrides.maxFeeBps ?? 10_000,
    },
  };
  const out = await new AuthCaptureEvmScheme(recorder).createPaymentPayload(
    2,
    requirements as never,
  );
  const salt = (out as unknown as { payload: { salt: string } }).payload.salt;
  return { requirements, typedData: captured, salt };
}

const declarationFor = (run: CapturedRun, receiver: string) => {
  const extra = run.requirements["extra"] as Record<string, unknown>;
  return {
    operator: String(run.requirements["payTo"]),
    receiver,
    feeRecipient: String(extra["feeRecipient"]),
    minFeeBps: Number(extra["minFeeBps"]),
    maxFeeBps: Number(extra["maxFeeBps"]),
    authorizationExpiry: Number(extra["captureDeadline"]),
    refundExpiry: Number(extra["refundDeadline"]),
    salt: run.salt,
  };
};

describe("auth-capture collector aliasing", () => {
  it("refuses by default even when the collector itself is allowlisted", async () => {
    const run = await genuineRun();
    // The ONLY `to` this scheme ever signs is the collector — a deployment
    // that allowlists it must still not produce a signature for an
    // arbitrary receiver hidden in the nonce.
    const { guarded } = rig({
      merchants: { allow: [`id:${EIP3009_TOKEN_COLLECTOR.toLowerCase()}`] },
    });
    let signedFor: string | null = null;
    try {
      const out = await new AuthCaptureEvmScheme(guarded).createPaymentPayload(
        2,
        run.requirements as never,
      );
      signedFor = JSON.stringify(out);
    } catch (err) {
      expect(tag(err)).toBe("AUTH_CAPTURE_UNPOLICEABLE");
    }
    expect(signedFor).toBeNull();
  });

  it("with the PaymentInfo declared, policy runs on the REAL payee, not the collector", async () => {
    const run = await genuineRun();
    const { guarded, calls } = rig({
      merchants: { allow: [`id:${EIP3009_TOKEN_COLLECTOR.toLowerCase()}`] },
      resolveAuthCapture: () => declarationFor(run, ATTACKER),
    });
    await expect(
      guarded.signTypedData(run.typedData as never),
    ).rejects.toBeInstanceOf(GuardSignerRefusedError);
    // The guard evaluated the RE-DERIVED receiver — the attacker — and denied.
    expect(calls.intents[0]?.merchant.id).toBe(ATTACKER.toLowerCase());
    expect(calls.statuses[0]).toBe("denied");
  });

  it("rejects a lying declaration: a receiver not in the signed nonce cannot pass", async () => {
    const run = await genuineRun();
    const { guarded } = rig({
      merchants: {
        allow: [`id:${SELLER.toLowerCase()}`, `id:${EIP3009_TOKEN_COLLECTOR.toLowerCase()}`],
      },
      // Claims the allowlisted seller; the bytes say the attacker.
      resolveAuthCapture: () => declarationFor(run, SELLER),
    });
    let signed = false;
    try {
      await guarded.signTypedData(run.typedData as never);
      signed = true;
    } catch (err) {
      expect(tag(err)).toBe("AUTH_CAPTURE_MISMATCH");
    }
    expect(signed).toBe(false);
  });

  it("still signs an honest, declared auth-capture payment to an allowlisted payee", async () => {
    const run = await genuineRun({ payTo: SELLER, feeRecipient: SELLER, maxFeeBps: 100 });
    const { guarded, calls } = rig({
      resolveAuthCapture: () => declarationFor(run, SELLER),
    });
    const sig = await guarded.signTypedData(run.typedData as never);
    expect(sig).toMatch(/^0x[0-9a-f]{130}$/i);
    expect(calls.intents[0]?.merchant.id).toBe(SELLER.toLowerCase());
    const meta = calls.intents[0]?.metadata as { authCapture?: { scheme?: string } };
    expect(meta.authCapture?.scheme).toBe("auth-capture");
  });
});
