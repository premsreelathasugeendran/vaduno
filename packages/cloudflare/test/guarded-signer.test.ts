/**
 * The ported hard-won properties of the guarded signer, each one observed
 * FAILING against a deliberately broken build before it was trusted (see the
 * planted-defect log in the package's development history): a check that
 * passes both ways proves nothing.
 */
import { describe, expect, it } from "vitest";
import { recoverTypedDataAddress } from "viem";
import { GuardSignerRefusedError, guardedSigner } from "../src/index.js";
import {
  ATTACKER,
  CHAIN_ID,
  EIGHT_DEC,
  NETWORK,
  SELLER,
  TWO_DEC,
  USDC,
  eip3009Types,
  executedRows,
  honestTransfer,
  nonce32,
  permitWitnessTypes,
  realAccount,
  rig,
  rowsMentioning,
  soon,
  tag,
} from "./rig.js";

type AnyTyped = Parameters<ReturnType<typeof guardedSigner>["signTypedData"]>[0];

const asTyped = (v: unknown): AnyTyped => v as AnyTyped;

async function refusalOf(p: Promise<unknown>): Promise<GuardSignerRefusedError> {
  try {
    await p;
  } catch (err) {
    expect(err).toBeInstanceOf(GuardSignerRefusedError);
    return err as GuardSignerRefusedError;
  }
  throw new Error("expected a GuardSignerRefusedError, but the call succeeded");
}

describe("honest path", () => {
  it("signs an in-policy EIP-3009 payment and counts it once; a byte-identical retry replays without double-count", async () => {
    const { guarded, ledger } = rig();
    const td = honestTransfer();
    const sig = await guarded.signTypedData(asTyped(td));
    expect(sig).toMatch(/^0x[0-9a-f]+$/i);
    const recovered = await recoverTypedDataAddress({
      ...(td as never as Parameters<typeof recoverTypedDataAddress>[0]),
      signature: sig,
    });
    expect(recovered.toLowerCase()).toBe(realAccount.address.toLowerCase());

    const again = await guarded.signTypedData(asTyped(td));
    expect(again).toBe(sig);
    // One executed settlement, not two: the id is the EIP-712 digest, so the
    // retry is byte-identical and replays instead of re-counting.
    expect(await executedRows(ledger)).toBe(1);
  });

  it("carries the settlement network on the intent so policy can gate the chain", async () => {
    const { guarded, calls } = rig({
      networks: { allow: [NETWORK] },
      assets: [
        { network: NETWORK, asset: USDC, symbol: "USDC", decimals: 6 },
        { network: "eip155:11155111", asset: USDC, symbol: "USDC", decimals: 6 },
      ],
    });
    await guarded.signTypedData(asTyped(honestTransfer()));
    expect(calls.intents[0]?.network).toBe(NETWORK);

    // Same currency, same registry, wrong chain: the POLICY refuses it.
    const err = await refusalOf(
      guarded.signTypedData(asTyped(honestTransfer({ chainId: 11155111 }))),
    );
    expect(err.code).toContain("NETWORK");
  });
});

describe("snapshot before read, sign the snapshot (TOCTOU)", () => {
  it("getters that flip after the policy read cannot make the key sign what policy never saw", async () => {
    const { guarded } = rig();
    let hostile = false;
    let reads = 0;
    const validBefore = soon();
    const nonce = nonce32();
    const td = {
      domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
      types: eip3009Types,
      primaryType: "TransferWithAuthorization",
      message: {
        from: realAccount.address,
        get to() {
          return hostile ? ATTACKER : SELLER;
        },
        get value() {
          return hostile ? 100_000_000n : 10_000n;
        },
        validAfter: 0n,
        get validBefore() {
          reads += 1;
          if (reads === 1) hostile = true;
          return validBefore;
        },
        nonce,
      },
    };
    const hostileView = {
      domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
      types: eip3009Types,
      primaryType: "TransferWithAuthorization" as const,
      message: {
        from: realAccount.address,
        to: ATTACKER,
        value: 100_000_000n,
        validAfter: 0n,
        validBefore,
        nonce,
      },
    };
    let bindsHostile = false;
    try {
      const sig = await guarded.signTypedData(asTyped(td));
      const rec = await recoverTypedDataAddress({
        ...(hostileView as never as Parameters<typeof recoverTypedDataAddress>[0]),
        signature: sig,
      }).catch(() => "n/a");
      bindsHostile = String(rec).toLowerCase() === realAccount.address.toLowerCase();
    } catch {
      // A refusal is also a pass: no signature exists at all.
    }
    expect(bindsHostile).toBe(false);
  });

  it("mutating the request object after calling (without awaiting) cannot change the signed bytes", async () => {
    const { guarded, calls } = rig();
    const validBefore = soon();
    const nonce = nonce32();
    const td = honestTransfer({ validBefore, nonce });
    const pending = guarded.signTypedData(asTyped(td));
    // The caller still owns this object and mutates it across the await gap.
    (td.message as Record<string, unknown>).to = ATTACKER;
    (td.message as Record<string, unknown>).value = 100_000_000n;

    const hostileView = {
      domain: td.domain,
      types: eip3009Types,
      primaryType: "TransferWithAuthorization" as const,
      message: {
        from: realAccount.address,
        to: ATTACKER,
        value: 100_000_000n,
        validAfter: 0n,
        validBefore,
        nonce,
      },
    };
    let bindsHostile = false;
    try {
      const sig = await pending;
      const rec = await recoverTypedDataAddress({
        ...(hostileView as never as Parameters<typeof recoverTypedDataAddress>[0]),
        signature: sig,
      }).catch(() => "n/a");
      bindsHostile = String(rec).toLowerCase() === realAccount.address.toLowerCase();
    } catch {
      // refusal also passes
    }
    expect(bindsHostile).toBe(false);
    // And what the guard policed is the benign payload, not the mutation.
    expect(calls.intents[0]?.merchant.id).toBe(SELLER.toLowerCase());
    expect(calls.intents[0]?.amount.amountMinor).toBe(10_000);
  });
});

describe("commitment: police only facts the signature carries", () => {
  it("refuses when types omit the payee (`to`), instead of policing message.to", async () => {
    const types = {
      TransferWithAuthorization: eip3009Types.TransferWithAuthorization.filter(
        (f) => f.name !== "to",
      ),
    };
    const { guarded, ledger } = rig();
    const err = await refusalOf(guarded.signTypedData(asTyped(honestTransfer({ types }))));
    expect(err.code).toBe("TYPED_DATA_NOT_COMMITTED");
    expect(err.intentId).toBeDefined();
    expect(await rowsMentioning(ledger, err.intentId!)).toBeGreaterThan(0);
  });

  it("refuses a decimal-string chainId: present, policed, and NOT in the signed bytes (inferred domain)", async () => {
    const { guarded } = rig();
    const err = await refusalOf(
      guarded.signTypedData(asTyped(honestTransfer({ chainId: String(CHAIN_ID) }))),
    );
    expect(err.code).toBe("TYPED_DATA_NOT_COMMITTED");
    expect(err.message).toContain("INFERRED");
  });

  it("refuses an explicit types.EIP712Domain that narrows away verifyingContract", async () => {
    const td = honestTransfer();
    (td.types as Record<string, unknown>) = {
      ...eip3009Types,
      EIP712Domain: [
        { name: "name", type: "string" },
        { name: "version", type: "string" },
        { name: "chainId", type: "uint256" },
      ],
    };
    const { guarded } = rig();
    const err = await refusalOf(guarded.signTypedData(asTyped(td)));
    expect(err.code).toBe("TYPED_DATA_NOT_COMMITTED");
  });

  it("records the committed-field set alongside the digest on the signed path", async () => {
    const { guarded, calls } = rig();
    await guarded.signTypedData(asTyped(honestTransfer()));
    const meta = calls.intents[0]?.metadata as {
      digest?: string;
      committed?: { domain?: string[]; struct?: Record<string, string[]> };
    };
    expect(meta.digest).toMatch(/^0x[0-9a-f]{64}$/);
    expect(meta.committed?.domain).toContain("chainId");
    expect(meta.committed?.domain).toContain("verifyingContract");
    expect(meta.committed?.struct?.["TransferWithAuthorization"]).toContain("to");
  });
});

describe("default-deny", () => {
  it("refuses an unrecognized primaryType (EIP-2612 Permit is an approval, not a payment) and audits the refusal", async () => {
    const { guarded, ledger } = rig();
    const err = await refusalOf(
      guarded.signTypedData(
        asTyped({
          domain: { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
          types: {
            Permit: [
              { name: "owner", type: "address" },
              { name: "spender", type: "address" },
              { name: "value", type: "uint256" },
              { name: "nonce", type: "uint256" },
              { name: "deadline", type: "uint256" },
            ],
          },
          primaryType: "Permit",
          message: {
            owner: realAccount.address,
            spender: ATTACKER,
            value: 2n ** 256n - 1n,
            nonce: 0n,
            deadline: soon(),
          },
        }),
      ),
    );
    expect(err.code).toBe("UNRECOGNIZED_TYPED_DATA");
    expect(await rowsMentioning(ledger, err.intentId!)).toBeGreaterThan(0);
  });

  it("refuses a request whose (chainId, asset) pair is not in the trusted registry", async () => {
    const { guarded, calls } = rig();
    const err = await refusalOf(
      guarded.signTypedData(asTyped(honestTransfer({ verifyingContract: TWO_DEC }))),
    );
    // Denied by the guard (currency cannot match), not signed on faith.
    expect(err.code).toContain("CURRENCY");
    expect(calls.intents[0]?.amount.currency).toBe(`UNKNOWN:${TWO_DEC.toLowerCase()}`);
  });
});

describe("raw-key capabilities", () => {
  it("stubs every non-signTypedData capability with an AUDITED throwing refusal", async () => {
    const { guarded, ledger } = rig();
    const g = guarded as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>;
    for (const capability of ["signTransaction", "signMessage", "sign"]) {
      const fn = g[capability];
      expect(typeof fn, `${capability} should exist as a stub`).toBe("function");
      const err = await refusalOf(fn!({}));
      expect(err.code).toBe("UNGATED_CAPABILITY_DISABLED");
      expect(await rowsMentioning(ledger, err.intentId!)).toBeGreaterThan(0);
    }
  });

  it("is frozen and holds no property that references the real account", () => {
    const { guarded } = rig();
    expect(Object.isFrozen(guarded)).toBe(true);
    const values = Object.values(guarded as unknown as Record<string, unknown>);
    expect(values).not.toContain(realAccount);
    expect(values).not.toContain(realAccount.signTypedData);
    expect(values).not.toContain(realAccount.signTransaction);
  });
});

describe("amounts and decimals", () => {
  it("scales a 2-decimal dollar token instead of counting raw atomic units (10000 atomic = $100.00, not $0.01)", async () => {
    const { guarded, calls } = rig({
      assets: [
        { network: NETWORK, asset: USDC, symbol: "USDC", decimals: 6 },
        { network: NETWORK, asset: TWO_DEC, symbol: "USDC", decimals: 2 },
      ],
      currencyDecimals: 6,
      merchants: { allow: [`id:${SELLER.toLowerCase()}`] },
    });
    // $100.00 of the 2-decimal token, against a $0.05 per-transaction cap.
    const err = await refusalOf(
      guarded.signTypedData(asTyped(honestTransfer({ verifyingContract: TWO_DEC }))),
    );
    expect(err.code).toContain("LIMIT");
    expect(calls.intents[0]?.amount.amountMinor).toBe(100_000_000);
  });

  it("rounds UP when downscaling, so dust can never cost nothing", async () => {
    const { guarded, calls } = rig({
      assets: [{ network: NETWORK, asset: EIGHT_DEC, symbol: "USDC", decimals: 8 }],
      currencyDecimals: 6,
    });
    // 101 atomic units of an 8-decimal token = 1.01 minor units -> 2, never 1.
    await guarded.signTypedData(
      asTyped(honestTransfer({ verifyingContract: EIGHT_DEC, value: 101n })),
    );
    expect(calls.intents[0]?.amount.amountMinor).toBe(2);
    const scale = (calls.intents[0]?.metadata as { scale?: { roundedUp?: boolean } }).scale;
    expect(scale?.roundedUp).toBe(true);
  });

  it("refuses (never guesses) when a currency's registered assets disagree about decimals", async () => {
    const { guarded } = rig({
      assets: [
        { network: NETWORK, asset: USDC, symbol: "USDC", decimals: 6 },
        { network: NETWORK, asset: TWO_DEC, symbol: "USDC", decimals: 2 },
      ],
      // no currencyDecimals declared
    });
    const err = await refusalOf(guarded.signTypedData(asTyped(honestTransfer())));
    expect(err.code).toBe("AMBIGUOUS_CURRENCY_DECIMALS");
  });

  it("denies an over-cap payment", async () => {
    const { guarded } = rig();
    const err = await refusalOf(
      guarded.signTypedData(asTyped(honestTransfer({ value: 60_000n }))),
    );
    expect(err.code).toContain("LIMIT");
  });

  it("holds the daily cap under 12 parallel distinct signs", async () => {
    const { guarded } = rig({
      limits: { perTransactionMinor: 50_000, perDayMinor: 20_000 },
    });
    const outcomes = await Promise.allSettled(
      Array.from({ length: 12 }, () =>
        guarded.signTypedData(asTyped(honestTransfer({ value: 5_000n }))),
      ),
    );
    const signed = outcomes.filter((o) => o.status === "fulfilled").length;
    expect(signed).toBe(4); // 4 x 5000 = the whole 20000 daily budget, exactly
  });
});

describe("unsettleable authorizations cannot burn budget", () => {
  it("refuses a payer that is not this wallet", async () => {
    const { guarded, ledger } = rig();
    const err = await refusalOf(
      guarded.signTypedData(asTyped(honestTransfer({ from: ATTACKER }))),
    );
    expect(err.code).toBe("PAYER_NOT_THIS_SIGNER");
    expect(await executedRows(ledger)).toBe(0);
  });

  it("refuses an already-expired authorization", async () => {
    const { guarded } = rig();
    const err = await refusalOf(
      guarded.signTypedData(
        asTyped(honestTransfer({ validBefore: BigInt(Math.floor(Date.now() / 1000) - 10) })),
      ),
    );
    expect(err.code).toBe("AUTHORIZATION_EXPIRED");
  });

  it("enforces maxValiditySeconds when configured", async () => {
    const { guarded } = rig({ maxValiditySeconds: 60 });
    const err = await refusalOf(
      guarded.signTypedData(
        asTyped(honestTransfer({ validBefore: BigInt(Math.floor(Date.now() / 1000) + 3600) })),
      ),
    );
    expect(err.code).toBe("VALIDITY_WINDOW_TOO_LONG");
  });
});

describe("permit2", () => {
  const permitRequest = (spender: string) =>
    asTyped({
      domain: { name: "Permit2", chainId: CHAIN_ID, verifyingContract: TWO_DEC },
      types: permitWitnessTypes,
      primaryType: "PermitWitnessTransferFrom",
      message: {
        permitted: { token: USDC, amount: 10_000n },
        spender,
        nonce: 7n,
        deadline: soon(),
        witness: { to: SELLER, facilitator: SELLER, validAfter: 0n },
      },
    });

  it("polices the spender (the authority), not just the witness recipient (the hint)", async () => {
    const { guarded } = rig();
    const err = await refusalOf(guarded.signTypedData(permitRequest(ATTACKER)));
    expect(err.code).toBe("PERMIT2_SPENDER_NOT_ALLOWED");
  });

  it("signs when the spender is declared and the witness payee is allowlisted", async () => {
    const { guarded, calls } = rig({ permit2Spenders: [SELLER] });
    const sig = await guarded.signTypedData(permitRequest(SELLER));
    expect(sig).toMatch(/^0x[0-9a-f]+$/i);
    expect(calls.intents[0]?.merchant.id).toBe(SELLER.toLowerCase());
  });
});

describe("every refusal is audited and the ledger stays verifiable", () => {
  it("writes rows for local refusals of several kinds, and the chain still verifies", async () => {
    const { guarded, ledger } = rig();
    const refusals: string[] = [];
    for (const attempt of [
      () => guarded.signTypedData(asTyped({ primaryType: "Nonsense", domain: {}, types: {}, message: {} })),
      () => guarded.signTypedData(asTyped(honestTransfer({ from: ATTACKER }))),
      () =>
        (guarded as unknown as { signTransaction(a: unknown): Promise<unknown> }).signTransaction(
          {},
        ),
    ]) {
      const err = await refusalOf(attempt());
      refusals.push(err.intentId!);
    }
    for (const id of refusals) {
      expect(await rowsMentioning(ledger, id), `refusal ${id} left no trace`).toBeGreaterThan(0);
    }
    const v = await ledger.verify();
    expect(v.ok).toBe(true);
  });
});

describe("construction-time diagnostics", () => {
  it("refuses a non-eip155 asset registry entry loudly", () => {
    expect(() =>
      rig({ assets: [{ network: "solana:mainnet", asset: USDC, symbol: "USDC", decimals: 6 }] }),
    ).toThrow(/eip155/);
  });

  it("refuses a host-form merchant allowlist when merchantUrl is a wrap-time constant", () => {
    expect(() =>
      rig({ merchants: { allow: ["host:x402.org"] }, merchantUrl: "https://x402.org/paid" }),
    ).toThrow(/host-form/);
  });

  it("host patterns cannot match at signer level even without the diagnostic: a host-allow policy denies", async () => {
    // No merchantUrl -> the constructor diagnostic does not fire; the
    // structural control is that merchant.url is never populated, so the
    // host pattern has nothing to match and the payment is DENIED.
    const { guarded } = rig({ merchants: { allow: ["host:x402.org"] } });
    const err = await refusalOf(guarded.signTypedData(asTyped(honestTransfer())));
    expect(err.code).toContain("MERCHANT");
  });

  it("validates currencyDecimals and maxValiditySeconds", () => {
    expect(() => rig({ currencyDecimals: 37 })).toThrow(/currencyDecimals/);
    expect(() => rig({ maxValiditySeconds: 0 })).toThrow(/maxValiditySeconds/);
  });
});
