/**
 * MandateManager over a pluggable Ed25519Signer — the property set that makes
 * a KMS/HSM-resident key safe to adopt:
 *
 *  - the wire format is FROZEN: a signer config and a legacy privateKeyPem
 *    config produce byte-identical signatures for the same key;
 *  - misconfiguration fails at construction, before any authority exists;
 *  - every signer failure denies NEW authority only — nothing half-issued,
 *    nothing recorded, and previously issued mandates keep verifying;
 *  - issuance can never degrade to unsigned or locally-signed output.
 */
import { createPrivateKey, sign as edSign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { AuditLedger } from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import { canonicalJson } from "../src/ledger/hash.js";
import {
  MANDATE_DOMAIN,
  MandateManager,
  generateMandateKeyPair,
  mandateKeyId,
  type Mandate,
} from "../src/mandate/mandate.js";
import {
  LocalKeySigner,
  SignerError,
  SignerTimeoutError,
  SignerVerificationError,
  type Ed25519Signer,
} from "../src/mandate/signer.js";
import { makeIntent } from "./helpers.js";

const constraints = {
  maxAmountMinor: 10_000,
  currency: "USD",
  validFrom: new Date(Date.now() - 1000).toISOString(),
  expiresAt: new Date(Date.now() + 60_000).toISOString(),
  maxUses: 3,
};

const issueParams = { issuer: "human@example.com", agentId: "agent-1", constraints };

/** Recompute the one signature this mandate's unsigned fields admit. */
function expectedSignature(m: Mandate, privateKeyPem: string): string {
  const { signature: _sig, ...unsigned } = m;
  return edSign(
    null,
    Buffer.from(MANDATE_DOMAIN + canonicalJson(unsigned), "utf8"),
    createPrivateKey(privateKeyPem),
  ).toString("base64");
}

describe("wire freeze: signer config is byte-identical to privateKeyPem config", () => {
  it("both configs sign the exact same bytes for the same key", async () => {
    const keys = generateMandateKeyPair();
    const viaPem = new MandateManager({
      publicKeyPem: keys.publicKeyPem,
      privateKeyPem: keys.privateKeyPem,
    });
    const viaSigner = new MandateManager({ signer: new LocalKeySigner(keys.privateKeyPem) });

    for (const manager of [viaPem, viaSigner]) {
      const m = await manager.issue(issueParams);
      // Ed25519 is deterministic: identical unsigned bytes under one key have
      // exactly one signature. Byte-compare against an independent signing.
      expect(m.signature).toBe(expectedSignature(m, keys.privateKeyPem));
      expect(m.kid).toBe(mandateKeyId(keys.publicKeyPem));
    }
  });

  it("a mandate issued via signer verifies in a verifier built from the PEM public key", async () => {
    const keys = generateMandateKeyPair();
    const issuer = new MandateManager({ signer: new LocalKeySigner(keys.privateKeyPem) });
    const m = await issuer.issue(issueParams);
    const verifier = new MandateManager({ publicKeyPem: keys.publicKeyPem });
    verifier.register(m);
    expect(verifier.check(m.id, makeIntent()).ok).toBe(true);
  });
});

describe("construction refusals — misconfig fails before any authority exists", () => {
  const keys = generateMandateKeyPair();

  it("both privateKeyPem AND signer", () => {
    expect(
      () =>
        new MandateManager({
          publicKeyPem: keys.publicKeyPem,
          privateKeyPem: keys.privateKeyPem,
          signer: new LocalKeySigner(keys.privateKeyPem),
        }),
    ).toThrow(SignerError);
  });

  it("a signer declaring a non-Ed25519 algorithm", () => {
    const bad = {
      algorithm: "secp256k1",
      publicKeyPem: keys.publicKeyPem,
      sign: async () => new Uint8Array(64),
    } as unknown as Ed25519Signer;
    expect(() => new MandateManager({ signer: bad })).toThrow(SignerError);
  });

  it("an explicit publicKeyPem whose kid differs from the signer's", () => {
    // Issuing under this config would mint mandates whose kid names a key
    // that never signed them — permanently unverifiable. Refused up front.
    const other = generateMandateKeyPair();
    expect(
      () =>
        new MandateManager({
          publicKeyPem: other.publicKeyPem,
          signer: new LocalKeySigner(keys.privateKeyPem),
        }),
    ).toThrow(SignerError);
  });

  it("a signer whose declared public key does not parse", () => {
    const bad = {
      algorithm: "Ed25519",
      publicKeyPem: "not a pem",
      sign: async () => new Uint8Array(64),
    } as Ed25519Signer;
    expect(() => new MandateManager({ signer: bad })).toThrow(SignerError);
  });

  it("a LEGACY pem pair whose publicKeyPem does not match the privateKeyPem", () => {
    // Same failure shape as the signer/publicKeyPem mismatch: every issued
    // mandate would carry the kid of a key that never signed it. The legacy
    // config gets the same construction-time refusal.
    const other = generateMandateKeyPair();
    expect(
      () =>
        new MandateManager({
          publicKeyPem: other.publicKeyPem,
          privateKeyPem: keys.privateKeyPem,
        }),
    ).toThrow(SignerError);
  });

  it("neither a public key nor a signer", () => {
    expect(() => new MandateManager({})).toThrow(SignerError);
  });
});

describe("signer failures deny — no phantom mandates, ever", () => {
  const keys = generateMandateKeyPair();

  function rig(signer: Ed25519Signer, signTimeoutMs?: number) {
    const ledger = new AuditLedger(new MemoryLedgerStore());
    const manager = new MandateManager(
      { signer },
      ledger,
      () => new Date(),
      signTimeoutMs !== undefined ? { signTimeoutMs } : {},
    );
    return { ledger, manager };
  }

  async function expectNothingRecorded(ledger: AuditLedger, manager: MandateManager) {
    const entries = await ledger.all();
    expect(entries.filter((e) => e.type === "mandate_issued")).toHaveLength(0);
    // No states entry either: an unknown id is UNKNOWN_MANDATE, not a mandate.
    expect(manager.check("any-id", makeIntent()).code).toBe("UNKNOWN_MANDATE");
  }

  it("rejecting signer => SignerError, no ledger entry, no state", async () => {
    const { ledger, manager } = rig({
      algorithm: "Ed25519",
      publicKeyPem: keys.publicKeyPem,
      sign: async () => {
        throw new Error("kms: IAM permission revoked");
      },
    });
    await expect(manager.issue(issueParams)).rejects.toBeInstanceOf(SignerError);
    await expectNothingRecorded(ledger, manager);
  });

  it("wrong-key signer => SignerVerificationError, nothing recorded", async () => {
    // Kills "trust the signer's bytes": valid-looking 64-byte output by the
    // WRONG key must be caught by post-sign verification.
    const impostor = new LocalKeySigner(generateMandateKeyPair().privateKeyPem);
    const { ledger, manager } = rig({
      algorithm: "Ed25519",
      publicKeyPem: keys.publicKeyPem,
      sign: (m) => impostor.sign(m),
    });
    await expect(manager.issue(issueParams)).rejects.toBeInstanceOf(SignerVerificationError);
    await expectNothingRecorded(ledger, manager);
  });

  it("corrupt proxy / MITM outputs (empty, truncated, random 64) are refused before anything is emitted", async () => {
    const outputs = [
      new Uint8Array(0),
      new Uint8Array(32),
      Uint8Array.from({ length: 64 }, (_, i) => (i * 101 + 7) % 256),
    ];
    for (const out of outputs) {
      const { ledger, manager } = rig({
        algorithm: "Ed25519",
        publicKeyPem: keys.publicKeyPem,
        sign: async () => out,
      });
      await expect(manager.issue(issueParams)).rejects.toBeInstanceOf(SignerError);
      await expectNothingRecorded(ledger, manager);
    }
  });

  it("wedged KMS => SignerTimeoutError under 500ms; a LATE resolution changes nothing", async () => {
    let late!: (v: Uint8Array) => void;
    const real = new LocalKeySigner(keys.privateKeyPem);
    const { ledger, manager } = rig(
      {
        algorithm: "Ed25519",
        publicKeyPem: keys.publicKeyPem,
        sign: () => new Promise<Uint8Array>((res) => (late = res)),
      },
      50,
    );
    const t0 = Date.now();
    await expect(manager.issue(issueParams)).rejects.toBeInstanceOf(SignerTimeoutError);
    expect(Date.now() - t0).toBeLessThan(500);
    // The KMS wakes up and delivers a VALID signature — too late. Nothing may
    // appear in states or the ledger, and issuance must not have degraded to
    // unsigned or locally-signed output in the meantime.
    late(await real.sign(Buffer.from("whatever")));
    await new Promise((r) => setTimeout(r, 30));
    await expectNothingRecorded(ledger, manager);
  });

  it("a signer that ROTATES its declared key after construction cannot mint an unverifiable mandate", async () => {
    // A KMS wrapper resolving "latest key version" re-declares its public key
    // when the KMS rotates. The manager froze kid/verifyKeys at construction,
    // so a mandate signed by the NEW key would be recorded under a kid the
    // manager itself can no longer verify — "nothing unverifiable can leave
    // this process" requires verifying against the construction-frozen key,
    // which turns rotation into a clean deny.
    const rotatedKeys = generateMandateKeyPair();
    const original = new LocalKeySigner(keys.privateKeyPem);
    const rotated = new LocalKeySigner(rotatedKeys.privateKeyPem);
    let pem = keys.publicKeyPem;
    let backend: Ed25519Signer = original;
    const { ledger, manager } = rig({
      algorithm: "Ed25519",
      get publicKeyPem() {
        return pem;
      },
      sign: (m) => backend.sign(m),
    });
    const before = await manager.issue(issueParams);

    // The KMS rotates: declaration AND signing move to the new key. Without
    // the construction-time freeze, checkedSign would now happily verify the
    // new key's signature against the new key's declaration — and record a
    // mandate whose kid names the OLD key.
    pem = rotatedKeys.publicKeyPem;
    backend = rotated;
    await expect(manager.issue(issueParams)).rejects.toBeInstanceOf(SignerVerificationError);

    // Exactly one mandate exists, and it still verifies and consumes.
    const entries = await ledger.all();
    expect(entries.filter((e) => e.type === "mandate_issued")).toHaveLength(1);
    expect(manager.check(before.id, makeIntent()).ok).toBe(true);
  });

  it("input-mutating signer: the issued mandate still verifies", async () => {
    const real = new LocalKeySigner(keys.privateKeyPem);
    const { manager } = rig({
      algorithm: "Ed25519",
      publicKeyPem: keys.publicKeyPem,
      sign: async (m) => {
        const sig = await real.sign(m);
        (m as Uint8Array).fill(0); // scribble AFTER signing the true bytes
        return sig;
      },
    });
    const mandate = await manager.issue(issueParams);
    expect(manager.check(mandate.id, makeIntent()).ok).toBe(true);
  });
});

describe("liveness and isolation", () => {
  it("10 concurrent issues through a slow signer yield 10 distinct verifying mandates", async () => {
    const keys = generateMandateKeyPair();
    const real = new LocalKeySigner(keys.privateKeyPem);
    const slow: Ed25519Signer = {
      algorithm: "Ed25519",
      publicKeyPem: keys.publicKeyPem,
      sign: async (m) => {
        await new Promise((r) => setTimeout(r, 20));
        return real.sign(m);
      },
    };
    const manager = new MandateManager({ signer: slow });
    const mandates = await Promise.all(
      Array.from({ length: 10 }, () => manager.issue(issueParams)),
    );
    expect(new Set(mandates.map((m) => m.id)).size).toBe(10);
    for (const m of mandates) expect(manager.check(m.id, makeIntent()).ok).toBe(true);

    // consumeOnce is unchanged by the async signing path.
    const intent = makeIntent();
    const first = await manager.consumeOnce(mandates[0]!.id, intent);
    expect(first.kind).toBe("consumed");
    const replay = await manager.consumeOnce(mandates[0]!.id, intent);
    expect(replay.kind).toBe("replayed");
  });

  it("verify-only manager: check/consumeOnce work; issue throws without touching any signer", async () => {
    const keys = generateMandateKeyPair();
    const issuer = new MandateManager({ signer: new LocalKeySigner(keys.privateKeyPem) });
    const mandate = await issuer.issue(issueParams);

    const verifier = new MandateManager({ publicKeyPem: keys.publicKeyPem });
    verifier.register(mandate);
    expect(verifier.check(mandate.id, makeIntent()).ok).toBe(true);
    const outcome = await verifier.consumeOnce(mandate.id, makeIntent());
    expect(outcome.kind).toBe("consumed");
    await expect(verifier.issue(issueParams)).rejects.toThrow(/cannot issue/);
  });

  it("IAM revocation bounds the breach to the inside window", async () => {
    // The signer starts rejecting (key access revoked at the KMS): zero
    // mandates issue after that instant, while mandates issued BEFORE still
    // verify and consume — revocation of issuing power is not retroactive
    // destruction of evidence.
    const keys = generateMandateKeyPair();
    const real = new LocalKeySigner(keys.privateKeyPem);
    let revoked = false;
    const signer: Ed25519Signer = {
      algorithm: "Ed25519",
      publicKeyPem: keys.publicKeyPem,
      sign: (m) => {
        if (revoked) return Promise.reject(new Error("kms: PERMISSION_DENIED"));
        return real.sign(m);
      },
    };
    const manager = new MandateManager({ signer });
    const before = await manager.issue(issueParams);

    revoked = true;
    await expect(manager.issue(issueParams)).rejects.toBeInstanceOf(SignerError);

    expect(manager.check(before.id, makeIntent()).ok).toBe(true);
    const outcome = await manager.consumeOnce(before.id, makeIntent());
    expect(outcome.kind).toBe("consumed");
  });

  it("offline forgery from a FULL stolen config fails at every verifier", async () => {
    // The attacker holds everything a KMS-backed deployment stores: the
    // public PEM, the kid, the KMS resource name. Everything except the
    // HSM-resident key — which was never present in any process.
    const victim = generateMandateKeyPair();
    const attacker = generateMandateKeyPair();
    const verifier = new MandateManager({ publicKeyPem: victim.publicKeyPem });

    const stolenKid = mandateKeyId(victim.publicKeyPem);
    const unsigned = {
      v: 1,
      alg: "Ed25519",
      kid: stolenKid,
      id: "forged-1",
      issuer: "human@example.com",
      agentId: "agent-1",
      constraints,
      createdAt: new Date().toISOString(),
    };
    // Best available forgery: sign with the attacker's OWN key, label with
    // the victim's kid.
    const forgedSig = edSign(
      null,
      Buffer.from(MANDATE_DOMAIN + canonicalJson(unsigned), "utf8"),
      createPrivateKey(attacker.privateKeyPem),
    ).toString("base64");
    const forged = { ...unsigned, signature: forgedSig } as Mandate;
    verifier.register(forged);
    expect(verifier.check(forged.id, makeIntent()).code).toBe("SIGNATURE_INVALID");

    // Honest labelling with the attacker's kid does no better: the verifier
    // does not hold that key.
    const relabelled = {
      ...unsigned,
      id: "forged-2",
      kid: mandateKeyId(attacker.publicKeyPem),
    };
    const relabelledSig = edSign(
      null,
      Buffer.from(MANDATE_DOMAIN + canonicalJson(relabelled), "utf8"),
      createPrivateKey(attacker.privateKeyPem),
    ).toString("base64");
    const forged2 = { ...relabelled, signature: relabelledSig } as Mandate;
    verifier.register(forged2);
    expect(verifier.check(forged2.id, makeIntent()).code).toBe("KEY_UNKNOWN");
  });
});
