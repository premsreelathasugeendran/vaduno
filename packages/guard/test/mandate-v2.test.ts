/**
 * Hybrid (v2) mandates — the second algorithm slot.
 *
 * PQ NOTE, honestly: this machine has no native ML-DSA (Node 20 / OpenSSL
 * 3.0), so every test here runs the surrounding LOGIC through a deterministic
 * fake MlDsa44Ops with real sizes and real SPKI parsing — see fake-mldsa.ts.
 * The native algorithm itself is exercised only by the skipIf-gated suite in
 * pq.test.ts on runtimes that have it. Nothing here silently passes because
 * of a skip: the fake makes each assertion falsifiable everywhere.
 */
import { describe, expect, it } from "vitest";
import { createPrivateKey, sign as edSign, verify as edVerify, createPublicKey } from "node:crypto";
import { AuditLedger } from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import { canonicalJson } from "../src/ledger/hash.js";
import {
  MANDATE_ALG,
  MANDATE_DOMAIN,
  MandateManager,
  generateMandateKeyPair,
  mandateKeyId,
  type Mandate,
} from "../src/mandate/mandate.js";
import {
  MANDATE_V2_ALGS,
  MANDATE_V2_DOMAIN,
  MANDATE_V2_FORMAT_VERSION,
  checkMandateV2Structure,
  mandateV2Payload,
  type MandateV2,
} from "../src/mandate/hybrid.js";
import {
  MLDSA44_ALG,
  MLDSA44_SIGNATURE_BYTES,
  PqUnavailableError,
  mlDsa44Available,
  mlDsa44KeyId,
} from "../src/mandate/pq.js";
import { SignerError } from "../src/mandate/signer.js";
import { fakeMlDsa44KeyPair, fakeMlDsa44Ops } from "./fake-mldsa.js";
import { makeIntent } from "./helpers.js";

const constraints = {
  maxAmountMinor: 10_000,
  currency: "USD",
  validFrom: new Date(Date.now() - 1000).toISOString(),
  expiresAt: new Date(Date.now() + 60_000).toISOString(),
  maxUses: 1,
};

const fake = fakeMlDsa44Ops();
const edKeys = generateMandateKeyPair();
const pqKeys = fakeMlDsa44KeyPair("issuer-1");

function hybridIssuer(opts: { requireAlgs?: string[] } = {}) {
  return new MandateManager(
    {
      publicKeyPem: edKeys.publicKeyPem,
      privateKeyPem: edKeys.privateKeyPem,
      mlDsa44PublicKeyPem: pqKeys.publicKeyPem,
      mlDsa44PrivateKeyPem: pqKeys.privateKeyPem,
    },
    new AuditLedger(new MemoryLedgerStore()),
    undefined,
    { pq: fake, ...opts },
  );
}

/** A verifier with chosen key/policy config, holding mandate `m`. */
function verifierHolding(
  m: Mandate | MandateV2,
  cfg: {
    ed?: boolean;
    pqKey?: boolean;
    requireAlgs?: string[];
    pq?: typeof fake | null;
  } = {},
) {
  const v = new MandateManager(
    {
      ...(cfg.ed !== false ? { publicKeyPem: edKeys.publicKeyPem } : {}),
      ...(cfg.pqKey !== false ? { mlDsa44PublicKeyPem: pqKeys.publicKeyPem } : {}),
    },
    new AuditLedger(new MemoryLedgerStore()),
    undefined,
    {
      pq: cfg.pq !== undefined ? cfg.pq : fake,
      ...(cfg.requireAlgs ? { requireAlgs: cfg.requireAlgs } : {}),
    },
  );
  v.register(m);
  return v;
}

const issueHybrid = (m: MandateManager) =>
  m.issueHybrid({ issuer: "human@example.com", agentId: "agent-1", constraints });

describe("issuing a hybrid mandate", () => {
  it("carries v2, the exact alg suite, per-alg kids, and BOTH signatures over the SAME v2-tagged payload", async () => {
    const mandate = await issueHybrid(hybridIssuer());
    expect(mandate.v).toBe(MANDATE_V2_FORMAT_VERSION);
    expect(mandate.algs).toEqual([...MANDATE_V2_ALGS]);
    expect(mandate.kids[MANDATE_ALG]).toBe(mandateKeyId(edKeys.publicKeyPem));
    expect(mandate.kids[MLDSA44_ALG]).toBe(mlDsa44KeyId(pqKeys.publicKeyPem));

    const { signatures, ...unsigned } = mandate;
    const payload = mandateV2Payload(unsigned);
    // NEW domain tag, NEW version — the v1 preimage space is untouched.
    expect(payload.toString("utf8").startsWith("vaduno-mandate/v2\n")).toBe(true);
    expect(MANDATE_V2_DOMAIN).not.toBe(MANDATE_DOMAIN);
    // Both signatures verify over the SAME bytes.
    expect(
      edVerify(
        null,
        payload,
        createPublicKey(edKeys.publicKeyPem),
        Buffer.from(signatures[MANDATE_ALG]!, "base64"),
      ),
    ).toBe(true);
    expect(
      fake.verify(payload, pqKeys.publicKeyPem, Buffer.from(signatures[MLDSA44_ALG]!, "base64")),
    ).toBe(true);
  });

  it("verifies, consumes once, and hydrates from the ledger like any mandate", async () => {
    const ledger = new AuditLedger(new MemoryLedgerStore());
    const issuer = new MandateManager(
      {
        publicKeyPem: edKeys.publicKeyPem,
        privateKeyPem: edKeys.privateKeyPem,
        mlDsa44PublicKeyPem: pqKeys.publicKeyPem,
        mlDsa44PrivateKeyPem: pqKeys.privateKeyPem,
      },
      ledger,
      undefined,
      { pq: fake },
    );
    const mandate = await issueHybrid(issuer);
    const intent = makeIntent({ mandateId: mandate.id });
    expect(issuer.check(mandate.id, intent).ok).toBe(true);
    const outcome = await issuer.consumeOnce(mandate.id, intent);
    expect(outcome.kind).toBe("consumed");
    // A second, DIFFERENT intent is refused — single use, enforced atomically.
    const again = await issuer.consumeOnce(mandate.id, makeIntent());
    expect(again.kind).toBe("rejected");

    // Restart: a fresh verify-only manager rebuilds v2 state from the ledger.
    const restarted = new MandateManager(
      { publicKeyPem: edKeys.publicKeyPem, mlDsa44PublicKeyPem: pqKeys.publicKeyPem },
      ledger,
      undefined,
      { pq: fake },
    );
    await restarted.hydrateFromLedger();
    expect(restarted.check(mandate.id, makeIntent()).code).toBe("USES_EXHAUSTED");
  });

  it("refuses to issue hybrid without the ML-DSA key, and construction with one fails on a no-PQ runtime", async () => {
    const noPq = new MandateManager(
      { publicKeyPem: edKeys.publicKeyPem, privateKeyPem: edKeys.privateKeyPem },
      new AuditLedger(new MemoryLedgerStore()),
      undefined,
      { pq: fake },
    );
    await expect(issueHybrid(noPq)).rejects.toThrow(/mlDsa44PrivateKeyPem/);

    // Constructing a hybrid ISSUER on a runtime with no ML-DSA fails at
    // construction (typed), never at first issue.
    expect(
      () =>
        new MandateManager(
          {
            publicKeyPem: edKeys.publicKeyPem,
            privateKeyPem: edKeys.privateKeyPem,
            mlDsa44PublicKeyPem: pqKeys.publicKeyPem,
            mlDsa44PrivateKeyPem: pqKeys.privateKeyPem,
          },
          undefined,
          undefined,
          { pq: null },
        ),
    ).toThrow(PqUnavailableError);
  });

  it.skipIf(mlDsa44Available())(
    "SKIPPED-ON-PQ-RUNTIMES: with NO override, a hybrid-signing config throws the typed PqUnavailableError (real probe says no)",
    () => {
      expect(
        () =>
          new MandateManager({
            publicKeyPem: edKeys.publicKeyPem,
            privateKeyPem: edKeys.privateKeyPem,
            mlDsa44PublicKeyPem: pqKeys.publicKeyPem,
            mlDsa44PrivateKeyPem: pqKeys.privateKeyPem,
          }),
      ).toThrow(PqUnavailableError);
    },
  );
});

describe("hybrid verification: both halves must verify where checkable", () => {
  it("a tampered constraint breaks the Ed25519 signature (checked first)", async () => {
    const mandate = await issueHybrid(hybridIssuer());
    const tampered: MandateV2 = {
      ...mandate,
      constraints: { ...mandate.constraints, maxAmountMinor: 1_000_000 },
    };
    expect(verifierHolding(tampered).check(tampered.id, makeIntent()).code).toBe(
      "SIGNATURE_INVALID",
    );
  });

  it("a valid Ed25519 half with a corrupted ML-DSA half is REFUSED — present-but-invalid is tamper evidence, never ignorable", async () => {
    const mandate = await issueHybrid(hybridIssuer());
    const bad = Buffer.from(mandate.signatures[MLDSA44_ALG]!, "base64");
    bad[0] = bad[0]! ^ 0xff;
    const tampered: MandateV2 = {
      ...mandate,
      signatures: { ...mandate.signatures, [MLDSA44_ALG]: bad.toString("base64") },
    };
    const check = verifierHolding(tampered).check(tampered.id, makeIntent());
    expect(check.ok).toBe(false);
    expect(check.code).toBe("SIGNATURE_INVALID");
    expect(check.message).toContain(MLDSA44_ALG);
  });

  it("an unknown Ed25519 kid is KEY_UNKNOWN", async () => {
    const mandate = await issueHybrid(hybridIssuer());
    const other = generateMandateKeyPair();
    const v = new MandateManager(
      { publicKeyPem: other.publicKeyPem, mlDsa44PublicKeyPem: pqKeys.publicKeyPem },
      new AuditLedger(new MemoryLedgerStore()),
      undefined,
      { pq: fake },
    );
    v.register(mandate);
    expect(v.check(mandate.id, makeIntent()).code).toBe("KEY_UNKNOWN");
  });

  it("an unheld ML-DSA kid rests on the classical signature WITHOUT requireAlgs, and is KEY_UNKNOWN with it", async () => {
    const mandate = await issueHybrid(hybridIssuer());
    // Verifier holds the Ed25519 key but a DIFFERENT ML-DSA key.
    const otherPq = fakeMlDsa44KeyPair("someone-else");
    const relying = new MandateManager(
      { publicKeyPem: edKeys.publicKeyPem, mlDsa44PublicKeyPem: otherPq.publicKeyPem },
      new AuditLedger(new MemoryLedgerStore()),
      undefined,
      { pq: fake },
    );
    relying.register(mandate);
    // Same standing as a v1 mandate — no PQ trust anchor for this kid, so
    // classical trust is all it ever had here. Documented residual.
    expect(relying.check(mandate.id, makeIntent()).ok).toBe(true);

    const strict = new MandateManager(
      { publicKeyPem: edKeys.publicKeyPem, mlDsa44PublicKeyPem: otherPq.publicKeyPem },
      new AuditLedger(new MemoryLedgerStore()),
      undefined,
      { pq: fake, requireAlgs: [MLDSA44_ALG] },
    );
    strict.register(mandate);
    expect(strict.check(mandate.id, makeIntent()).code).toBe("KEY_UNKNOWN");
  });
});

describe("no-PQ runtime (pq: null): the documented degraded path", () => {
  it("a v2 mandate verifies RESTING ON ITS CLASSICAL SIGNATURE", async () => {
    const mandate = await issueHybrid(hybridIssuer());
    const v = verifierHolding(mandate, { pq: null });
    expect(v.check(mandate.id, makeIntent()).ok).toBe(true);
  });

  it("with requireAlgs [ML-DSA-44] the same mandate is REFUSED, naming the probe", async () => {
    const mandate = await issueHybrid(hybridIssuer());
    const v = verifierHolding(mandate, { pq: null, requireAlgs: [MLDSA44_ALG] });
    const check = v.check(mandate.id, makeIntent());
    expect(check.ok).toBe(false);
    expect(check.code).toBe("ALG_REQUIREMENT_NOT_MET");
    expect(check.message).toMatch(/probe/);
    expect(check.message).toMatch(/OpenSSL >= 3\.5/);
  });
});

describe("ATTACK: the post-CRQC downgrade is a FRESH v1 MINT, and requireAlgs is the defense", () => {
  it("exposure: an attacker holding a recovered Ed25519 key mints a fresh v1 that verifies — no v2 stripping needed", async () => {
    // Post-CRQC, the attacker recovers the issuer's Ed25519 private key from
    // its public half. Simulated here by simply USING the private key: the
    // point is that the verifier still registers Ed25519-only trust, so
    // nothing about issuing v2 mandates protects anything by itself.
    const attacker = new MandateManager(
      { publicKeyPem: edKeys.publicKeyPem, privateKeyPem: edKeys.privateKeyPem },
      new AuditLedger(new MemoryLedgerStore()),
    );
    const forgedFreshV1 = await attacker.issue({
      issuer: "human@example.com", // claims to be the real issuer
      agentId: "agent-1",
      constraints: { ...constraints, maxAmountMinor: 999_999 },
    });

    // The victim verifier: hybrid-capable, holds BOTH keys, verifies v2
    // strictly — and still accepts the fresh v1, because requireAlgs
    // defaults to [] and v1 remains a supported format.
    const victim = verifierHolding(forgedFreshV1);
    const check = victim.check(forgedFreshV1.id, makeIntent());
    expect(check.ok).toBe(true); // THE EXPOSURE — this line failing would mean the doc overclaims

    // Remedy: requireAlgs ["ML-DSA-44"] refuses every v1 outright, however
    // perfect its Ed25519 signature. This — or de-registering classical-only
    // trust — is the ONLY defense; the refusal happens before any crypto.
    const hardened = verifierHolding(forgedFreshV1, { requireAlgs: [MLDSA44_ALG] });
    const denied = hardened.check(forgedFreshV1.id, makeIntent());
    expect(denied.ok).toBe(false);
    expect(denied.code).toBe("ALG_REQUIREMENT_NOT_MET");
    expect(denied.message).toContain("v1");
  });

  it("requireAlgs is validated at construction — a typo cannot silently deny forever", () => {
    expect(
      () =>
        new MandateManager(
          { publicKeyPem: edKeys.publicKeyPem },
          undefined,
          undefined,
          { requireAlgs: ["ML-DSA-65"] },
        ),
    ).toThrow(SignerError);
  });
});

describe("(algorithm, kid) binding — a truncated-hash collision cannot cross families", () => {
  it("a v1 mandate naming the ML-DSA key's kid is KEY_UNKNOWN even though that 16-hex id IS registered (under ML-DSA-44)", () => {
    // mandateKeyId is a 64-bit truncated hash, so ids from different
    // families can collide. Key lookup binds the algorithm: the Ed25519
    // registry is consulted for v1, and an id living only in the ML-DSA
    // registry must not resolve. (The old doc claim said collisions were
    // impossible "by construction" — that was false and is now removed.)
    const mlKid = mlDsa44KeyId(pqKeys.publicKeyPem);
    const unsigned: Omit<Mandate, "signature"> = {
      v: 1,
      alg: MANDATE_ALG,
      kid: mlKid, // names an id held ONLY by the ML-DSA-44 registry
      id: "33333333-4444-5555-6666-777777777777",
      issuer: "human@example.com",
      agentId: "agent-1",
      constraints,
      createdAt: new Date().toISOString(),
    };
    const payload = Buffer.from(MANDATE_DOMAIN + canonicalJson(unsigned), "utf8");
    const signature = edSign(null, payload, createPrivateKey(edKeys.privateKeyPem)).toString(
      "base64",
    );
    const mandate: Mandate = { ...unsigned, signature };

    const v = verifierHolding(mandate);
    const check = v.check(mandate.id, makeIntent());
    expect(check.ok).toBe(false);
    expect(check.code).toBe("KEY_UNKNOWN");
  });
});

describe("pre-crypto structural bounds (MALFORMED before any signature check)", () => {
  async function issued(): Promise<MandateV2> {
    return issueHybrid(hybridIssuer());
  }

  it("algs must be exactly the hybrid suite, in order", async () => {
    const m = await issued();
    for (const algs of [
      ["ML-DSA-44", "Ed25519"], // reordered
      ["Ed25519"], // v1's job
      ["Ed25519", "ML-DSA-44", "ML-DSA-87"], // extra
      [],
    ]) {
      const bad = { ...m, algs } as MandateV2;
      expect(checkMandateV2Structure(bad).ok).toBe(false);
      const check = verifierHolding(bad).check(bad.id, makeIntent());
      expect(check.code).toBe("MALFORMED");
    }
  });

  it("kids keys MUST equal algs exactly, and each kid must be 16 lowercase hex", async () => {
    const m = await issued();
    const cases: Array<Record<string, string>> = [
      { ...m.kids, extra: "aaaaaaaaaaaaaaaa" }, // extra key
      { [MANDATE_ALG]: m.kids[MANDATE_ALG]! }, // missing ML-DSA-44
      { ...m.kids, [MLDSA44_ALG]: "AAAAAAAAAAAAAAAA" }, // uppercase
      { ...m.kids, [MLDSA44_ALG]: "abcd" }, // too short
      { ...m.kids, [MLDSA44_ALG]: "0".repeat(64) }, // too long
    ];
    for (const kids of cases) {
      const bad = { ...m, kids } as MandateV2;
      const r = checkMandateV2Structure(bad);
      expect(r.ok).toBe(false);
      expect(verifierHolding(bad).check(bad.id, makeIntent()).code).toBe("MALFORMED");
    }
  });

  it("signature length is checked on the DECODED bytes, not the encoded string", async () => {
    const m = await issued();
    // 64 valid base64 chars decode to 48 bytes — an encoded-length check
    // could be satisfied while the decoded signature is the wrong size.
    const wrongSize = Buffer.alloc(64).toString("base64"); // 64 bytes, not 2420
    const bad: MandateV2 = {
      ...m,
      signatures: { ...m.signatures, [MLDSA44_ALG]: wrongSize },
    };
    const r = checkMandateV2Structure(bad);
    expect(r.ok).toBe(false);
    expect(!r.ok && r.message).toMatch(new RegExp(String(MLDSA44_SIGNATURE_BYTES)));
    expect(verifierHolding(bad).check(bad.id, makeIntent()).code).toBe("MALFORMED");
  });

  it("rejects non-base64, oversized, and missing signatures", async () => {
    const m = await issued();
    for (const sig of [
      "not base64 !!", // alphabet violation
      "A".repeat(4000), // longer than 2420 bytes can encode
      "", // empty
    ]) {
      const bad: MandateV2 = { ...m, signatures: { ...m.signatures, [MLDSA44_ALG]: sig } };
      expect(checkMandateV2Structure(bad).ok).toBe(false);
    }
    const missing = { ...m, signatures: { [MANDATE_ALG]: m.signatures[MANDATE_ALG]! } };
    expect(checkMandateV2Structure(missing as MandateV2).ok).toBe(false);
  });

  it("a well-formed issued mandate passes the gate", async () => {
    expect(checkMandateV2Structure(await issued()).ok).toBe(true);
  });
});

describe("v1 and v2 coexist", () => {
  it("one manager verifies and consumes both formats side by side", async () => {
    const ledger = new AuditLedger(new MemoryLedgerStore());
    const manager = new MandateManager(
      {
        publicKeyPem: edKeys.publicKeyPem,
        privateKeyPem: edKeys.privateKeyPem,
        mlDsa44PublicKeyPem: pqKeys.publicKeyPem,
        mlDsa44PrivateKeyPem: pqKeys.privateKeyPem,
      },
      ledger,
      undefined,
      { pq: fake },
    );
    const v1 = await manager.issue({ issuer: "h@e.com", agentId: "agent-1", constraints });
    const v2 = await manager.issueHybrid({ issuer: "h@e.com", agentId: "agent-1", constraints });
    expect(manager.check(v1.id, makeIntent()).ok).toBe(true);
    expect(manager.check(v2.id, makeIntent()).ok).toBe(true);
    expect((await manager.consumeOnce(v1.id, makeIntent())).kind).toBe("consumed");
    expect((await manager.consumeOnce(v2.id, makeIntent())).kind).toBe("consumed");
  });
});
