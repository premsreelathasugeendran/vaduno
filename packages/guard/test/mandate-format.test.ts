/**
 * Mandate signing-format guarantees added in 0.3.0.
 *
 * Before this, the signed payload was bare `canonicalJson(mandate)` — no domain
 * tag, no algorithm, no key id, no version — while every other signed structure
 * in the project (contextHash, the STH, the status-list credential, the
 * transparency leaf) domain-separated correctly. Mandates were the exception,
 * and they are the structure that authorizes spending money.
 */
import { describe, expect, it } from "vitest";
import { AuditLedger } from "../src/ledger/ledger.js";
import { MemoryLedgerStore } from "../src/ledger/stores/memory.js";
import {
  MANDATE_ALG,
  MANDATE_DOMAIN,
  MANDATE_FORMAT_VERSION,
  MandateManager,
  generateMandateKeyPair,
  mandateKeyId,
  type Mandate,
} from "../src/mandate/mandate.js";
import { canonicalJson } from "../src/ledger/hash.js";
import { makeIntent } from "./helpers.js";

const constraints = {
  maxAmountMinor: 10_000,
  currency: "USD",
  validFrom: new Date(Date.now() - 1000).toISOString(),
  expiresAt: new Date(Date.now() + 60_000).toISOString(),
  maxUses: 1,
};

function mm(keys = generateMandateKeyPair(), extra?: string[]) {
  return {
    keys,
    manager: new MandateManager({
      publicKeyPem: keys.publicKeyPem,
      privateKeyPem: keys.privateKeyPem,
      ...(extra ? { additionalPublicKeyPems: extra } : {}),
    }, new AuditLedger(new MemoryLedgerStore())),
  };
}

const issue = (m: MandateManager) =>
  m.issue({ issuer: "human@example.com", agentId: "agent-1", constraints });

describe("mandate carries its own format metadata", () => {
  it("stamps version, algorithm and the key id that signed it", async () => {
    const { keys, manager } = mm();
    const mandate = await issue(manager);
    expect(mandate.v).toBe(MANDATE_FORMAT_VERSION);
    expect(mandate.alg).toBe(MANDATE_ALG);
    expect(mandate.kid).toBe(mandateKeyId(keys.publicKeyPem));
  });

  it("derives the same key id from the same key, independently", () => {
    const keys = generateMandateKeyPair();
    // Derived from the key, not assigned — so a second implementation computes
    // the identical id without coordinating with this one.
    expect(mandateKeyId(keys.publicKeyPem)).toBe(mandateKeyId(keys.publicKeyPem));
    expect(mandateKeyId(keys.publicKeyPem)).not.toBe(
      mandateKeyId(generateMandateKeyPair().publicKeyPem),
    );
  });

  it("signs over the DOMAIN TAG, not bare canonical JSON", async () => {
    const { manager } = mm();
    const mandate = await issue(manager);
    const { signature: _sig, ...unsigned } = mandate;
    // The bytes a verifier must reconstruct. If the domain tag were dropped,
    // this mandate would share a signature space with any other structure whose
    // canonical form happened to coincide.
    const signed = MANDATE_DOMAIN + canonicalJson(unsigned);
    expect(signed.startsWith("vaduno-mandate/v1\n")).toBe(true);
    expect(signed).not.toBe(canonicalJson(unsigned));
  });
});

describe("a verifier refuses what it cannot check, rather than guessing", () => {
  // A tampered copy has to be registered into a verifier that has NOT already
  // seen the id: register() is deliberately a no-op for a known mandate, so
  // that re-registering cannot reset a use count.
  function verifierHolding(publicKeyPem: string, m: Mandate): MandateManager {
    const v = new MandateManager({ publicKeyPem }, new AuditLedger(new MemoryLedgerStore()));
    v.register(m);
    return v;
  }

  it("refuses an unknown format version", async () => {
    const { keys, manager } = mm();
    const mandate = await issue(manager);
    const v = verifierHolding(keys.publicKeyPem, { ...mandate, v: 99 } as Mandate);
    expect(v.check(mandate.id, makeIntent()).code).toBe("VERSION_UNSUPPORTED");
  });

  it("refuses an algorithm it does not implement", async () => {
    const { keys, manager } = mm();
    const mandate = await issue(manager);
    const v = verifierHolding(keys.publicKeyPem, { ...mandate, alg: "RSA-PSS" } as Mandate);
    expect(v.check(mandate.id, makeIntent()).code).toBe("ALG_UNSUPPORTED");
  });

  it("refuses a key it does not hold, naming the key", async () => {
    const issuer = mm();
    const other = mm();
    const mandate = await issue(issuer.manager);
    other.manager.register(mandate);
    const check = other.manager.check(mandate.id, makeIntent());
    expect(check.code).toBe("KEY_UNKNOWN");
    expect(check.message).toContain(mandate.kid);
  });

  it("ATTACK: swapping kid to a key the verifier DOES hold does not help", async () => {
    // The kid is inside the signed payload, so relabelling a mandate to name a
    // different key changes the bytes and breaks the signature. Without that,
    // a rotation window would accept a mandate whose kid claims one key while
    // the signature was made by another.
    const attacker = mm();
    const victim = mm();
    const mandate = await issue(attacker.manager);

    const relabelled: Mandate = { ...mandate, kid: mandateKeyId(victim.keys.publicKeyPem) };
    const v = new MandateManager(
      { publicKeyPem: victim.keys.publicKeyPem },
      new AuditLedger(new MemoryLedgerStore()),
    );
    v.register(relabelled);
    const check = v.check(relabelled.id, makeIntent());

    expect(check.ok).toBe(false);
    expect(check.code).toBe("SIGNATURE_INVALID");
  });
});

describe("key rotation", () => {
  it("a verifier holding both keys accepts mandates from either", async () => {
    const oldKeys = generateMandateKeyPair();
    const newKeys = generateMandateKeyPair();

    const oldIssuer = mm(oldKeys).manager;
    const mandateFromOldKey = await issue(oldIssuer);

    // The rotation overlap: sign with the new key, still accept the old one
    // while previously-issued mandates are inside their validity window.
    const rotated = new MandateManager(
      {
        publicKeyPem: newKeys.publicKeyPem,
        privateKeyPem: newKeys.privateKeyPem,
        additionalPublicKeyPems: [oldKeys.publicKeyPem],
      },
      new AuditLedger(new MemoryLedgerStore()),
    );

    rotated.register(mandateFromOldKey);
    expect(rotated.check(mandateFromOldKey.id, makeIntent()).ok).toBe(true);

    const mandateFromNewKey = await issue(rotated);
    expect(mandateFromNewKey.kid).toBe(mandateKeyId(newKeys.publicKeyPem));
    expect(rotated.check(mandateFromNewKey.id, makeIntent()).ok).toBe(true);
  });

  it("additional keys are verify-only — the manager signs with its own key", async () => {
    const signing = generateMandateKeyPair();
    const foreign = generateMandateKeyPair();
    const manager = new MandateManager(
      {
        publicKeyPem: signing.publicKeyPem,
        privateKeyPem: signing.privateKeyPem,
        additionalPublicKeyPems: [foreign.publicKeyPem],
      },
      new AuditLedger(new MemoryLedgerStore()),
    );
    const mandate = await issue(manager);
    expect(mandate.kid).toBe(mandateKeyId(signing.publicKeyPem));
    expect(mandate.kid).not.toBe(mandateKeyId(foreign.publicKeyPem));
  });
});
