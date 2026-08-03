/**
 * Shai-Hulud-style key harvest: a compromised dependency enumerates every
 * reachable object and every crypto call looking for private key material.
 *
 * With a KMS-backed signer config there must be nothing to find:
 *  - no code path calls createPrivateKey (asserted two ways: a module spy,
 *    and the sturdier runtime assertion that the manager's private-key field
 *    is null);
 *  - JSON.stringify and util.inspect of the manager and the signer contain
 *    no "PRIVATE KEY" — the PEM header every harvester greps for.
 */
import { inspect } from "node:util";
import * as crypto from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { MandateManager, generateMandateKeyPair } from "../src/mandate/mandate.js";
import { LocalKeySigner, type Ed25519Signer } from "../src/mandate/signer.js";
import { makeIntent } from "./helpers.js";

vi.mock("node:crypto", { spy: true });

const constraints = {
  maxAmountMinor: 10_000,
  currency: "USD",
  validFrom: new Date(Date.now() - 1000).toISOString(),
  expiresAt: new Date(Date.now() + 60_000).toISOString(),
  maxUses: 1,
};

/**
 * Stands in for a KMS: holds a KeyObject the way the HSM holds silicon —
 * created OUTSIDE the code paths under test, before the spy counter is read.
 */
function kmsBackedSigner(): { signer: Ed25519Signer; publicKeyPem: string } {
  const keys = generateMandateKeyPair();
  const remote = new LocalKeySigner(keys.privateKeyPem);
  return {
    publicKeyPem: keys.publicKeyPem,
    signer: {
      algorithm: "Ed25519",
      publicKeyPem: keys.publicKeyPem,
      // Only signatures cross this boundary, as with a real KMS.
      sign: (m) => remote.sign(m),
    },
  };
}

describe("nothing to harvest in a KMS-backed process", () => {
  it("no code path calls createPrivateKey between construction and issuance", async () => {
    const { signer } = kmsBackedSigner(); // uses createPrivateKey for the FAKE KMS's key
    vi.mocked(crypto.createPrivateKey).mockClear();

    const manager = new MandateManager({ signer });
    const mandate = await manager.issue({
      issuer: "human@example.com",
      agentId: "agent-1",
      constraints,
    });
    expect(manager.check(mandate.id, makeIntent()).ok).toBe(true);

    expect(vi.mocked(crypto.createPrivateKey).mock.calls.length).toBe(0);

    // Canary proving the spy is LIVE inside the modules under test — without
    // this, a broken mock would make the zero-count assertion decorative.
    new LocalKeySigner(generateMandateKeyPair().privateKeyPem);
    expect(vi.mocked(crypto.createPrivateKey).mock.calls.length).toBeGreaterThan(0);
  });

  it("the sturdier half: the manager's private-key field IS null", () => {
    const { signer } = kmsBackedSigner();
    const manager = new MandateManager({ signer });
    // Typed `null` in the source; asserted here so a regression that stores
    // key material in the manager fails a test, not just a comment.
    expect((manager as unknown as { privateKey: unknown }).privateKey).toBeNull();
  });

  it("JSON.stringify and util.inspect of manager and signer yield no PRIVATE KEY", async () => {
    const { signer } = kmsBackedSigner();
    const manager = new MandateManager({ signer });
    await manager.issue({ issuer: "human@example.com", agentId: "agent-1", constraints });

    for (const dump of [
      JSON.stringify(manager),
      JSON.stringify(signer),
      inspect(manager, { depth: 10, showHidden: true }),
      inspect(signer, { depth: 10, showHidden: true }),
    ]) {
      expect(dump).not.toContain("PRIVATE KEY");
    }
  });

  it("even the LEGACY config leaks nothing: the PEM is wrapped, not retained", async () => {
    // A legacy privateKeyPem config must not be the weak deployment: the PEM
    // string is consumed by LocalKeySigner's #private field and never stored
    // on the manager.
    const keys = generateMandateKeyPair();
    const manager = new MandateManager({
      publicKeyPem: keys.publicKeyPem,
      privateKeyPem: keys.privateKeyPem,
    });
    await manager.issue({ issuer: "human@example.com", agentId: "agent-1", constraints });
    for (const dump of [
      JSON.stringify(manager),
      inspect(manager, { depth: 10, showHidden: true }),
    ]) {
      expect(dump).not.toContain("PRIVATE KEY");
    }
    expect((manager as unknown as { privateKey: unknown }).privateKey).toBeNull();
  });

  it("the signer interface has no export path and no toJSON", () => {
    const local = new LocalKeySigner(generateMandateKeyPair().privateKeyPem);
    expect((local as unknown as { toJSON?: unknown }).toJSON).toBeUndefined();
    expect((local as unknown as { export?: unknown }).export).toBeUndefined();
    // Own enumerable surface is exactly the declared capability.
    expect(Object.keys(local).sort()).toEqual(["algorithm", "publicKeyPem"]);
  });
});
