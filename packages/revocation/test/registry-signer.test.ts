/**
 * Status-list publishing behind a pluggable Ed25519Signer. The properties:
 * byte-identical wire output vs the pem path; misconfig refused at
 * construction; and — the rollback-floor interaction — a first-publish
 * signing failure leaves the version counter UNCHANGED so the SAME version
 * stays retryable. Without that, a wedged KMS would burn version numbers and
 * hand a verifier's monotonic floor a gap it could misread as rollback.
 */
import { describe, expect, it } from "vitest";
import {
  AuditLedger,
  LocalKeySigner,
  MemoryLedgerStore,
  SignerError,
  generateMandateKeyPair,
  type Ed25519Signer,
} from "@vaduno/guard";
import { Bitstring, MINIMUM_ENTRIES } from "../src/bitstring.js";
import { checkStatus, publishStatusList, publishStatusListWith } from "../src/status-list.js";
import { RevocationRegistry } from "../src/registry.js";

const keys = generateMandateKeyPair();
const signer = new LocalKeySigner(keys.privateKeyPem);
const fixedNow = () => new Date("2026-08-03T00:00:00.000Z");

describe("publishStatusListWith is byte-identical to publishStatusList", () => {
  it("same key, same now(), same credential", async () => {
    const bits = new Bitstring(MINIMUM_ENTRIES);
    bits.set(7, true);
    const base = {
      id: "https://example.com/status/1",
      issuer: "issuer-1",
      statusPurpose: "revocation" as const,
      version: 3,
      now: fixedNow,
    };
    const sync = publishStatusList(bits, { ...base, privateKeyPem: keys.privateKeyPem });
    const viaSigner = await publishStatusListWith(bits, { ...base, signer });
    expect(viaSigner).toEqual(sync);

    const check = checkStatus(viaSigner, 7, {
      publicKeyPem: keys.publicKeyPem,
      expectedPurpose: "revocation",
      // Freshness is judged inside the credential's fixed validity window.
      now: () => new Date("2026-08-03T00:30:00.000Z"),
    });
    expect(check.revoked).toBe(true);
  });
});

describe("registry construction refusals", () => {
  it("refuses both privateKeyPem and signer", () => {
    expect(
      () =>
        new RevocationRegistry({
          issuer: "issuer-1",
          listId: "list-1",
          privateKeyPem: keys.privateKeyPem,
          signer,
        }),
    ).toThrow(SignerError);
  });

  it("refuses a non-Ed25519 signer", () => {
    const bad = {
      algorithm: "secp256k1",
      publicKeyPem: keys.publicKeyPem,
      sign: async () => new Uint8Array(64),
    } as unknown as Ed25519Signer;
    expect(
      () => new RevocationRegistry({ issuer: "issuer-1", listId: "list-1", signer: bad }),
    ).toThrow(SignerError);
  });

  it("refuses an unparseable legacy privateKeyPem at construction, not first publish", () => {
    expect(
      () =>
        new RevocationRegistry({ issuer: "issuer-1", listId: "list-1", privateKeyPem: "junk" }),
    ).toThrow(SignerError);
  });

  it("refuses a signer whose DECLARED public key does not parse — at construction, not first publish", () => {
    // "Throws at construction, before any authority exists" must hold here
    // exactly as it does for MandateManager; failing only at first publish
    // would let a half-configured registry be trusted in the meantime.
    const bad = {
      algorithm: "Ed25519",
      publicKeyPem: "not a pem",
      sign: async () => new Uint8Array(64),
    } as Ed25519Signer;
    expect(
      () => new RevocationRegistry({ issuer: "issuer-1", listId: "list-1", signer: bad }),
    ).toThrow(SignerError);
  });
});

describe("registry publishing through a signer", () => {
  it("signer-backed registry publishes a verifiable list", async () => {
    const registry = new RevocationRegistry({
      issuer: "issuer-1",
      listId: "list-1",
      signer,
      ledger: new AuditLedger(new MemoryLedgerStore()),
    });
    await registry.assignIndex("mandate-1", "agent-1");
    await registry.revokeMandate("mandate-1");
    const credential = await registry.publish(1);
    const idx = (await registry.isRevoked("mandate-1"))!.index!;
    const check = checkStatus(credential, idx, {
      publicKeyPem: keys.publicKeyPem,
      expectedPurpose: "revocation",
      expectedListId: "list-1",
      expectedIssuer: "issuer-1",
    });
    expect(check.revoked).toBe(true);
  });

  it("first-publish failure leaves the version RETRYABLE; the retry verifies", async () => {
    let failures = 1;
    const flaky: Ed25519Signer = {
      algorithm: "Ed25519",
      publicKeyPem: keys.publicKeyPem,
      sign: (m) => {
        if (failures > 0) {
          failures -= 1;
          return Promise.reject(new Error("kms unavailable"));
        }
        return signer.sign(m);
      },
    };
    const ledger = new AuditLedger(new MemoryLedgerStore());
    const registry = new RevocationRegistry({
      issuer: "issuer-1",
      listId: "list-1",
      signer: flaky,
      ledger,
    });
    await registry.revokeMandate("mandate-1");

    await expect(registry.publish(1)).rejects.toBeInstanceOf(SignerError);
    // Nothing was published: no status_list_published entry, version floor
    // untouched.
    const entries = await ledger.all();
    expect(entries.filter((e) => e.type === "status_list_published")).toHaveLength(0);

    // The SAME version succeeds on retry — no gap for a verifier's rollback
    // floor to misread.
    const credential = await registry.publish(1);
    expect(credential.version).toBe(1);
    const idx = (await registry.isRevoked("mandate-1"))!.index!;
    expect(
      checkStatus(credential, idx, {
        publicKeyPem: keys.publicKeyPem,
        expectedPurpose: "revocation",
      }).revoked,
    ).toBe(true);

    // And the floor still holds afterwards: re-publishing version 1 is refused.
    await expect(registry.publish(1)).rejects.toThrow(/strictly increase/);
  });

  it("two concurrent publishes through a SLOW signer can neither share a version nor regress the floor", async () => {
    // The attack window: an async signer puts a KMS round-trip between "read
    // the version floor" and "advance it". A timer-driven publisher racing an
    // on-demand publish could then mint two validly-signed credentials at the
    // SAME version — one showing a mandate revoked, one not — and the slower
    // publish could regress the floor: exactly the rollback the
    // strictly-increasing counter exists to prevent.
    const pending: Array<{ msg: Uint8Array; resolve: (sig: Uint8Array) => void }> = [];
    const slow: Ed25519Signer = {
      algorithm: "Ed25519",
      publicKeyPem: keys.publicKeyPem,
      // Parks every sign call until the test releases it — a controllable KMS.
      sign: (m) =>
        new Promise<Uint8Array>((resolve) => {
          pending.push({ msg: Buffer.from(m), resolve });
        }),
    };
    const registry = new RevocationRegistry({
      issuer: "issuer-1",
      listId: "list-1",
      signer: slow,
      now: fixedNow,
    });
    await registry.revokeMandate("mandate-1");

    const p1 = registry.publish(1);
    p1.catch(() => undefined);
    // v1 is now parked inside the signer. A second publish of the SAME
    // version must be refused while it is in flight...
    await expect(registry.publish(1)).rejects.toThrow(/strictly increase/);
    // ...while a HIGHER version may proceed concurrently.
    const p2 = registry.publish(2);
    p2.catch(() => undefined);
    await new Promise((r) => setTimeout(r, 20));
    expect(pending).toHaveLength(2);

    // Adversarial completion order: v2 signs FIRST, v1 (the older snapshot)
    // completes LAST. If the floor were assigned instead of max'd, v1's late
    // completion would drag it from 2 back to 1. Pick each parked call by the
    // version baked into its payload, not by arrival order.
    const parkedFor = (version: number) =>
      pending.find((p) => Buffer.from(p.msg).toString("utf8").includes(`"version":${version}`))!;
    const parked2 = parkedFor(2);
    parked2.resolve(await signer.sign(parked2.msg));
    const c2 = await p2;
    const parked1 = parkedFor(1);
    parked1.resolve(await signer.sign(parked1.msg));
    const c1 = await p1;

    // Distinct versions, both independently verifiable.
    expect(c1.version).toBe(1);
    expect(c2.version).toBe(2);
    for (const c of [c1, c2]) {
      expect(
        checkStatus(c, (await registry.isRevoked("mandate-1"))!.index!, {
          publicKeyPem: keys.publicKeyPem,
          expectedPurpose: "revocation",
          now: () => new Date("2026-08-03T00:30:00.000Z"),
        }).revoked,
      ).toBe(true);
    }

    // The floor did NOT regress to 1: versions 1 and 2 are burned, 3 is next.
    await expect(registry.publish(2)).rejects.toThrow(/strictly increase: 2 <= 2/);
    pending.length = 0;
    const p3 = registry.publish(3);
    await new Promise((r) => setTimeout(r, 20));
    pending[0]!.resolve(await signer.sign(pending[0]!.msg));
    expect((await p3).version).toBe(3);
  });

  it("a signer that ROTATES its declared key after construction is refused — the frozen key wins", async () => {
    // The registry snapshots the declared key at construction. A KMS wrapper
    // resolving "latest key version" that later rotates must fail closed
    // rather than publish lists this deployment can no longer verify.
    const rotated = generateMandateKeyPair();
    const rotatedSigner = new LocalKeySigner(rotated.privateKeyPem);
    let pem = keys.publicKeyPem;
    let backend: Ed25519Signer = signer;
    const rotating: Ed25519Signer = {
      algorithm: "Ed25519",
      get publicKeyPem() {
        return pem;
      },
      sign: (m) => backend.sign(m),
    };
    const registry = new RevocationRegistry({
      issuer: "issuer-1",
      listId: "list-1",
      signer: rotating,
    });
    await registry.revokeMandate("mandate-1");
    const before = await registry.publish(1);
    expect(before.version).toBe(1);

    // The backend rotates: declaration AND signing move to the new key.
    pem = rotated.publicKeyPem;
    backend = rotatedSigner;
    await expect(registry.publish(2)).rejects.toThrow(/declared public key/);
    // The failed publish released its reservation: version 2 stays retryable
    // once the operator restores the constructed key.
    pem = keys.publicKeyPem;
    backend = signer;
    expect((await registry.publish(2)).version).toBe(2);
  });
});
