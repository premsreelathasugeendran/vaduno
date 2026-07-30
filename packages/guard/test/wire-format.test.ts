/**
 * The wire format is what it says on disk, not what the code happens to do.
 *
 * These tests read `spec/vectors/*.json` — committed, hand-checkable constants —
 * and assert the implementation reproduces them. That direction matters:
 * before this existed, `hash.test.ts` compared canonicalJson to ITSELF
 * (`canonicalJson(a) === canonicalJson(b)`) and the repo contained no hardcoded
 * digest for any signed structure. Every preimage in the project could have
 * drifted silently, and a second implementation had nothing to check against.
 *
 * If one of these fails, the wire format changed. That is either a bug or a
 * deliberate breaking change requiring a domain-tag version bump — it is never
 * a reason to regenerate the vectors until the test passes.
 */
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { canonicalJson, sha256Hex, CanonicalizeError } from "../src/ledger/hash.js";
import {
  MANDATE_DOMAIN,
  mandateContextHash,
  mandateKeyId,
} from "../src/mandate/mandate.js";
import { intentDigest } from "../src/enforce/consume-store.js";
import type { PaymentIntent } from "../src/types.js";

const vectorsDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "spec", "vectors");
const load = <T>(name: string): T =>
  JSON.parse(readFileSync(join(vectorsDir, name), "utf8")) as T;

describe("canonicalJson matches the committed vectors", () => {
  const v = load<{ cases: { note: string; input: unknown; canonical: string }[] }>(
    "canonical-json.json",
  );

  for (const c of v.cases) {
    it(c.note, () => {
      expect(canonicalJson(c.input)).toBe(c.canonical);
    });
  }

  it("every committed case canonicalizes to a DISTINCT string", () => {
    // Injectivity, asserted over the vector set rather than argued for.
    const outputs = v.cases.map((c) => c.canonical);
    expect(new Set(outputs).size).toBe(outputs.length);
  });

  it("rejects each input the vectors say must be rejected", () => {
    const rejected: Array<() => unknown> = [
      () => canonicalJson({ n: 1n }),
      () => canonicalJson({ d: new Date(0) }),
      () => canonicalJson({ x: Number.NaN }),
      () => canonicalJson({ x: Number.POSITIVE_INFINITY }),
      () => canonicalJson([undefined]),
      () => canonicalJson({ v: new Map([[1, 2]]) }),
    ];
    for (const fn of rejected) expect(fn).toThrow(CanonicalizeError);
  });
});

describe("sha256Hex matches the committed vectors", () => {
  const v = load<{ cases: { input: string; hash: string }[] }>("sha256.json");
  for (const c of v.cases) {
    it(`sha256(${JSON.stringify(c.input)})`, () => {
      expect(sha256Hex(c.input)).toBe(c.hash);
    });
  }
});

describe("mandate signing preimage matches the committed vector", () => {
  const v = load<{
    domain: string;
    testKeys: { publicKeyPem: string };
    expectedKeyId: string;
    unsigned: Record<string, unknown>;
    preimage: string;
    preimageSha256: string;
  }>("mandate.json");

  it("the domain tag is the one on disk", () => {
    expect(MANDATE_DOMAIN).toBe(v.domain);
  });

  it("the key id derives from the fixed test key exactly", () => {
    // Derived, not assigned — so a second implementation reaches the same id
    // from the public key alone.
    expect(mandateKeyId(v.testKeys.publicKeyPem)).toBe(v.expectedKeyId);
  });

  it("the preimage bytes reproduce", () => {
    expect(MANDATE_DOMAIN + canonicalJson(v.unsigned)).toBe(v.preimage);
    expect(sha256Hex(v.preimage)).toBe(v.preimageSha256);
  });

  it("the kid is INSIDE the preimage, so relabelling changes the bytes", () => {
    const relabelled = { ...v.unsigned, kid: "0000000000000000" };
    expect(MANDATE_DOMAIN + canonicalJson(relabelled)).not.toBe(v.preimage);
  });
});

describe("mandateContextHash matches the committed vector", () => {
  const v = load<{ context: Record<string, unknown>; hash: string }>("mandate-context.json");
  it("reproduces the committed hash", () => {
    expect(mandateContextHash(v.context)).toBe(v.hash);
  });
});

describe("intentDigest matches the committed vector", () => {
  const v = load<{ intent: PaymentIntent; digest: string }>("intent-digest.json");

  it("reproduces the committed digest", () => {
    expect(intentDigest(v.intent)).toBe(v.digest);
  });

  it("changing a MONEY field changes the digest", () => {
    const dearer: PaymentIntent = {
      ...v.intent,
      amount: { ...v.intent.amount, amountMinor: v.intent.amount.amountMinor + 1 },
    };
    expect(intentDigest(dearer)).not.toBe(v.digest);
  });

  it("changing a NON-money field does not", () => {
    // The digest deliberately covers money-affecting fields only, so an
    // honest retry carrying a new timestamp still replays rather than being
    // rejected as a different payment.
    const later: PaymentIntent = { ...v.intent, requestedAt: "2027-06-06T06:06:06.000Z" };
    expect(intentDigest(later)).toBe(v.digest);
  });
});

describe("ledger entry hash matches the committed vector", () => {
  const v = load<{ entry: Record<string, unknown>; hash: string; genesisPrevHash: string }>(
    "ledger-entry.json",
  );

  it("reproduces the committed hash", () => {
    expect(sha256Hex(canonicalJson(v.entry))).toBe(v.hash);
  });

  it("changing prevHash changes the entry hash — the chain link holds", () => {
    const forked = { ...v.entry, prevHash: "1".repeat(64) };
    expect(sha256Hex(canonicalJson(forked))).not.toBe(v.hash);
  });
});

describe("Merkle hashing matches the committed vector (RFC 9162)", () => {
  const v = load<{
    emptyTreeRoot: string;
    cases: Array<{ leaf?: string; leafHash?: string; left?: string; right?: string; root?: string }>;
  }>("merkle.json");

  const leafHash = (data: string) =>
    createHash("sha256")
      .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(data, "utf8")]))
      .digest("hex");
  const nodeHash = (l: string, r: string) =>
    createHash("sha256")
      .update(Buffer.concat([Buffer.from([0x01]), Buffer.from(l, "hex"), Buffer.from(r, "hex")]))
      .digest("hex");

  it("leaf hashes reproduce", () => {
    for (const c of v.cases) {
      if (c.leaf !== undefined && c.leafHash) expect(leafHash(c.leaf)).toBe(c.leafHash);
    }
  });

  it("interior node hashes reproduce", () => {
    for (const c of v.cases) {
      if (c.left && c.right && c.root) expect(nodeHash(c.left, c.right)).toBe(c.root);
    }
  });

  it("the 0x00/0x01 prefixes actually separate the two domains", () => {
    // Without distinct prefixes, a leaf could be presented as an interior node
    // — the second-preimage attack RFC 6962 exists to prevent.
    const a = leafHash("x");
    const b = createHash("sha256").update(Buffer.from("x", "utf8")).digest("hex");
    expect(a).not.toBe(b);
  });

  it("the empty tree root is SHA-256 of nothing", () => {
    expect(createHash("sha256").update(Buffer.alloc(0)).digest("hex")).toBe(v.emptyTreeRoot);
  });
});

describe("domain separators are all distinct and all committed", () => {
  const v = load<{ domains: Record<string, string> }>("domains.json");

  it("no two structures share a domain tag", () => {
    const tags = Object.values(v.domains);
    expect(new Set(tags).size).toBe(tags.length);
  });

  it("every tag is versioned and newline-terminated", () => {
    // The trailing newline is what stops a tag being a prefix of a longer one,
    // and the version is what makes a future format change expressible.
    for (const [name, tag] of Object.entries(v.domains)) {
      expect(tag, name).toMatch(/^vaduno-[a-z-]+\/v\d+\n$/);
    }
  });

  it("the mandate tag in code equals the one on disk", () => {
    expect(MANDATE_DOMAIN).toBe(v.domains.mandate);
  });
});
