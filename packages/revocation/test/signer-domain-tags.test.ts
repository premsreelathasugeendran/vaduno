/**
 * REVISION 4 — domain separation asserted AT THE SIGNER BOUNDARY, including
 * its honest limit.
 *
 * The key-separation requirement (docs/signers.md) says keys behind an
 * Ed25519Signer hold no other signing authority. Domain separation is the
 * defense-in-depth behind it, and it is PARTIAL:
 *
 *  - mandate / tree-head / status-list payloads begin with fixed vaduno-*
 *    tags, and cosignature payloads with the fixed C2SP `cosignature/v1`
 *    header — none of those can BE a rail transaction;
 *  - checkpoint payloads carry NO fixed tag: their leading bytes are the
 *    OPERATOR-CHOSEN origin (that is the C2SP format witnesses verify). The
 *    signer path compensates by refusing control/non-ASCII bytes in the
 *    body, so it cannot be shaped into a binary transaction framing — but
 *    the steering guarantee is scoped to the tagged payloads.
 *
 * A capture signer records every payload across every signing call site
 * (mandate issue, tree head, checkpoint, cosignature, status list — plus the
 * mirror and registry paths that route through them) and asserts the exact
 * prefix — or, for checkpoints, the exact untagged body and the printable-
 * ASCII refusal. If a future call site signs untagged bytes, or the
 * checkpoint path starts accepting binary origins, this fails.
 */
import { describe, expect, it } from "vitest";
import {
  AuditLedger,
  canonicalJson,
  LocalKeySigner,
  MANDATE_DOMAIN,
  MandateManager,
  MemoryLedgerStore,
  generateMandateKeyPair,
  type Ed25519Signer,
} from "@vaduno/guard";
import {
  cosignCheckpointWith,
  LedgerMirror,
  MemoryTreeStore,
  signCheckpointWith,
  signTreeHeadWith,
  TransparencyLog,
} from "@vaduno/transparency";
import { Bitstring, MINIMUM_ENTRIES } from "../src/bitstring.js";
import { publishStatusListWith } from "../src/status-list.js";
import { RevocationRegistry } from "../src/registry.js";

/** Every signing payload must begin with exactly one of these. */
const VADUNO_TAGS = {
  mandate: "vaduno-mandate/v1\n",
  sth: "vaduno-tlog-sth/v1\n",
  statusList: "vaduno-status-list/v1\n",
} as const;
/** C2SP framings — interop formats whose structure IS the domain separation. */
const COSIGNATURE_TAG = "cosignature/v1\n";
const ORIGIN = "vaduno.example/ledger";

class CaptureSigner implements Ed25519Signer {
  readonly algorithm = "Ed25519" as const;
  readonly publicKeyPem: string;
  readonly captured: string[] = [];
  readonly #inner: LocalKeySigner;

  constructor(privateKeyPem: string) {
    this.#inner = new LocalKeySigner(privateKeyPem);
    this.publicKeyPem = this.#inner.publicKeyPem;
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    this.captured.push(Buffer.from(message).toString("utf8"));
    return this.#inner.sign(message);
  }
}

const keys = generateMandateKeyPair();

describe("domain separation at the signer boundary: tagged payloads lead with their tag; the untagged checkpoint path is policed", () => {
  it("mandate issuance signs vaduno-mandate/v1", async () => {
    const signer = new CaptureSigner(keys.privateKeyPem);
    const manager = new MandateManager({ signer });
    await manager.issue({
      issuer: "human@example.com",
      agentId: "agent-1",
      constraints: {
        maxAmountMinor: 1000,
        currency: "USD",
        validFrom: new Date(Date.now() - 1000).toISOString(),
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        maxUses: 1,
      },
    });
    expect(signer.captured).toHaveLength(1);
    expect(signer.captured[0]!.startsWith(VADUNO_TAGS.mandate)).toBe(true);
  });

  it("tree heads sign vaduno-tlog-sth/v1 — directly and via the mirror", async () => {
    const signer = new CaptureSigner(keys.privateKeyPem);
    const tree = new TransparencyLog(new MemoryTreeStore());
    await tree.appendLeaves(["leaf"]);
    await signTreeHeadWith(await tree.head(), { logId: "log-1", signer });

    const ledger = new AuditLedger(new MemoryLedgerStore());
    await ledger.append("policy_updated", { note: "x" });
    const mirror = new LedgerMirror(ledger, new TransparencyLog(new MemoryTreeStore()), {
      signing: { logId: "log-1", signer },
    });
    await mirror.sync();

    expect(signer.captured).toHaveLength(2);
    for (const payload of signer.captured) {
      expect(payload.startsWith(VADUNO_TAGS.sth)).toBe(true);
    }
  });

  it("status lists sign vaduno-status-list/v1 — directly and via the registry", async () => {
    const signer = new CaptureSigner(keys.privateKeyPem);
    const bits = new Bitstring(MINIMUM_ENTRIES);
    await publishStatusListWith(bits, {
      id: "list-1",
      issuer: "issuer-1",
      statusPurpose: "revocation",
      version: 1,
      signer,
    });

    const registry = new RevocationRegistry({ issuer: "issuer-1", listId: "list-1", signer });
    await registry.revokeMandate("mandate-1");
    await registry.publish(1);

    expect(signer.captured).toHaveLength(2);
    for (const payload of signer.captured) {
      expect(payload.startsWith(VADUNO_TAGS.statusList)).toBe(true);
    }
  });

  it("checkpoints sign an UNTAGGED C2SP body led by the operator-chosen origin; cosignatures sign cosignature/v1", async () => {
    const signer = new CaptureSigner(keys.privateKeyPem);
    const tree = new TransparencyLog(new MemoryTreeStore());
    await tree.appendLeaves(["leaf"]);
    const head = await tree.head();
    const cp = { origin: ORIGIN, treeSize: head.treeSize, rootHash: head.rootHash };

    const note = await signCheckpointWith(cp, { name: ORIGIN, signer });
    await cosignCheckpointWith(note, { name: "witness-1", signer, timestamp: 1_754_179_200 });

    expect(signer.captured).toHaveLength(2);
    // Pin the exact signed bytes by INDEPENDENT reconstruction (not by
    // calling checkpointBody, which is the code under test): origin line,
    // decimal size, base64-of-hex root, each newline-terminated. This is the
    // corrected claim — the leading bytes are the OPERATOR-CHOSEN origin,
    // NOT a vaduno-* tag, which is why the steering guarantee is scoped to
    // the tagged payloads and why signCheckpointWith polices the body below.
    expect(signer.captured[0]).toBe(
      `${ORIGIN}\n${head.treeSize}\n${Buffer.from(head.rootHash, "hex").toString("base64")}\n`,
    );
    for (const tag of Object.values(VADUNO_TAGS)) {
      expect(signer.captured[0]!.startsWith(tag)).toBe(false);
    }
    // The cosignature payload leads with the C2SP cosignature domain tag.
    expect(signer.captured[1]!.startsWith(`${COSIGNATURE_TAG}time 1754179200\n`)).toBe(true);
  });

  it("the reviewer probe: a binary origin (Solana message-header shape) never reaches signer.sign()", async () => {
    // Without the printable-ASCII wall, this origin makes the signing payload
    // OPEN with bytes 01 00 01 02 03 — the shape of a Solana message header.
    // The signer path must refuse it BEFORE the signer sees any bytes.
    const signer = new CaptureSigner(keys.privateKeyPem);
    const binaryOrigin = "\x01\x00\x01\x02\x03";
    const rootHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    await expect(
      signCheckpointWith(
        { origin: binaryOrigin, treeSize: 0, rootHash },
        { name: "log", signer },
      ),
    ).rejects.toThrow(/printable ASCII/);
    // Non-ASCII is refused too — only 0x20-0x7E and newlines may reach a
    // signer through the checkpoint path.
    await expect(
      signCheckpointWith(
        { origin: "vaduno.example/lög", treeSize: 0, rootHash },
        { name: "log", signer },
      ),
    ).rejects.toThrow(/printable ASCII/);
    expect(signer.captured).toHaveLength(0);
  });

  it("the tags are mutually exclusive: none is a prefix of another", () => {
    const tags = [...Object.values(VADUNO_TAGS), COSIGNATURE_TAG, `${ORIGIN}\n`];
    for (const a of tags) {
      for (const b of tags) {
        if (a === b) continue;
        expect(a.startsWith(b), `${JSON.stringify(b)} prefixes ${JSON.stringify(a)}`).toBe(false);
      }
    }
  });

  it("a rail-transaction-shaped payload starts with NONE of the tags", () => {
    // What a steered shared-key signer would need Vaduno to sign: raw
    // transaction bytes, or bare canonical JSON of a payment. On the TAGGED
    // paths (mandate, STH, status list, cosignature) neither shape can reach
    // signer.sign(), because those payloads always lead with one of these
    // tags and no rail encoding does. (The untagged checkpoint path is
    // covered above: binary framings are refused outright, and a printable
    // body is always >= 3 newline-terminated lines — not a bare JSON object
    // or raw transaction blob.)
    const railish = [
      canonicalJson({ amountMinor: 500_000, currency: "USD", to: "attacker" }),
      Buffer.from([0x01, 0x00, 0x01, 0x02]).toString("utf8"),
    ];
    const tags = [...Object.values(VADUNO_TAGS), COSIGNATURE_TAG];
    for (const payload of railish) {
      for (const tag of tags) {
        expect(payload.startsWith(tag)).toBe(false);
      }
    }
  });
});
