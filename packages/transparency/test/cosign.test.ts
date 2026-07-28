import { describe, expect, it } from "vitest";
import { createHash, createPublicKey } from "node:crypto";
import {
  MemoryTreeStore,
  TransparencyLog,
  attachCosignatures,
  checkCosignatureQuorum,
  checkpointBody,
  cosignCheckpoint,
  cosignaturePayload,
  generateLogKeyPair,
  keyId,
  parseNote,
  rawEd25519PublicKey,
  signCheckpoint,
  verifyCosignatures,
  verifyNoteSignature,
  witnessCosign,
  CosigningWitness,
  EMPTY_TREE_ROOT_HEX,
  SIG_TYPE_COSIGNATURE_V1,
  SIG_TYPE_ED25519,
  type CosigningWitnessState,
  type KnownWitness,
} from "../src/index.js";

const ORIGIN = "vaduno.example/ledger";
const log = generateLogKeyPair();
const witnessA = generateLogKeyPair();
const witnessB = generateLogKeyPair();
const witnessC = generateLogKeyPair();

const NOW = 1_780_000_000;
const nowSeconds = () => NOW;

/** The log binding every relying party must supply. */
const BINDING = { origin: ORIGIN, logPublicKeyPem: log.publicKeyPem };

function known(name: string, keys: { publicKeyPem: string }): KnownWitness {
  return { name, publicKeyPem: keys.publicKeyPem };
}

describe("C2SP checkpoint note format", () => {
  it("renders the body as origin / size / base64 root, newline-terminated", () => {
    const rootHash = "a".repeat(64);
    const body = checkpointBody({ origin: ORIGIN, treeSize: 42, rootHash });
    const lines = body.split("\n");
    expect(lines[0]).toBe(ORIGIN);
    expect(lines[1]).toBe("42");
    expect(lines[2]).toBe(Buffer.from(rootHash, "hex").toString("base64"));
    expect(body.endsWith("\n")).toBe(true);
    expect(lines[3]).toBe(""); // trailing newline only
  });

  it("computes the key ID as SHA-256(name || 0x0A || sigType || pubkey)[:4]", () => {
    const raw = rawEd25519PublicKey(log.publicKeyPem);
    const expected = createHash("sha256")
      .update(Buffer.from(ORIGIN, "utf8"))
      .update(Buffer.from([0x0a]))
      .update(Buffer.from([SIG_TYPE_ED25519]))
      .update(raw)
      .digest()
      .subarray(0, 4)
      .toString("hex");
    expect(keyId(ORIGIN, SIG_TYPE_ED25519, raw)).toBe(expected);
  });

  it("gives the SAME key a DIFFERENT id per role, so a cosignature cannot pose as a log signature", () => {
    const raw = rawEd25519PublicKey(log.publicKeyPem);
    expect(keyId(ORIGIN, SIG_TYPE_ED25519, raw)).not.toBe(
      keyId(ORIGIN, SIG_TYPE_COSIGNATURE_V1, raw),
    );
  });

  it("extracts the 32 raw Ed25519 public key bytes", () => {
    const raw = rawEd25519PublicKey(log.publicKeyPem);
    expect(raw).toHaveLength(32);
    // Must match what node itself considers the key material.
    const der = createPublicKey(log.publicKeyPem).export({ type: "spki", format: "der" });
    expect(raw.equals(Buffer.from(der.subarray(der.length - 32)))).toBe(true);
  });

  it("round-trips sign -> parse -> verify", () => {
    const rootHash = "b".repeat(64);
    const note = signCheckpoint(
      { origin: ORIGIN, treeSize: 7, rootHash },
      { name: ORIGIN, privateKeyPem: log.privateKeyPem, publicKeyPem: log.publicKeyPem },
    );
    // The note has the em-dash signature line and a blank-line separator.
    expect(note).toContain("\n\n— " + ORIGIN + " ");
    const parsed = parseNote(note);
    expect(parsed.checkpoint).toEqual({ origin: ORIGIN, treeSize: 7, rootHash });
    expect(parsed.signatures).toHaveLength(1);
    expect(verifyNoteSignature(note, { name: ORIGIN, publicKeyPem: log.publicKeyPem })).toBe(true);
  });

  it("rejects a note signed by the wrong key", () => {
    const note = signCheckpoint(
      { origin: ORIGIN, treeSize: 1, rootHash: "c".repeat(64) },
      { name: ORIGIN, privateKeyPem: log.privateKeyPem, publicKeyPem: log.publicKeyPem },
    );
    expect(
      verifyNoteSignature(note, { name: ORIGIN, publicKeyPem: witnessA.publicKeyPem }),
    ).toBe(false);
  });

  it("detects a tampered body (signature covers origin, size, and root)", () => {
    const note = signCheckpoint(
      { origin: ORIGIN, treeSize: 5, rootHash: "d".repeat(64) },
      { name: ORIGIN, privateKeyPem: log.privateKeyPem, publicKeyPem: log.publicKeyPem },
    );
    const tampered = note.replace("\n5\n", "\n6\n");
    expect(verifyNoteSignature(tampered, { name: ORIGIN, publicKeyPem: log.publicKeyPem })).toBe(
      false,
    );
  });

  it("fails closed on malformed notes", () => {
    const root32 = Buffer.from("ab".repeat(32), "hex").toString("base64");
    expect(() => parseNote("")).toThrow(/empty/);
    expect(() => parseNote("only-a-body\n")).toThrow(/blank line/);
    expect(() => parseNote("a\nb\n\n")).toThrow(/at least 3 lines/);
    // Leading zeroes are forbidden by the spec.
    expect(() => parseNote(`${ORIGIN}\n007\n${root32}\n\n`)).toThrow(/leading zeroes/);
    expect(() => parseNote(`${ORIGIN}\n1\nnot base64!\n\n`)).toThrow(/not base64/);
  });

  it("REGRESSION: one byzantine signature line cannot veto the whole note", () => {
    // Per the signed-note spec, unusable signatures are IGNORED. If parseNote
    // threw, any party able to append a garbage line could deny a valid
    // k-of-n quorum to everyone else.
    const note = signCheckpoint(
      { origin: ORIGIN, treeSize: 4, rootHash: "7".repeat(64) },
      { name: ORIGIN, privateKeyPem: log.privateKeyPem, publicKeyPem: log.publicKeyPem },
    );
    const poisoned = note + "garbage-not-a-sig-line\n— w AAAA\n— nospace\n";
    const parsed = parseNote(poisoned);
    expect(parsed.malformedSignatures).toBe(3);
    // The log's real signature still verifies.
    expect(parsed.signatures).toHaveLength(1);
    expect(verifyNoteSignature(parsed, { name: ORIGIN, publicKeyPem: log.publicKeyPem })).toBe(
      true,
    );
  });

  it("bounds an adversarial note: size and signature-line count", () => {
    const note = signCheckpoint(
      { origin: ORIGIN, treeSize: 4, rootHash: "7".repeat(64) },
      { name: ORIGIN, privateKeyPem: log.privateKeyPem, publicKeyPem: log.publicKeyPem },
    );
    // Each signature line would otherwise cost the receiver an Ed25519 verify.
    const flooded = note + "— w AAAAAAAAAA\n".repeat(300);
    expect(() => parseNote(flooded)).toThrow(/signature lines/);
    const huge = note + "— w " + "A".repeat(2 * 1024 * 1024) + "\n";
    expect(() => parseNote(huge)).toThrow(/exceeds/);
  });

  it("REGRESSION: a size-0 checkpoint must carry the empty-tree root", () => {
    const bogus = Buffer.from("11".repeat(32), "hex").toString("base64");
    expect(() => parseNote(`${ORIGIN}\n0\n${bogus}\n\n`)).toThrow(/empty-tree root/);
    const real = Buffer.from(EMPTY_TREE_ROOT_HEX, "hex").toString("base64");
    expect(parseNote(`${ORIGIN}\n0\n${real}\n\n`).checkpoint.treeSize).toBe(0);
  });

  it("REGRESSION: a root hash that is not 32 bytes is rejected", () => {
    // RFC 6962 roots are always SHA-256. A short/long "root" must never be
    // accepted as a tree head, in either direction.
    expect(() =>
      checkpointBody({ origin: ORIGIN, treeSize: 1, rootHash: "ab".repeat(16) }),
    ).toThrow(/64 lowercase hex/);
    expect(() =>
      checkpointBody({ origin: ORIGIN, treeSize: 1, rootHash: "ab".repeat(48) }),
    ).toThrow(/64 lowercase hex/);
    // And on the parse side, where the bytes arrive from an untrusted peer.
    const short = Buffer.alloc(16).toString("base64");
    expect(() => parseNote(`${ORIGIN}\n1\n${short}\n\n`)).toThrow(/32 bytes/);
    const long = Buffer.alloc(48).toString("base64");
    expect(() => parseNote(`${ORIGIN}\n1\n${long}\n\n`)).toThrow(/32 bytes/);
  });
});

describe("tlog-cosignature v1", () => {
  function freshNote(treeSize = 3, rootHash = "e".repeat(64)) {
    return signCheckpoint(
      { origin: ORIGIN, treeSize, rootHash },
      { name: ORIGIN, privateKeyPem: log.privateKeyPem, publicKeyPem: log.publicKeyPem },
    );
  }

  it("signs the spec's exact payload: header, time line, then the body", () => {
    const body = checkpointBody({ origin: ORIGIN, treeSize: 3, rootHash: "e".repeat(64) });
    const payload = cosignaturePayload(body, 1679315147).toString("utf8");
    expect(payload).toBe(`cosignature/v1\ntime 1679315147\n${body}`);
  });

  it("a verified cosignature round-trips through attach -> verify", () => {
    const note = freshNote();
    const record = cosignCheckpoint(note, {
      name: "witness.example/a",
      privateKeyPem: witnessA.privateKeyPem,
      publicKeyPem: witnessA.publicKeyPem,
      timestamp: NOW,
    });
    const witnessed = attachCosignatures(note, [record]);
    const verified = verifyCosignatures(
      witnessed,
      [known("witness.example/a", witnessA)],
      { nowSeconds },
    );
    expect(verified).toEqual([{ name: "witness.example/a", timestamp: NOW }]);
    // The log's own signature still verifies alongside the cosignature.
    expect(
      verifyNoteSignature(witnessed, { name: ORIGIN, publicKeyPem: log.publicKeyPem }),
    ).toBe(true);
  });

  it("a cosignature does NOT verify against a different checkpoint body", () => {
    const noteA = freshNote(3, "e".repeat(64));
    const noteB = freshNote(3, "f".repeat(64));
    const record = cosignCheckpoint(noteA, {
      name: "witness.example/a",
      privateKeyPem: witnessA.privateKeyPem,
      publicKeyPem: witnessA.publicKeyPem,
      timestamp: NOW,
    });
    // Splice witness A's line onto a DIFFERENT checkpoint.
    const forged = noteB + record.line;
    expect(
      verifyCosignatures(forged, [known("witness.example/a", witnessA)], { nowSeconds }),
    ).toEqual([]);
  });

  it("WIRE FORMAT: the timestamp is carried IN the signature blob (keyID||ts||sig)", () => {
    // Getting this wrong breaks interop with real Go/Sigsum witnesses in both
    // directions, while every local test still passes — so assert the layout.
    const note = freshNote();
    const record = cosignCheckpoint(note, {
      name: "witness.example/a",
      privateKeyPem: witnessA.privateKeyPem,
      publicKeyPem: witnessA.publicKeyPem,
      timestamp: NOW,
    });
    const parsed = parseNote(attachCosignatures(note, [record]));
    const cosig = parsed.signatures.find((s) => s.name === "witness.example/a")!;
    // 8-byte big-endian timestamp, then the 64-byte Ed25519 signature.
    expect(cosig.signature).toHaveLength(8 + 64);
    expect(Number(cosig.signature.readBigUInt64BE(0))).toBe(NOW);
    // No side-channel needed: the note alone is verifiable.
    expect(
      verifyCosignatures(attachCosignatures(note, [record]), [
        known("witness.example/a", witnessA),
      ], { nowSeconds }),
    ).toEqual([{ name: "witness.example/a", timestamp: NOW }]);
  });

  it("a tampered timestamp in the blob does not verify", () => {
    const note = freshNote();
    const record = cosignCheckpoint(note, {
      name: "witness.example/a",
      privateKeyPem: witnessA.privateKeyPem,
      publicKeyPem: witnessA.publicKeyPem,
      timestamp: NOW,
    });
    // Rewrite the embedded timestamp; the signature covers it, so it must fail.
    const line = record.line.trim();
    const b64 = line.slice(line.lastIndexOf(" ") + 1);
    const blob = Buffer.from(b64, "base64");
    blob.writeBigUInt64BE(BigInt(NOW - 60), 4); // after the 4-byte key ID
    const tampered = `— witness.example/a ${blob.toString("base64")}\n`;
    expect(
      verifyCosignatures(note + tampered, [known("witness.example/a", witnessA)], {
        nowSeconds,
      }),
    ).toEqual([]);
  });

  it("rejects stale and implausibly future-dated cosignatures", () => {
    const note = freshNote();
    const stale = cosignCheckpoint(note, {
      name: "witness.example/a",
      privateKeyPem: witnessA.privateKeyPem,
      publicKeyPem: witnessA.publicKeyPem,
      timestamp: NOW - 90_000, // > 24h old
    });
    const future = cosignCheckpoint(note, {
      name: "witness.example/b",
      privateKeyPem: witnessB.privateKeyPem,
      publicKeyPem: witnessB.publicKeyPem,
      timestamp: NOW + 10_000, // way beyond skew
    });
    const witnessed = attachCosignatures(note, [stale, future]);
    const verified = verifyCosignatures(
      witnessed,
      [known("witness.example/a", witnessA), known("witness.example/b", witnessB)],
      { nowSeconds },
    );
    expect(verified).toEqual([]);
    // Widening maxAge admits the stale one — the bound is the policy, not the crypto.
    const relaxed = verifyCosignatures(
      witnessed,
      [known("witness.example/a", witnessA)],
      { nowSeconds, maxAgeSeconds: 100_000 },
    );
    expect(relaxed.map((v) => v.name)).toEqual(["witness.example/a"]);
  });

  it("ignores a cosignature whose name matches but key does not", () => {
    const note = freshNote();
    const record = cosignCheckpoint(note, {
      name: "witness.example/a",
      privateKeyPem: witnessB.privateKeyPem, // WRONG key for this name
      publicKeyPem: witnessB.publicKeyPem,
      timestamp: NOW,
    });
    const witnessed = attachCosignatures(note, [record]);
    expect(
      verifyCosignatures(witnessed, [known("witness.example/a", witnessA)], { nowSeconds }),
    ).toEqual([]);
  });
});

describe("quorum policy", () => {
  const witnesses = [
    known("witness.example/a", witnessA),
    known("witness.example/b", witnessB),
    known("witness.example/c", witnessC),
  ];

  function cosignedBy(keys: Array<{ name: string; kp: typeof witnessA }>) {
    const note = signCheckpoint(
      { origin: ORIGIN, treeSize: 9, rootHash: "1".repeat(64) },
      { name: ORIGIN, privateKeyPem: log.privateKeyPem, publicKeyPem: log.publicKeyPem },
    );
    return attachCosignatures(
      note,
      keys.map(({ name, kp }) =>
        cosignCheckpoint(note, {
          name,
          privateKeyPem: kp.privateKeyPem,
          publicKeyPem: kp.publicKeyPem,
          timestamp: NOW,
        }),
      ),
    );
  }

  it("reaches quorum with k distinct witnesses", () => {
    const witnessed = cosignedBy([
      { name: "witness.example/a", kp: witnessA },
      { name: "witness.example/b", kp: witnessB },
    ]);
    const r = checkCosignatureQuorum(witnessed, witnesses, 2, BINDING, { nowSeconds });
    expect(r.ok).toBe(true);
    expect(r.verified.map((v) => v.name).sort()).toEqual([
      "witness.example/a",
      "witness.example/b",
    ]);
    expect(r.missing).toEqual(["witness.example/c"]);
  });

  it("fails closed below quorum and names who is missing", () => {
    const witnessed = cosignedBy([{ name: "witness.example/a", kp: witnessA }]);
    const r = checkCosignatureQuorum(witnessed, witnesses, 2, BINDING, { nowSeconds });
    expect(r.ok).toBe(false);
    expect(r.message).toMatch(/only 1 of 2/);
    expect(r.missing.sort()).toEqual(["witness.example/b", "witness.example/c"]);
  });

  it("a duplicate witness cannot fill a quorum by itself", () => {
    const witnessed = cosignedBy([{ name: "witness.example/a", kp: witnessA }]);
    // Same witness listed twice must still count once.
    const dupes = [known("witness.example/a", witnessA), known("witness.example/a", witnessA)];
    const r = checkCosignatureQuorum(witnessed, dupes, 2, BINDING, { nowSeconds });
    expect(r.ok).toBe(false);
    expect(r.message).toMatch(/unreachable: only 1 independent witness key/);
  });

  it("REGRESSION: ONE key under TWO names cannot fill a 2-of-2 quorum", () => {
    // Key IDs are name-derived, so a single party holding one private key can
    // mint valid cosignature lines under any number of names. Counting NAMES
    // would let it fake independence; quorum counts distinct KEYS.
    const note = signCheckpoint(
      { origin: ORIGIN, treeSize: 9, rootHash: "1".repeat(64) },
      { name: ORIGIN, privateKeyPem: log.privateKeyPem, publicKeyPem: log.publicKeyPem },
    );
    const witnessed = attachCosignatures(note, [
      cosignCheckpoint(note, {
        name: "witness.one",
        privateKeyPem: witnessA.privateKeyPem,
        publicKeyPem: witnessA.publicKeyPem,
        timestamp: NOW,
      }),
      cosignCheckpoint(note, {
        name: "witness.two",
        privateKeyPem: witnessA.privateKeyPem, // SAME key, different name
        publicKeyPem: witnessA.publicKeyPem,
        timestamp: NOW,
      }),
    ]);
    const r = checkCosignatureQuorum(
      witnessed,
      [known("witness.one", witnessA), known("witness.two", witnessA)],
      2,
      BINDING,
      { nowSeconds },
    );
    expect(r.ok).toBe(false);
    expect(r.duplicateKeys).toEqual(["witness.one", "witness.two"]);
    expect(r.message).toMatch(/unreachable: only 1 independent witness key/);

    // A 1-of-n threshold is still satisfiable by that single party.
    const one = checkCosignatureQuorum(
      witnessed,
      [known("witness.one", witnessA), known("witness.two", witnessA)],
      1,
      BINDING,
      { nowSeconds },
    );
    expect(one.ok).toBe(true);
    expect(one.duplicateKeys).toHaveLength(2);
  });

  it("counts distinct KEYS even when both cosignatures verify", () => {
    // Both lines are cryptographically valid; independence is what fails.
    const witnessed = cosignedBy([
      { name: "witness.example/a", kp: witnessA },
      { name: "witness.example/b", kp: witnessB },
    ]);
    const r = checkCosignatureQuorum(
      witnessed,
      [known("witness.example/a", witnessA), known("witness.example/b", witnessB)],
      2,
      BINDING,
      { nowSeconds },
    );
    expect(r.ok).toBe(true); // genuinely two parties
    expect(r.duplicateKeys).toEqual([]);
  });

  it("an unreachable quorum is reported, not silently passed", () => {
    const witnessed = cosignedBy([{ name: "witness.example/a", kp: witnessA }]);
    const r = checkCosignatureQuorum(witnessed, [known("witness.example/a", witnessA)], 3, BINDING, {
      nowSeconds,
    });
    expect(r.ok).toBe(false);
    expect(r.message).toMatch(/unreachable/);
  });

  it("rejects a nonsense threshold", () => {
    const witnessed = cosignedBy([]);
    expect(checkCosignatureQuorum(witnessed, witnesses, 0, BINDING, { nowSeconds }).ok).toBe(false);
    expect(checkCosignatureQuorum(witnessed, witnesses, -1, BINDING, { nowSeconds }).ok).toBe(false);
  });

  it("REGRESSION: a quorum on ANOTHER log's checkpoint is rejected when origin is pinned", () => {
    // Cosignatures are bound to the body, but nothing stops someone handing a
    // relying party a DIFFERENT log's checkpoint that genuinely has k
    // cosignatures. Pinning origin (and the log key) is what binds it to
    // "the log I actually follow".
    const foreign = signCheckpoint(
      { origin: "someone.else/log", treeSize: 9, rootHash: "1".repeat(64) },
      { name: "someone.else/log", privateKeyPem: log.privateKeyPem, publicKeyPem: log.publicKeyPem },
    );
    const witnessed = attachCosignatures(foreign, [
      cosignCheckpoint(foreign, {
        name: "witness.example/a",
        privateKeyPem: witnessA.privateKeyPem,
        publicKeyPem: witnessA.publicKeyPem,
        timestamp: NOW,
      }),
      cosignCheckpoint(foreign, {
        name: "witness.example/b",
        privateKeyPem: witnessB.privateKeyPem,
        publicKeyPem: witnessB.publicKeyPem,
        timestamp: NOW,
      }),
    ]);
    // The cosignatures are genuine — real witnesses really did cosign that
    // note at TOFU for the other origin, with no misbehaviour at all. Binding
    // is what stops it counting as a quorum on OUR log. It is a required
    // argument, so this fails closed by construction, not by remembering to
    // opt in.
    const r = checkCosignatureQuorum(witnessed, witnesses, 2, BINDING, { nowSeconds });
    expect(r.ok).toBe(false);
    expect(r.message).toMatch(/origin "someone.else\/log" != expected/);
    expect(r.checkpoint).toBeUndefined();
  });

  it("pinning the log key rejects a checkpoint the log never signed", () => {
    const impostor = signCheckpoint(
      { origin: ORIGIN, treeSize: 9, rootHash: "1".repeat(64) },
      { name: ORIGIN, privateKeyPem: witnessC.privateKeyPem, publicKeyPem: witnessC.publicKeyPem },
    );
    const witnessed = attachCosignatures(impostor, [
      cosignCheckpoint(impostor, {
        name: "witness.example/a",
        privateKeyPem: witnessA.privateKeyPem,
        publicKeyPem: witnessA.publicKeyPem,
        timestamp: NOW,
      }),
      cosignCheckpoint(impostor, {
        name: "witness.example/b",
        privateKeyPem: witnessB.privateKeyPem,
        publicKeyPem: witnessB.publicKeyPem,
        timestamp: NOW,
      }),
    ]);
    const r = checkCosignatureQuorum(witnessed, witnesses, 2, BINDING, { nowSeconds });
    expect(r.ok).toBe(false);
    expect(r.message).toMatch(/not signed by the expected log key/);
  });

  it("REGRESSION: a note with the LOG SIGNATURE STRIPPED never reaches quorum", () => {
    // Cosignatures alone are not a log statement. Without the log's own
    // signature the equivocation would also be unattributable afterwards.
    const note = signCheckpoint(
      { origin: ORIGIN, treeSize: 9, rootHash: "1".repeat(64) },
      { name: ORIGIN, privateKeyPem: log.privateKeyPem, publicKeyPem: log.publicKeyPem },
    );
    const body = note.slice(0, note.indexOf("\n\n") + 1);
    const cosigs = [
      cosignCheckpoint(note, {
        name: "witness.example/a",
        privateKeyPem: witnessA.privateKeyPem,
        publicKeyPem: witnessA.publicKeyPem,
        timestamp: NOW,
      }),
      cosignCheckpoint(note, {
        name: "witness.example/b",
        privateKeyPem: witnessB.privateKeyPem,
        publicKeyPem: witnessB.publicKeyPem,
        timestamp: NOW,
      }),
    ];
    const stripped = body + "\n" + cosigs.map((c) => c.line).join("");
    expect(parseNote(stripped).signatures).toHaveLength(2); // both cosignatures
    const r = checkCosignatureQuorum(stripped, witnesses, 2, BINDING, { nowSeconds });
    expect(r.ok).toBe(false);
    expect(r.message).toMatch(/not signed by the expected log key/);
  });

  it("returns the verified checkpoint so callers consume what was checked", () => {
    const witnessed = cosignedBy([
      { name: "witness.example/a", kp: witnessA },
      { name: "witness.example/b", kp: witnessB },
    ]);
    const r = checkCosignatureQuorum(witnessed, witnesses, 2, BINDING, { nowSeconds });
    expect(r.ok).toBe(true);
    expect(r.checkpoint).toEqual({ origin: ORIGIN, treeSize: 9, rootHash: "1".repeat(64) });
  });

  it("an unparseable note never reaches quorum", () => {
    const r = checkCosignatureQuorum("garbage", witnesses, 1, BINDING, { nowSeconds });
    expect(r.ok).toBe(false);
  });

  it("a broken clock fails closed rather than disabling freshness checks", () => {
    const witnessed = cosignedBy([
      { name: "witness.example/a", kp: witnessA },
      { name: "witness.example/b", kp: witnessB },
    ]);
    const r = checkCosignatureQuorum(witnessed, witnesses, 2, BINDING, {
      nowSeconds: () => NaN,
    });
    expect(r.ok).toBe(false);
  });
});

describe("witnessCosign — the refusal is the security property", () => {
  async function logNote(entries: string[]) {
    const tlog = new TransparencyLog(new MemoryTreeStore());
    for (const e of entries) await tlog.appendLeaf(e);
    const head = await tlog.head();
    const note = signCheckpoint(
      { origin: ORIGIN, treeSize: head.treeSize, rootHash: head.rootHash },
      { name: ORIGIN, privateKeyPem: log.privateKeyPem, publicKeyPem: log.publicKeyPem },
    );
    return { tlog, head, note };
  }

  function freshState(): CosigningWitnessState {
    return {
      origin: ORIGIN,
      logPublicKeyPem: log.publicKeyPem,
      logKeyName: ORIGIN,
      lastCosigned: null,
    };
  }

  const witnessOpts = {
    name: "witness.example/a",
    privateKeyPem: witnessA.privateKeyPem,
    publicKeyPem: witnessA.publicKeyPem,
    timestamp: NOW,
  };

  it("cosigns a first checkpoint, then honest growth with a consistency proof", async () => {
    const first = await logNote(["a", "b", "c"]);
    const r1 = witnessCosign(freshState(), first.note, witnessOpts);
    expect(r1.ok).toBe(true);
    if (!r1.ok) return;
    expect(r1.state.lastCosigned).toMatchObject({ treeSize: 3, rootHash: first.head.rootHash });

    // Log grows honestly.
    await first.tlog.appendLeaf("d");
    await first.tlog.appendLeaf("e");
    const grown = await first.tlog.head();
    const note2 = signCheckpoint(
      { origin: ORIGIN, treeSize: grown.treeSize, rootHash: grown.rootHash },
      { name: ORIGIN, privateKeyPem: log.privateKeyPem, publicKeyPem: log.publicKeyPem },
    );
    // Without a proof the witness refuses.
    expect(witnessCosign(r1.state, note2, witnessOpts)).toMatchObject({
      ok: false,
      code: "CONSISTENCY_PROOF_MISSING",
    });
    // With one, it cosigns.
    const proof = await first.tlog.proveConsistency(3, 5);
    const r2 = witnessCosign(r1.state, note2, { ...witnessOpts, proof });
    expect(r2.ok).toBe(true);
  });

  it("REFUSES to cosign an equivocating log (same size, different root)", async () => {
    const real = await logNote(["a", "b", "c"]);
    const r1 = witnessCosign(freshState(), real.note, witnessOpts);
    expect(r1.ok).toBe(true);
    if (!r1.ok) return;

    // The operator signs a DIFFERENT history at the same size — a perfectly
    // valid signature over a fork. This is the attack cosigning exists to stop.
    const fork = await logNote(["a", "b", "EVIL"]);
    expect(fork.head.rootHash).not.toBe(real.head.rootHash);
    const verdict = witnessCosign(r1.state, fork.note, witnessOpts);
    expect(verdict.ok).toBe(false);
    if (verdict.ok) return;
    expect(verdict.code).toBe("ROOT_CHANGED_WITHOUT_GROWTH");
  });

  it("REFUSES a rewritten history that cannot prove consistency", async () => {
    const real = await logNote(["a", "b", "c"]);
    const r1 = witnessCosign(freshState(), real.note, witnessOpts);
    if (!r1.ok) return;

    // A larger tree built on a different prefix: growth, but not append-only.
    const rewritten = await logNote(["x", "y", "z", "w"]);
    const bogusProof = await rewritten.tlog.proveConsistency(3, 4);
    const verdict = witnessCosign(r1.state, rewritten.note, {
      ...witnessOpts,
      proof: bogusProof,
    });
    expect(verdict.ok).toBe(false);
    if (verdict.ok) return;
    expect(verdict.code).toBe("CONSISTENCY_PROOF_INVALID");
  });

  it("REFUSES a shrunken tree", async () => {
    const big = await logNote(["a", "b", "c", "d"]);
    const r1 = witnessCosign(freshState(), big.note, witnessOpts);
    if (!r1.ok) return;
    const small = await logNote(["a", "b"]);
    expect(witnessCosign(r1.state, small.note, witnessOpts)).toMatchObject({
      ok: false,
      code: "TREE_SHRANK",
    });
  });

  it("REFUSES a checkpoint for another log, or one the log did not sign", async () => {
    const other = signCheckpoint(
      { origin: "someone.else/log", treeSize: 1, rootHash: "9".repeat(64) },
      { name: "someone.else/log", privateKeyPem: log.privateKeyPem, publicKeyPem: log.publicKeyPem },
    );
    expect(witnessCosign(freshState(), other, witnessOpts)).toMatchObject({
      ok: false,
      code: "WRONG_ORIGIN",
    });

    // Right origin, but signed by an impostor key.
    const impostor = signCheckpoint(
      { origin: ORIGIN, treeSize: 1, rootHash: "9".repeat(64) },
      {
        name: ORIGIN,
        privateKeyPem: witnessB.privateKeyPem,
        publicKeyPem: witnessB.publicKeyPem,
      },
    );
    expect(witnessCosign(freshState(), impostor, witnessOpts)).toMatchObject({
      ok: false,
      code: "LOG_SIGNATURE_INVALID",
    });
  });

  it("does not advance witness state on refusal", async () => {
    const real = await logNote(["a", "b", "c"]);
    const r1 = witnessCosign(freshState(), real.note, witnessOpts);
    if (!r1.ok) return;
    const fork = await logNote(["a", "b", "EVIL"]);
    witnessCosign(r1.state, fork.note, witnessOpts);
    // The witness still holds the ORIGINAL history, so the fork cannot become
    // its new baseline by simply being presented twice.
    expect(r1.state.lastCosigned).toMatchObject({ treeSize: 3, rootHash: real.head.rootHash });
    const again = witnessCosign(r1.state, fork.note, witnessOpts);
    expect(again.ok).toBe(false);
  });

  it("REGRESSION: a witness cannot cosign two forks under CONCURRENT requests", async () => {
    // witnessCosign is pure — it returns new state and trusts the caller to
    // store it. Two concurrent requests both read the OLD state, both pass the
    // consistency check, and the witness ends up having cosigned two
    // conflicting checkpoints: exactly what it exists to prevent.
    // CosigningWitness serializes and commits before releasing the next.
    const real = await logNote(["a", "b", "c"]);
    const fork = await logNote(["a", "b", "EVIL"]);
    const witness = new CosigningWitness(freshState(), {
      name: "witness.example/a",
      privateKeyPem: witnessA.privateKeyPem,
      publicKeyPem: witnessA.publicKeyPem,
    });

    const [r1, r2] = await Promise.all([
      witness.cosign(real.note, { timestamp: NOW }),
      witness.cosign(fork.note, { timestamp: NOW }),
    ]);
    // Exactly one is cosigned; the other is refused as equivocation.
    const okCount = [r1, r2].filter((r) => r.ok).length;
    expect(okCount).toBe(1);
    const refused = [r1, r2].find((r) => !r.ok)!;
    if (refused.ok) throw new Error("unreachable");
    expect(refused.code).toBe("ROOT_CHANGED_WITHOUT_GROWTH");
  });

  it("REGRESSION: equivocation hidden in EXTENSION lines is refused", async () => {
    // Witness memory used to be only (treeSize, rootHash), so a log could
    // present two different bodies for the same tree state and get both
    // cosigned. The witness now commits to the whole body.
    const head = { treeSize: 3, rootHash: "5".repeat(64) };
    const noteA = signCheckpoint(
      { origin: ORIGIN, ...head, extensions: ["note alpha"] },
      { name: ORIGIN, privateKeyPem: log.privateKeyPem, publicKeyPem: log.publicKeyPem },
    );
    const noteB = signCheckpoint(
      { origin: ORIGIN, ...head, extensions: ["note BETA"] },
      { name: ORIGIN, privateKeyPem: log.privateKeyPem, publicKeyPem: log.publicKeyPem },
    );
    const r1 = witnessCosign(freshState(), noteA, witnessOpts);
    expect(r1.ok).toBe(true);
    if (!r1.ok) return;
    const r2 = witnessCosign(r1.state, noteB, witnessOpts);
    expect(r2.ok).toBe(false);
    if (r2.ok) return;
    expect(r2.code).toBe("BODY_CHANGED_WITHOUT_GROWTH");
    // Re-presenting the IDENTICAL body is still fine (freshness refresh).
    expect(witnessCosign(r1.state, noteA, witnessOpts).ok).toBe(true);
  });

  it("END TO END: an equivocating operator cannot reach a 2-of-3 quorum", async () => {
    const real = await logNote(["a", "b", "c"]);
    const fork = await logNote(["a", "b", "EVIL"]);

    // Three independent witnesses all see the REAL log first.
    const states = [freshState(), freshState(), freshState()];
    const kps = [witnessA, witnessB, witnessC];
    const names = ["witness.example/a", "witness.example/b", "witness.example/c"];
    const advanced = states.map((s, i) => {
      const r = witnessCosign(s, real.note, {
        name: names[i]!,
        privateKeyPem: kps[i]!.privateKeyPem,
        publicKeyPem: kps[i]!.publicKeyPem,
        timestamp: NOW,
      });
      expect(r.ok).toBe(true);
      return r.ok ? r.state : s;
    });

    // The operator now tries to get the FORK cosigned by everyone.
    const forkCosignatures = advanced
      .map((s, i) =>
        witnessCosign(s, fork.note, {
          name: names[i]!,
          privateKeyPem: kps[i]!.privateKeyPem,
          publicKeyPem: kps[i]!.publicKeyPem,
          timestamp: NOW,
        }),
      )
      .filter((r) => r.ok);
    // Every honest witness refuses — the fork gets zero cosignatures.
    expect(forkCosignatures).toHaveLength(0);

    const quorum = checkCosignatureQuorum(
      fork.note,
      names.map((n, i) => known(n, kps[i]!)),
      2,
      BINDING,
      { nowSeconds },
    );
    expect(quorum.ok).toBe(false);
    expect(quorum.message).toMatch(/only 0 of 2/);
  });
});
