/**
 * Dependency freeze: ZERO new runtime dependencies in any published package.
 *
 * The signer work is exactly the kind of change that tempts one in
 * (@google-cloud/kms, a PKCS#11 binding) — those live in DOCS ONLY. This test
 * pins the full production-dependency surface of every publishable package,
 * so adding one fails a test before it fails the release gate. Discovered,
 * never hardcoded to a package list: a new package with a new dependency
 * fails here too.
 */
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const packagesDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** The complete, intended production-dependency surface. Internal-only. */
const FROZEN_DEPENDENCIES: Record<string, string[]> = {
  "@vaduno/agent": ["@vaduno/guard"],
  "@vaduno/cloudflare": ["@vaduno/guard"],
  "@vaduno/guard": [],
  "@vaduno/postgres": ["@vaduno/guard", "@vaduno/revocation"],
  "@vaduno/revocation": ["@vaduno/guard"],
  "@vaduno/stripe": ["@vaduno/guard"],
  "@vaduno/transparency": ["@vaduno/guard"],
  "@vaduno/x402": ["@vaduno/guard"],
};

/** Peers a consumer may be asked to install. Also frozen. */
const FROZEN_PEERS: Record<string, string[]> = {
  "@vaduno/postgres": ["pg"],
  "@vaduno/stripe": ["stripe"],
  // viem is a PEER, not a dependency, on purpose: the guarded signer must
  // hash with the consumer's own viem (hashTypedData/getTypesForEIP712Domain
  // are the commitment gate's oracle), so a second smuggled copy — and any
  // version skew between what they sign with and what we hash with — must be
  // impossible. Every Agents-SDK x402 consumer already has viem installed.
  "@vaduno/cloudflare": ["viem"],
};

interface Pkg {
  name: string;
  private?: boolean;
  dependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  bundledDependencies?: unknown;
}

const publishable: Pkg[] = readdirSync(packagesDir, { withFileTypes: true })
  .filter((e) => e.isDirectory() && existsSync(join(packagesDir, e.name, "package.json")))
  .map((e) => JSON.parse(readFileSync(join(packagesDir, e.name, "package.json"), "utf8")) as Pkg)
  .filter((p) => p.private !== true);

describe("zero new production dependencies in every published package", () => {
  it("covers every publishable package (a new package must be frozen here)", () => {
    expect(publishable.map((p) => p.name).sort()).toEqual(
      Object.keys(FROZEN_DEPENDENCIES).sort(),
    );
  });

  for (const pkg of publishable) {
    it(`${pkg.name} dependencies are exactly the frozen set`, () => {
      expect(Object.keys(pkg.dependencies ?? {}).sort()).toEqual(
        (FROZEN_DEPENDENCIES[pkg.name] ?? []).sort(),
      );
      expect(Object.keys(pkg.peerDependencies ?? {}).sort()).toEqual(
        (FROZEN_PEERS[pkg.name] ?? []).sort(),
      );
      expect(Object.keys(pkg.optionalDependencies ?? {})).toEqual([]);
      expect(pkg.bundledDependencies).toBeUndefined();
    });

    it(`${pkg.name} ships no runtime dependency outside @vaduno/*`, () => {
      // The stronger statement of the rule, independent of the frozen map.
      for (const dep of Object.keys(pkg.dependencies ?? {})) {
        expect(dep.startsWith("@vaduno/"), `${pkg.name} depends on ${dep}`).toBe(true);
      }
    });
  }
});
