/**
 * Pre-publish gate. Run `npm run release:check` before ever typing
 * `npm publish` — it catches the mistakes that are painful precisely because
 * npm publishes are effectively permanent (you may unpublish within 72h, but
 * the exact name+version can never be reused).
 *
 * Checks, per publishable package:
 *   - publishConfig.access === "public"   (scoped packages are RESTRICTED by
 *     default; without this, publishing fails or — worse — silently goes private)
 *   - README.md and LICENSE present       (npm auto-includes them, but only if
 *     they exist in the package directory; the repo root's copies do NOT ship)
 *   - dist/ exists and is newer than src/ (never ship a stale build)
 *   - the tarball contains no source, tests, secrets, or junk
 *   - internal @vaduno/* deps use a real semver range, not "*" or "workspace:"
 *   - version matches across the workspace (they release as a set)
 */
import { execFileSync } from "node:child_process";
import { readFileSync, existsSync, statSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGES = ["guard", "transparency", "revocation", "x402", "stripe"];
/** Anything matching these must never appear in a published tarball. */
const FORBIDDEN = [
  /(^|\/)src\//,
  /(^|\/)test\//,
  /\.test\./,
  /\.env/,
  /\.pem$/,
  /(^|\/)node_modules\//,
  /\.tsbuildinfo$/,
  /(^|\/)\.git/,
];

let failures = 0;
let warnings = 0;
const fail = (pkg, msg) => {
  console.error(`  ✗ ${pkg}: ${msg}`);
  failures++;
};
const warn = (pkg, msg) => {
  console.warn(`  ! ${pkg}: ${msg}`);
  warnings++;
};

function newestMtime(dir) {
  let newest = 0;
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else newest = Math.max(newest, statSync(p).mtimeMs);
    }
  };
  if (existsSync(dir)) walk(dir);
  return newest;
}

const versions = new Set();

for (const name of PACKAGES) {
  const dir = join(root, "packages", name);
  const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  console.log(`\n${pkg.name}@${pkg.version}`);
  versions.add(pkg.version);

  if (pkg.private) fail(pkg.name, 'marked "private" but is in the publish list');
  if (pkg.publishConfig?.access !== "public") {
    fail(pkg.name, 'missing publishConfig.access="public" — a scoped package defaults to RESTRICTED');
  }
  if (!pkg.scripts?.prepublishOnly) {
    warn(pkg.name, "no prepublishOnly guard (build+test before publish)");
  }
  for (const f of ["README.md", "LICENSE"]) {
    if (!existsSync(join(dir, f))) {
      fail(pkg.name, `${f} missing — npm only ships the copy in THIS directory`);
    }
  }
  if (!existsSync(join(dir, "dist"))) {
    fail(pkg.name, "dist/ missing — run npm run build");
  } else if (newestMtime(join(dir, "src")) > newestMtime(join(dir, "dist"))) {
    fail(pkg.name, "src/ is newer than dist/ — the build is STALE, rebuild before publishing");
  }
  for (const [dep, range] of Object.entries(pkg.dependencies ?? {})) {
    if (!dep.startsWith("@vaduno/")) continue;
    if (range === "*" || range.startsWith("workspace:")) {
      fail(pkg.name, `dependency ${dep}="${range}" will not resolve for consumers`);
    }
  }

  // What would actually ship?
  const out = execFileSync("npm", ["pack", "--dry-run", "--json"], {
    cwd: dir,
    encoding: "utf8",
    shell: process.platform === "win32",
  });
  const [meta] = JSON.parse(out);
  const files = meta.files.map((f) => f.path);
  for (const f of files) {
    if (FORBIDDEN.some((re) => re.test(f))) fail(pkg.name, `tarball contains ${f}`);
  }
  const has = (p) => files.some((f) => f === p);
  if (!has("README.md")) fail(pkg.name, "tarball has no README.md (this is the npm landing page)");
  if (!has("LICENSE")) fail(pkg.name, "tarball has no LICENSE");
  if (!files.some((f) => f.endsWith(".d.ts"))) fail(pkg.name, "tarball has no type declarations");
  console.log(`  ${files.length} files, ${(meta.unpackedSize / 1024).toFixed(1)} kB unpacked`);
}

if (versions.size > 1) {
  console.error(`\n✗ versions differ across packages: ${[...versions].join(", ")}`);
  failures++;
}

console.log("\n" + "─".repeat(60));
if (failures > 0) {
  console.error(`✗ ${failures} problem(s) — DO NOT PUBLISH`);
  process.exit(1);
}
console.log(`✓ all packages look publishable${warnings ? ` (${warnings} warning(s))` : ""}`);
console.log(`
Publish order matters — the others depend on @vaduno/guard:
  1. @vaduno/guard
  2. @vaduno/transparency, @vaduno/revocation, @vaduno/x402, @vaduno/stripe

Reminder: publishes are effectively permanent. Use --dry-run first, and
consider --tag next for a pre-release you can retract from "latest".
`);
