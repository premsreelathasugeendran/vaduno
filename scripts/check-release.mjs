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
/**
 * Discovered, never hardcoded. A literal list silently skips any package added
 * after it was written — the gate reports "all packages look publishable"
 * while never having looked at the new one. That is the same failure as
 * checking a README exists without reading it, and it is how @vaduno/postgres
 * would have shipped ungated.
 */
const PACKAGES = readdirSync(join(root, "packages"), { withFileTypes: true })
  .filter((e) => e.isDirectory() && existsSync(join(root, "packages", e.name, "package.json")))
  .map((e) => e.name)
  .filter((name) => {
    const pkg = JSON.parse(
      readFileSync(join(root, "packages", name, "package.json"), "utf8"),
    );
    return pkg.private !== true;
  })
  .sort();
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

/**
 * Claims that must never ship unqualified in a package README.
 *
 * Each of these is a TRUE statement that becomes FALSE when its qualifier is
 * dropped, which is this project's demonstrated failure mode — it has happened
 * five times. The rule is not "avoid these words"; it is "if you make this
 * claim, make it precisely, because someone will check it against the code."
 */
const README_CLAIM_TRAPS = [
  {
    // packages/guard/src/mandate/mandate.ts holds an Ed25519 private key when
    // it ISSUES. The honest claim is "no keys TO FUNDS": no custody, no PANs,
    // no wallet or bank credentials.
    // "keys TO funds" and "keys FOR funds" are equally precise; both qualify.
    re: /never holds[^.\n]*\bkeys\b(?![^.\n]*\b(to|for) funds\b)[^.\n]*/i,
    why: 'unqualified "never holds keys" — a mandate-issuing key IS held; say "keys to funds"',
  },
  {
    re: /\bno keys\b(?![^.\n]*\b(to|for) funds\b)/i,
    why: 'unqualified "no keys" — say "no keys to funds"',
  },
  {
    // The Stripe adapter has never contacted api.stripe.com in ANY mode.
    // Calling it "test-mode-only" implies it was tested against test mode.
    re: /test[- ]mode[- ]only/i,
    why: '"test-mode-only" implies it ran against Stripe test mode; it has never run against Stripe at all',
  },
  {
    // The precise, allowed claims: the hash/Merkle layers are PQ-adequate
    // today; hybrid v2 adds ML-DSA-44 ALONGSIDE Ed25519 where the runtime
    // supports it; classical signatures remain exposed post-CRQC unless
    // requireAlgs is set. "Quantum-safe/-proof/-resistant" states none of
    // those qualifiers and is therefore never allowed, in any package README.
    re: /\bquantum[- ]?(safe|proof|resistant)\b/i,
    why: 'unqualified "quantum-safe/-proof/-resistant" — say exactly what holds: hash/Merkle layers PQ-adequate, hybrid ML-DSA-44 alongside Ed25519 where the runtime supports it, classical signatures exposed post-CRQC unless requireAlgs is set',
  },
];

/**
 * Blank out double-quoted spans before running the claim traps.
 *
 * A security doc has to be able to NAME a forbidden phrase in order to forbid
 * it — `Nothing here is "quantum-safe"`, or an FAQ quoting a skeptic's
 * imprecise objection before correcting it. Those are the opposite of the
 * defect the traps exist to catch, and a gate that cannot tell them apart
 * pushes authors toward vaguer docs to appease it.
 *
 * The rule is deliberately mechanical rather than clever: a phrase in quotes
 * is being DISCUSSED, a phrase outside them is being ASSERTED. It does mean an
 * author could evade a trap by quoting a real claim — accepted, because the
 * traps are a safety net against forgetting, not an adversary model. The
 * author is not the attacker here.
 */
function withoutQuotedSpans(text) {
  return text.replace(/"[^"\n]*"/g, (m) => " ".repeat(m.length));
}

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
  // Checking that a README EXISTS is not the same as checking what it SAYS, and
  // the difference cost this project a release. 0.1.1 existed to correct the
  // unqualified claim "never holds funds or keys" — which was fixed in the root
  // README and in every package.json description, while three package READMEs
  // kept shipping it verbatim to npm. Those files are the npm landing pages;
  // nothing was diffing them. So the load-bearing claims are asserted here.
  const readmePath = join(dir, "README.md");
  if (existsSync(readmePath)) {
    const readme = withoutQuotedSpans(readFileSync(readmePath, "utf8"));
    for (const { re, why } of README_CLAIM_TRAPS) {
      const m = readme.match(re);
      if (m) fail(pkg.name, `README: ${why} — found ${JSON.stringify(m[0].trim().slice(0, 72))}`);
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

/**
 * The claim traps above run per PACKAGE README, because those are the npm
 * landing pages. But the docs asserted the gate "rejects that phrase" without
 * qualification, while the root README, SECURITY.md and docs/ went unscanned —
 * the gate's scope was narrower than the claim made for it, which is the exact
 * defect class the traps exist to catch, turned on the gate itself.
 *
 * Rather than narrow the sentence, widen the gate: these files carry the same
 * claims to the same readers.
 */
{
  const extraDocs = [
    join(root, "README.md"),
    join(root, "SECURITY.md"),
    join(root, "CONTRIBUTING.md"),
    ...(existsSync(join(root, "docs"))
      ? readdirSync(join(root, "docs"))
          .filter((f) => f.endsWith(".md"))
          .map((f) => join(root, "docs", f))
      : []),
    // Example READMEs carry the same claims to the same readers — often the
    // MOST load-bearing ones, because an example is where a reader goes to find
    // out what the thing actually does. They are not published to npm, so the
    // per-package loop above never sees them; leaving them unscanned would be
    // the gate's scope being narrower than the claim made for it, again.
    ...(existsSync(join(root, "examples"))
      ? readdirSync(join(root, "examples"))
          .map((d) => join(root, "examples", d, "README.md"))
          .filter((p) => existsSync(p))
      : []),
  ];
  for (const p of extraDocs) {
    if (!existsSync(p)) continue;
    const text = withoutQuotedSpans(readFileSync(p, "utf8"));
    const rel = p.slice(root.length + 1).replace(/\\/g, "/");
    for (const { re, why } of README_CLAIM_TRAPS) {
      const m = text.match(re);
      if (m) fail(rel, `${why} — found ${JSON.stringify(m[0].trim().slice(0, 72))}`);
    }
  }
}

/**
 * The root build/test scripts are hand-written lists, and a hand-written list
 * silently omits whatever was added after it. That already happened: the
 * now-deleted `release:pack` script never included @vaduno/postgres, so it
 * reported success while never having packed it.
 *
 * A package missing from `build` is caught above (no dist/). A package missing
 * from `test` is caught by NOTHING — its suite simply never runs, and the gate
 * still prints "all packages look publishable". So assert both here.
 */
{
  const rootPkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  for (const script of ["build", "test"]) {
    const body = rootPkg.scripts?.[script] ?? "";
    for (const name of PACKAGES) {
      const full = JSON.parse(
        readFileSync(join(root, "packages", name, "package.json"), "utf8"),
      ).name;
      if (!body.includes(full)) {
        console.error(`  ✗ root "${script}" script never runs ${full}`);
        failures++;
      }
    }
  }
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

// Derived, so this can never go stale the way a hardcoded list does. Anything
// depending on @vaduno/guard must land AFTER it or it is briefly uninstallable
// (ETARGET) for whoever installs in that window.
const dependents = PACKAGES.map((name) =>
  JSON.parse(readFileSync(join(root, "packages", name, "package.json"), "utf8")),
)
  .filter((p) => p.name !== "@vaduno/guard" && p.dependencies?.["@vaduno/guard"])
  .map((p) => p.name);

console.log(`
Publish order matters — these depend on @vaduno/guard:
  1. @vaduno/guard
  2. ${dependents.join(", ")}

Reminder: publishes are effectively permanent. Use --dry-run first, and
consider --tag next for a pre-release you can retract from "latest".
`);
