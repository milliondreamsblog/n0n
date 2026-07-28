// Reachability: not all code in a tarball is equal. A risky pattern in the
// file your postinstall hook executes runs on `npm install`, unconditionally,
// before you have read a line of it. The same pattern in a test fixture or an
// example may never execute at all. sx weights findings accordingly.

const ENTRY_FROM_NODE = /(?:^|[;&|]\s*)(?:node|nodejs)\s+(?:--[\w-]+\s+)*["']?([\w./@-]+\.[cm]?js)["']?/g;
const REQUIRE_OR_IMPORT =
  /(?:require\s*\(\s*["']([^"']+)["']\s*\)|(?:^|\s)(?:import|export)\b[^;]*?from\s*["']([^"']+)["']|import\s*\(\s*["']([^"']+)["']\s*\))/g;

// Directories whose code is shipped but not part of the runtime surface.
const INERT_PATH =
  /(^|\/)(test|tests|__tests__|spec|example|examples|demo|fixtures?|docs?|benchmark|benchmarks|\.github)\//i;

export const TIER = {
  INSTALL: "install", // executes on `npm install`
  RUNTIME: "runtime", // executes when the package is imported/run
  INERT: "inert", // tests, examples, docs — may never execute
};

function normalize(path) {
  return path.replace(/^package\//, "").replace(/^\.\//, "");
}

/** Resolve a require/import specifier to a file path within the package. */
function resolveLocal(fromPath, spec, byPath) {
  if (!spec.startsWith(".")) return null; // bare specifier = external dep
  const fromDir = fromPath.includes("/")
    ? fromPath.slice(0, fromPath.lastIndexOf("/"))
    : "";
  const parts = (fromDir ? `${fromDir}/${spec}` : spec).split("/");
  const stack = [];
  for (const part of parts) {
    if (part === "." || part === "") continue;
    if (part === "..") stack.pop();
    else stack.push(part);
  }
  const base = stack.join("/");
  for (const candidate of [
    base,
    `${base}.js`,
    `${base}.cjs`,
    `${base}.mjs`,
    `${base}/index.js`,
    `${base}/index.cjs`,
    `${base}/index.mjs`,
  ]) {
    if (byPath.has(candidate)) return candidate;
  }
  return null;
}

/**
 * Classify every file in the package by execution tier.
 * Returns a Map of normalized path -> TIER value.
 */
export function classifyFiles(manifest, files) {
  const byPath = new Map();
  for (const f of files) byPath.set(normalize(f.name), f);

  const tiers = new Map();
  const scripts = manifest.scripts ?? {};

  // --- seed: entry points named by install hooks --------------------------
  const installSeeds = new Set();
  for (const hook of ["preinstall", "install", "postinstall"]) {
    const cmd = scripts[hook];
    if (!cmd) continue;
    for (const match of cmd.matchAll(ENTRY_FROM_NODE)) {
      const resolved = normalize(match[1]);
      if (byPath.has(resolved)) installSeeds.add(resolved);
    }
  }

  // --- seed: the package's own runtime entry points ------------------------
  const runtimeSeeds = new Set();
  const addRuntimeSeed = (p) => {
    if (!p) return;
    const n = normalize(String(p));
    for (const candidate of [n, `${n}.js`, `${n}/index.js`]) {
      if (byPath.has(candidate)) {
        runtimeSeeds.add(candidate);
        return;
      }
    }
  };
  addRuntimeSeed(manifest.main ?? "index.js");
  addRuntimeSeed(manifest.module);
  if (typeof manifest.bin === "string") addRuntimeSeed(manifest.bin);
  else for (const p of Object.values(manifest.bin ?? {})) addRuntimeSeed(p);
  for (const value of Object.values(manifest.exports ?? {})) {
    if (typeof value === "string") addRuntimeSeed(value);
    else for (const nested of Object.values(value ?? {})) addRuntimeSeed(nested);
  }

  // --- walk the local module graph from each seed set ----------------------
  const walk = (seeds, tier) => {
    const queue = [...seeds];
    const seen = new Set();
    while (queue.length > 0) {
      const path = queue.shift();
      if (seen.has(path)) continue;
      seen.add(path);
      // install tier wins over runtime if a file is reachable from both
      if (!tiers.has(path) || tier === TIER.INSTALL) tiers.set(path, tier);
      const file = byPath.get(path);
      if (!file || file.data.length > 2 * 1024 * 1024) continue;
      const text = file.data.toString("utf8");
      for (const m of text.matchAll(REQUIRE_OR_IMPORT)) {
        const spec = m[1] ?? m[2] ?? m[3];
        const target = resolveLocal(path, spec, byPath);
        if (target && !seen.has(target)) queue.push(target);
      }
    }
  };
  walk(installSeeds, TIER.INSTALL);
  walk(runtimeSeeds, TIER.RUNTIME);

  // --- everything else -----------------------------------------------------
  for (const path of byPath.keys()) {
    if (tiers.has(path)) continue;
    tiers.set(path, INERT_PATH.test(path) ? TIER.INERT : TIER.RUNTIME);
  }
  return tiers;
}

// Severity multipliers per tier. Install-time code is the highest-stakes
// surface on npm: it runs unprompted. Inert code still gets a fraction rather
// than zero — a payload hidden in examples/ is a real (if lazier) technique.
export const TIER_WEIGHT = {
  [TIER.INSTALL]: 1.5,
  [TIER.RUNTIME]: 1,
  [TIER.INERT]: 0.25,
};
