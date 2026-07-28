import { typosquatTarget } from "./typosquat.js";

// Verdicts are deliberately capped at "suspicious" — sx never claims a
// package is malicious. That label needs human review sx doesn't have yet.
export const VERDICTS = ["low-risk", "caution", "suspicious"];

const DAY_MS = 24 * 60 * 60 * 1000;
const TEXT_EXTENSIONS = /\.(c?m?js|jsx|ts|tsx|json|sh|ps1|cmd|bat)$/i;
const BINARY_EXTENSIONS = /\.(exe|dll|so|dylib|node|bin)$/i;

function finding(severity, title, detail) {
  return { severity, title, detail };
}

// Bundled/minified outputs of legitimate libraries are full of eval, huge
// base64 blobs, and packed strings — near-zero signal, constant noise.
const BUNDLE_PATH = /\.min\.c?m?js$|(^|\/)(dist|build|umd|vendor|compiled|bundles?)\//i;

function scanSource(path, text, findings) {
  if (BUNDLE_PATH.test(path)) return;
  const flags = [];
  if (/\beval\s*\(/.test(text)) flags.push("eval()");
  if (/new\s+Function\s*\(/.test(text)) flags.push("new Function()");
  const usesChildProcess = /child_process|execSync|spawnSync/.test(text);
  const usesNetwork = /\bfetch\s*\(|https?\.request|XMLHttpRequest|net\.connect|dns\.lookup/.test(text);
  const usesEnv = /process\.env/.test(text);
  const base64Blob = /["'][A-Za-z0-9+/]{200,}={0,2}["']/.test(text);
  const hexBlob = /(\\x[0-9a-fA-F]{2}){40,}/.test(text);

  if (base64Blob) flags.push("large base64 blob");
  if (hexBlob) flags.push("hex-encoded string blob");

  if (flags.length > 0) {
    findings.push(
      finding(10, `Obfuscation signals in ${path}`, flags.join(", ")),
    );
  }
  // The classic exfiltration triple: read env + talk to network (+ shell).
  if (usesEnv && usesNetwork) {
    findings.push(
      finding(
        usesChildProcess ? 25 : 15,
        `Reads process.env and makes network calls (${path})`,
        usesChildProcess ? "also spawns child processes" : null,
      ),
    );
  } else if (usesChildProcess && usesNetwork) {
    findings.push(
      finding(15, `Spawns processes and makes network calls (${path})`, null),
    );
  }
}

/**
 * Run all heuristics over a fetched package.
 * Returns { verdict, score, findings, facts }.
 */
export function analyze(pkg) {
  const findings = [];
  const now = Date.now();

  // --- metadata heuristics -------------------------------------------------
  const squatOf = typosquatTarget(pkg.name);
  if (squatOf) {
    findings.push(
      finding(40, `Name is 1-2 edits from popular package "${squatOf}"`,
        "possible typosquat — double-check you typed the right name"),
    );
  }

  const ageDays = pkg.createdAt ? (now - Date.parse(pkg.createdAt)) / DAY_MS : null;
  if (ageDays !== null && ageDays < 7) {
    findings.push(finding(35, `Package is ${Math.floor(ageDays)} days old`, null));
  } else if (ageDays !== null && ageDays < 30) {
    findings.push(finding(20, `Package is under 30 days old`, null));
  }

  const versionAgeHours = pkg.versionPublishedAt
    ? (now - Date.parse(pkg.versionPublishedAt)) / (60 * 60 * 1000)
    : null;
  if (versionAgeHours !== null && versionAgeHours < 48 && ageDays !== null && ageDays >= 30) {
    findings.push(
      finding(10, `This version was published ${Math.floor(versionAgeHours)}h ago`,
        "fresh releases of established packages are how compromised maintainer attacks ship"),
    );
  }

  if (pkg.maintainers.length === 1) {
    findings.push(finding(5, "Single maintainer", null));
  }
  if (!pkg.readme || pkg.readme.length < 100) {
    findings.push(finding(5, "Missing or near-empty README", null));
  }
  if (pkg.weeklyDownloads !== null && pkg.weeklyDownloads < 100) {
    findings.push(finding(10, `Only ${pkg.weeklyDownloads} downloads last week`, null));
  }

  // --- install scripts -----------------------------------------------------
  const scripts = pkg.manifest.scripts ?? {};
  const installHooks = ["preinstall", "install", "postinstall"].filter(
    (hook) => scripts[hook],
  );
  for (const hook of installHooks) {
    findings.push(
      finding(25, `Runs a ${hook} script on install`, `"${scripts[hook]}"`),
    );
  }

  // --- tarball contents ----------------------------------------------------
  const binaries = pkg.files.filter((f) => BINARY_EXTENSIONS.test(f.name));
  if (binaries.length > 0) {
    findings.push(
      finding(15, `Ships ${binaries.length} precompiled binary file(s)`,
        binaries.slice(0, 3).map((f) => f.name.replace(/^package\//, "")).join(", ")),
    );
  }

  for (const file of pkg.files) {
    if (!TEXT_EXTENSIONS.test(file.name)) continue;
    if (file.size > 2 * 1024 * 1024) continue; // skip huge bundles
    const path = file.name.replace(/^package\//, "");
    // Only scan code that can actually run at install time or import time —
    // for v0 we scan everything but weight install-hook files implicitly via
    // the hook finding above.
    scanSource(path, file.data.toString("utf8"), findings);
  }

  // Cap repeated per-file findings so one pattern doesn't swamp the card.
  // The key must normalize away file paths — both "(path)" and "in path"
  // forms — or every file counts as a distinct finding.
  const deduped = [];
  const seenTitles = new Map();
  for (const f of findings) {
    const key = f.title.replace(/\s*\(.*\)/, "").replace(/ in .+$/, "");
    const count = seenTitles.get(key) ?? 0;
    if (count < 2) deduped.push(f);
    seenTitles.set(key, count + 1);
  }

  // Trust dampener: heuristics like install hooks and env+network access are
  // normal for massively-adopted packages (esbuild downloads its platform
  // binary in postinstall). Scale raw score down by proven install base + age
  // so the same signals still surface but read as "worth knowing", not alarm.
  const rawScore = deduped.reduce((sum, f) => sum + f.severity, 0);
  let trust = 1;
  if (ageDays !== null && ageDays > 365 && pkg.weeklyDownloads !== null) {
    if (pkg.weeklyDownloads > 10_000_000) trust = 0.4;
    else if (pkg.weeklyDownloads > 1_000_000) trust = 0.6;
    else if (pkg.weeklyDownloads > 100_000) trust = 0.8;
  } else if (ageDays !== null && ageDays > 730 && pkg.weeklyDownloads === null) {
    // Download stats unavailable (API hiccup / scoped package): age alone
    // still earns a modest discount so verdicts don't flap on network luck.
    trust = 0.8;
  }
  const score = Math.round(rawScore * trust);
  const verdict = score >= 50 ? "suspicious" : score >= 20 ? "caution" : "low-risk";

  return {
    verdict,
    score,
    rawScore,
    trust,
    findings: deduped.sort((a, b) => b.severity - a.severity),
    facts: {
      name: pkg.name,
      version: pkg.version,
      created: pkg.createdAt,
      published: pkg.versionPublishedAt,
      weeklyDownloads: pkg.weeklyDownloads,
      maintainers: pkg.maintainers.length,
      dependencies: Object.keys(pkg.manifest.dependencies ?? {}).length,
      fileCount: pkg.files.length,
      installHooks,
    },
  };
}
