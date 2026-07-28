import { typosquatTarget } from "./typosquat.js";
import { classifyFiles, TIER, TIER_WEIGHT } from "./reachability.js";

// Verdicts are deliberately capped at "suspicious" — sx never claims a
// package is malicious. That label needs human review sx doesn't have yet.
export const VERDICTS = ["low-risk", "caution", "suspicious"];

const DAY_MS = 24 * 60 * 60 * 1000;
const TEXT_EXTENSIONS = /\.(c?m?js|jsx|ts|tsx|json|sh|ps1|cmd|bat)$/i;
const BINARY_EXTENSIONS = /\.(exe|dll|so|dylib|node|bin)$/i;

// A finding is either about the package's *reputation* (age, downloads,
// maintainer count — ambient context) or its *behavior* (what the shipped code
// actually does). The distinction matters for scoring: a proven install base
// excuses weak reputation signals, but never excuses fresh dangerous code.
function finding(severity, title, detail, kind = "reputation") {
  return { severity, title, detail, kind };
}
const behavior = (severity, title, detail) =>
  finding(severity, title, detail, "behavior");

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
      behavior(10, `Obfuscation signals in ${path}`, flags.join(", ")),
    );
  }
  // The classic exfiltration triple: read env + talk to network (+ shell).
  if (usesEnv && usesNetwork) {
    findings.push(
      behavior(
        usesChildProcess ? 25 : 15,
        `Reads process.env and makes network calls (${path})`,
        usesChildProcess ? "also spawns child processes" : null,
      ),
    );
  } else if (usesChildProcess && usesNetwork) {
    findings.push(
      behavior(15, `Spawns processes and makes network calls (${path})`, null),
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
      behavior(25, `Runs a ${hook} script on install`, `"${scripts[hook]}"`),
    );
  }

  // --- tarball contents ----------------------------------------------------
  const binaries = pkg.files.filter((f) => BINARY_EXTENSIONS.test(f.name));
  if (binaries.length > 0) {
    findings.push(
      behavior(15, `Ships ${binaries.length} precompiled binary file(s)`,
        binaries.slice(0, 3).map((f) => f.name.replace(/^package\//, "")).join(", ")),
    );
  }

  // Classify files by whether they can actually execute, then weight each
  // file's findings by tier — install-time code counts more than a test
  // fixture that may never run.
  const tiers = classifyFiles(pkg.manifest, pkg.files);
  for (const file of pkg.files) {
    if (!TEXT_EXTENSIONS.test(file.name)) continue;
    if (file.size > 2 * 1024 * 1024) continue; // skip huge bundles
    const path = file.name.replace(/^package\//, "");
    const tier = tiers.get(path) ?? TIER.RUNTIME;
    const before = findings.length;
    scanSource(path, file.data.toString("utf8"), findings);
    for (let i = before; i < findings.length; i++) {
      findings[i].tier = tier;
      findings[i].severity = Math.round(findings[i].severity * TIER_WEIGHT[tier]);
      if (tier === TIER.INSTALL) {
        findings[i].detail = findings[i].detail
          ? `${findings[i].detail}; runs at install time`
          : "runs at install time";
      }
    }
  }

  // Cap repeated per-file findings so one pattern doesn't swamp the card.
  // The key must normalize away file paths — both "(path)" and "in path"
  // forms — or every file counts as a distinct finding. Sort by severity
  // first so the surviving copies are the install-time ones, not whichever
  // file happened to be scanned first.
  const deduped = [];
  const seenTitles = new Map();
  for (const f of [...findings].sort((a, b) => b.severity - a.severity)) {
    const key = f.title.replace(/\s*\(.*\)/, "").replace(/ in .+$/, "");
    const count = seenTitles.get(key) ?? 0;
    if (count < 2) deduped.push(f);
    seenTitles.set(key, count + 1);
  }

  // Trust dampener: install hooks and env+network access are normal for
  // massively-adopted packages (esbuild downloads its platform binary in
  // postinstall), so a proven install base discounts the score.
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

  // ...but reputation is earned by the *package*, not by code published an
  // hour ago. In a compromised-maintainer attack the install base is exactly
  // what makes it dangerous, so behavior findings in a fresh release are
  // scored at full weight. Without this, popularity becomes a hiding place.
  const freshRelease = versionAgeHours !== null && versionAgeHours < 72;
  const isDiscounted = (f) => !(freshRelease && f.kind === "behavior");
  const score = Math.round(
    deduped.reduce(
      (sum, f) => sum + f.severity * (isDiscounted(f) ? trust : 1),
      0,
    ),
  );
  const verdict = score >= 50 ? "suspicious" : score >= 20 ? "caution" : "low-risk";

  return {
    verdict,
    score,
    rawScore,
    trust,
    freshRelease,
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
