import { createHash } from "node:crypto";
import { fetchPackage, parseSpec, fetchVersionList } from "./registry.js";
import { classifyFiles, TIER } from "./reachability.js";
import { diffLines, toUnified } from "./linediff.js";

const TEXT = /\.(c?m?js|jsx|ts|tsx|json|sh|ps1|cmd|bat)$/i;
const hash = (buf) => createHash("sha256").update(buf).digest("hex");
const strip = (name) => name.replace(/^package\//, "");

// Files whose diffs carry no security signal but plenty of noise.
const IGNORED = /(^|\/)(CHANGELOG|LICENSE|\.md$)|package-lock\.json$/i;

/**
 * Compare two versions of a package and describe what changed, with the
 * riskiest files first. Order matters: the LLM budget is finite, so
 * install-time code must be spent on before anything else.
 */
export async function diffVersions(spec, fromVersion, toVersion) {
  const { name } = parseSpec(spec);
  const [before, after] = await Promise.all([
    fetchPackage(`${name}@${fromVersion}`),
    fetchPackage(`${name}@${toVersion}`),
  ]);

  const beforeFiles = new Map(before.files.map((f) => [strip(f.name), f]));
  const afterFiles = new Map(after.files.map((f) => [strip(f.name), f]));
  const tiers = classifyFiles(after.manifest, after.files);

  const changes = [];
  for (const [path, file] of afterFiles) {
    if (IGNORED.test(path)) continue;
    const old = beforeFiles.get(path);
    const tier = tiers.get(path) ?? TIER.RUNTIME;

    if (!old) {
      changes.push({ path, kind: "added", tier, file });
    } else if (hash(old.data) !== hash(file.data)) {
      changes.push({ path, kind: "modified", tier, file, old });
    }
  }
  for (const [path] of beforeFiles) {
    if (IGNORED.test(path)) continue;
    if (!afterFiles.has(path)) {
      changes.push({ path, kind: "removed", tier: TIER.RUNTIME });
    }
  }

  // Install-time first, then added files (new code is where payloads land),
  // then everything else.
  const rank = (c) =>
    (c.tier === TIER.INSTALL ? 0 : c.tier === TIER.INERT ? 2 : 1) +
    (c.kind === "added" ? -0.5 : 0);
  changes.sort((a, b) => rank(a) - rank(b));

  const scriptsBefore = before.manifest.scripts ?? {};
  const scriptsAfter = after.manifest.scripts ?? {};
  const scriptChanges = [];
  for (const hook of ["preinstall", "install", "postinstall"]) {
    if (scriptsBefore[hook] !== scriptsAfter[hook]) {
      scriptChanges.push({ hook, before: scriptsBefore[hook] ?? null, after: scriptsAfter[hook] ?? null });
    }
  }

  const depsBefore = new Set(Object.keys(before.manifest.dependencies ?? {}));
  const addedDeps = Object.keys(after.manifest.dependencies ?? {}).filter(
    (d) => !depsBefore.has(d),
  );

  return {
    name,
    from: before.version,
    to: after.version,
    changes,
    scriptChanges,
    addedDeps,
    maintainersBefore: before.maintainers.map((m) => m.name).sort(),
    maintainersAfter: after.maintainers.map((m) => m.name).sort(),
  };
}

/** Render a diff bundle as text for an LLM, under a byte budget. */
export function renderDiff(result, { budget = 40_000 } = {}) {
  const sections = [];
  let used = 0;

  if (result.scriptChanges.length > 0) {
    const text = result.scriptChanges
      .map((c) => `  ${c.hook}: ${c.before ?? "(none)"} -> ${c.after ?? "(none)"}`)
      .join("\n");
    sections.push(`INSTALL SCRIPT CHANGES:\n${text}`);
    used += text.length;
  }
  if (result.addedDeps.length > 0) {
    sections.push(`NEW DEPENDENCIES: ${result.addedDeps.join(", ")}`);
  }
  const mb = result.maintainersBefore.join(",");
  const ma = result.maintainersAfter.join(",");
  if (mb !== ma) {
    sections.push(`MAINTAINERS CHANGED: [${mb}] -> [${ma}]`);
  }

  const skipped = [];
  for (const change of result.changes) {
    if (used >= budget) {
      skipped.push(change.path);
      continue;
    }
    const tierTag = change.tier === TIER.INSTALL ? " [RUNS AT INSTALL TIME]" : "";

    if (change.kind === "removed") {
      sections.push(`REMOVED FILE: ${change.path}`);
      continue;
    }
    if (!TEXT.test(change.path)) {
      sections.push(`${change.kind.toUpperCase()} BINARY/OTHER FILE: ${change.path}${tierTag}`);
      continue;
    }
    if (change.kind === "added") {
      const body = change.file.data.toString("utf8").slice(0, 6000);
      const block = `ADDED FILE: ${change.path}${tierTag}\n${body}`;
      sections.push(block);
      used += block.length;
      continue;
    }
    const unified = toUnified(
      diffLines(change.old.data.toString("utf8"), change.file.data.toString("utf8")),
    );
    if (!unified.trim()) continue;
    const block = `MODIFIED FILE: ${change.path}${tierTag}\n${unified}`;
    sections.push(block);
    used += block.length;
  }

  if (skipped.length > 0) {
    sections.push(`(${skipped.length} further changed file(s) omitted for length: ${skipped.slice(0, 10).join(", ")})`);
  }
  return { text: sections.join("\n\n"), skipped };
}
