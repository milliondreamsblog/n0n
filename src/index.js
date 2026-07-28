#!/usr/bin/env node
import { createInterface } from "node:readline/promises";
import { spawn } from "node:child_process";
import { fetchPackage, parseSpec } from "./registry.js";
import { analyze } from "./analyze.js";
import { renderCard } from "./card.js";

const USAGE = `sx — see what an npm package will do before you run it

usage:
  sx <package>[@version] [args...]   analyze, then run via npx if you approve
  sx scan <package>[@version]        analyze only
  sx scan --json <package>           machine-readable report

flags:
  --yes    skip the confirmation prompt (still blocks on "suspicious")
`;

async function confirm(question, { dangerous }) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    if (dangerous) {
      const answer = await rl.question(`${question} type "run" to proceed: `);
      return answer.trim() === "run";
    }
    const answer = await rl.question(`${question} [y/N] `);
    return /^y(es)?$/i.test(answer.trim());
  } finally {
    rl.close();
  }
}

function runNpx(spec, args) {
  const child = spawn("npx", ["--yes", spec, ...args], {
    stdio: "inherit",
    shell: process.platform === "win32",
  });
  child.on("exit", (code) => process.exit(code ?? 0));
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    process.stdout.write(USAGE);
    process.exit(argv.length === 0 ? 1 : 0);
  }

  const scanOnly = argv[0] === "scan";
  const rest = scanOnly ? argv.slice(1) : argv;
  const json = rest.includes("--json");
  const yes = rest.includes("--yes");
  const positional = rest.filter((a) => !a.startsWith("--"));
  const spec = positional[0];
  const passthroughArgs = positional.slice(1);

  if (!spec) {
    process.stdout.write(USAGE);
    process.exit(1);
  }

  const { name } = parseSpec(spec);
  if (!json) process.stderr.write(`sx: analyzing ${name}...\n`);

  let report;
  try {
    const pkg = await fetchPackage(spec);
    report = analyze(pkg);
  } catch (err) {
    process.stderr.write(`sx: ${err.message}\n`);
    process.exit(2);
  }

  if (json) {
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
    process.exit(report.verdict === "suspicious" ? 3 : 0);
  }

  renderCard(report);

  if (scanOnly) {
    process.exit(report.verdict === "suspicious" ? 3 : 0);
  }

  const dangerous = report.verdict === "suspicious";
  if (yes && !dangerous) {
    runNpx(spec, passthroughArgs);
    return;
  }
  const ok = await confirm(
    dangerous
      ? `\nThis package looks suspicious.`
      : `\nRun ${report.facts.name}@${report.facts.version}?`,
    { dangerous },
  );
  if (!ok) {
    process.stderr.write("sx: aborted, nothing was run.\n");
    process.exit(0);
  }
  runNpx(spec, passthroughArgs);
}

main();
