#!/usr/bin/env node
import { createInterface } from "node:readline/promises";
import { spawn } from "node:child_process";
import { fetchPackage, parseSpec, fetchVersionList } from "./registry.js";
import { analyze } from "./analyze.js";
import { renderCard, renderDiffSummary } from "./card.js";

import { diffVersions, renderDiff } from "./diff.js";
import { reviewDiff, isConfigured, mergeReview } from "./llm.js";

const USAGE = `sx — see what an npm package will do before you run it

usage:
  sx <package>[@version] [args...]   analyze, then run via npx if you approve
  sx scan <package>[@version]        analyze only
  sx scan --json <package>           machine-readable report
  sx diff <package>[@version]        review what changed since the previous
                                     release (LLM-assisted if configured)

flags:
  --yes     skip the confirmation prompt (still blocks on "suspicious")
  --from X  version to diff from (default: the release before the target)

LLM review (optional) — set SX_LLM_API_KEY to enable:
  SX_LLM_API_KEY   provider API key
  SX_LLM_BASE_URL  OpenAI-compatible endpoint (default: api.openai.com/v1)
  SX_LLM_MODEL     model name (default: gpt-4o-mini)
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

function flagValue(argv, name) {
  const idx = argv.indexOf(`--${name}`);
  return idx !== -1 ? argv[idx + 1] : null;
}

async function runDiff(argv) {
  const positional = argv.filter((a, i) => !a.startsWith("--") && argv[i - 1] !== "--from");
  const spec = positional[0];
  if (!spec) {
    process.stdout.write(USAGE);
    process.exit(1);
  }
  const { name } = parseSpec(spec);
  const json = argv.includes("--json");

  const target = (await fetchPackage(spec)).version;
  let from = flagValue(argv, "from");
  if (!from) {
    const versions = await fetchVersionList(name);
    const idx = versions.findIndex((v) => v.version === target);
    if (idx <= 0) {
      process.stderr.write(`sx: ${name}@${target} has no earlier release to compare against\n`);
      process.exit(2);
    }
    from = versions[idx - 1].version;
  }

  if (!json) process.stderr.write(`sx: comparing ${name} ${from} -> ${target}...\n`);
  const result = await diffVersions(name, from, target);
  const rendered = renderDiff(result);

  let review = null;
  if (isConfigured()) {
    if (!json) process.stderr.write("sx: asking the model to review the diff...\n");
    review = await reviewDiff(result, rendered.text);
  }

  // The diff is only half the answer: what matters is the verdict on the
  // version you are about to install. Scan the target and fold the review in
  // — mergeReview may raise that verdict but never lower it.
  const heuristicReport = analyze(await fetchPackage(`${name}@${target}`));
  const report = review ? mergeReview(heuristicReport, review) : heuristicReport;
  const suspicious = report.verdict === "suspicious";

  if (json) {
    process.stdout.write(
      JSON.stringify(
        {
          ...result,
          changes: result.changes.map((c) => ({ path: c.path, kind: c.kind, tier: c.tier })),
          review,
          report,
        },
        null,
        2,
      ) + "\n",
    );
    process.exit(suspicious ? 3 : 0);
  }

  renderDiffSummary(result, review, isConfigured(), report);
  process.exit(suspicious ? 3 : 0);
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    process.stdout.write(USAGE);
    process.exit(argv.length === 0 ? 1 : 0);
  }

  if (argv[0] === "diff") {
    try {
      await runDiff(argv.slice(1));
    } catch (err) {
      process.stderr.write(`sx: ${err.message}\n`);
      process.exit(2);
    }
    return;
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
