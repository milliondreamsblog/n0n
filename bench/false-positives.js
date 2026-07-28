// False-positive benchmark: scan every package in the embedded POPULAR list
// (all legitimate, heavily-used packages) and report the verdict distribution.
// Target from the execution plan: <2% of known-good packages may score
// "suspicious". Run: node bench/false-positives.js [--limit N]
import { fetchPackage } from "../src/registry.js";
import { analyze } from "../src/analyze.js";
import { POPULAR } from "../src/typosquat.js";

const limitFlag = process.argv.indexOf("--limit");
const limit = limitFlag !== -1 ? Number(process.argv[limitFlag + 1]) : Infinity;
const names = POPULAR.slice(0, limit);

const CONCURRENCY = 8;
const results = [];
const failures = [];

async function worker(queue) {
  while (queue.length > 0) {
    const name = queue.shift();
    try {
      const report = analyze(await fetchPackage(name));
      results.push({ name, verdict: report.verdict, score: report.score });
      process.stderr.write(
        `${report.verdict === "suspicious" ? "!!" : "ok"} ${name} (${report.verdict}, ${report.score})\n`,
      );
    } catch (err) {
      failures.push({ name, error: err.message });
      process.stderr.write(`-- ${name} failed: ${err.message}\n`);
    }
  }
}

const queue = [...names];
await Promise.all(Array.from({ length: CONCURRENCY }, () => worker(queue)));

const byVerdict = { "low-risk": 0, caution: 0, suspicious: 0 };
for (const r of results) byVerdict[r.verdict]++;
const scanned = results.length;
const fpRate = ((byVerdict.suspicious / scanned) * 100).toFixed(1);

console.log("\n=== false-positive benchmark ===");
console.log(`scanned ${scanned}/${names.length} (${failures.length} fetch failures)`);
console.log(`low-risk:   ${byVerdict["low-risk"]}`);
console.log(`caution:    ${byVerdict.caution}`);
console.log(`suspicious: ${byVerdict.suspicious}  → FP rate ${fpRate}% (target <2%)`);

const flagged = results
  .filter((r) => r.verdict !== "low-risk")
  .sort((a, b) => b.score - a.score);
if (flagged.length > 0) {
  console.log("\nnon-low-risk packages:");
  for (const r of flagged) console.log(`  ${r.verdict.padEnd(10)} ${String(r.score).padStart(3)}  ${r.name}`);
}
process.exit(byVerdict.suspicious / scanned >= 0.02 ? 1 : 0);
