// ANSI info card. No color library — raw escape codes keep sx zero-dep.

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const RED = "\x1b[31m";

const VERDICT_STYLE = {
  "low-risk": { color: GREEN, label: "LOW RISK" },
  caution: { color: YELLOW, label: "CAUTION" },
  suspicious: { color: RED, label: "SUSPICIOUS" },
};

const WIDTH = 74;

function humanCount(n) {
  if (n === null || n === undefined) return "unknown";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

function humanAge(iso) {
  if (!iso) return "unknown";
  const days = Math.floor((Date.now() - Date.parse(iso)) / 86_400_000);
  if (days < 1) return "today";
  if (days < 60) return `${days} days ago`;
  if (days < 730) return `${Math.floor(days / 30)} months ago`;
  return `${Math.floor(days / 365)} years ago`;
}

function line(text = "") {
  process.stdout.write(`│ ${text}${RESET}\n`);
}

function wrap(text, indent) {
  const max = WIDTH - indent.length - 2;
  const words = text.split(" ");
  const lines = [];
  let current = "";
  for (const word of words) {
    if (current && current.length + word.length + 1 > max) {
      lines.push(current);
      current = word;
    } else {
      current = current ? `${current} ${word}` : word;
    }
  }
  if (current) lines.push(current);
  return lines;
}

const ASSESSMENT_STYLE = {
  routine: { color: GREEN, label: "ROUTINE" },
  unusual: { color: YELLOW, label: "UNUSUAL" },
  alarming: { color: RED, label: "ALARMING" },
};

export function renderDiffSummary(result, review, llmEnabled) {
  const title = ` sx diff · ${result.name} ${result.from} → ${result.to} `;
  process.stdout.write(
    `┌─${BOLD}${title}${RESET}` +
      "─".repeat(Math.max(1, WIDTH - title.length - 2)) +
      "┐\n",
  );

  const installChanges = result.changes.filter((c) => c.tier === "install");
  line(
    `${DIM}files changed${RESET} ${String(result.changes.length).padEnd(8)}` +
      `${DIM}install-time${RESET} ${
        installChanges.length ? RED + installChanges.length : GREEN + "0"
      }`,
  );

  if (result.scriptChanges.length > 0) {
    line();
    line(`${RED}${BOLD}install hooks changed${RESET}`);
    for (const c of result.scriptChanges) {
      for (const l of wrap(`${c.hook}: ${c.before ?? "(none)"} → ${c.after ?? "(none)"}`, "  ")) {
        line(`${RED}  ${l}`);
      }
    }
  }
  if (result.addedDeps.length > 0) {
    line(`${YELLOW}new dependencies: ${result.addedDeps.join(", ")}`);
  }
  if (result.maintainersBefore.join() !== result.maintainersAfter.join()) {
    line(`${YELLOW}maintainers changed: ${result.maintainersBefore.join(", ")} → ${result.maintainersAfter.join(", ")}`);
  }

  line();
  const shown = result.changes.slice(0, 12);
  for (const c of shown) {
    const mark = c.kind === "added" ? "+" : c.kind === "removed" ? "-" : "~";
    const tag = c.tier === "install" ? `${RED}[install-time]${RESET}${DIM} ` : "";
    line(`${DIM}  ${mark} ${tag}${c.path}`);
  }
  if (result.changes.length > shown.length) {
    line(`${DIM}  … ${result.changes.length - shown.length} more`);
  }

  if (review && !review.error) {
    const style = ASSESSMENT_STYLE[review.assessment] ?? ASSESSMENT_STYLE.unusual;
    line();
    line(`${BOLD}model review${RESET}  ${style.color}${BOLD}${style.label}${RESET}`);
    for (const l of wrap(review.summary, "  ")) line(`  ${l}`);
    for (const c of review.concerns ?? []) {
      const color = c.severity === "high" ? RED : c.severity === "medium" ? YELLOW : DIM;
      for (const [i, l] of wrap(c.detail, "  • ").entries()) {
        line(`${color}  ${i === 0 ? "• " : "  "}${l}`);
      }
    }
  } else if (review?.error) {
    line();
    line(`${DIM}model review unavailable: ${review.error}`);
  } else if (!llmEnabled) {
    line();
    line(`${DIM}set SX_LLM_API_KEY to add an AI review of this diff`);
  }

  process.stdout.write("└" + "─".repeat(WIDTH - 1) + "┘\n");
}

export function renderCard(report) {
  const { verdict, score, findings, facts } = report;
  const style = VERDICT_STYLE[verdict];
  const title = ` sx · ${facts.name}@${facts.version} `;

  process.stdout.write(
    `┌─${BOLD}${title}${RESET}` +
      "─".repeat(Math.max(1, WIDTH - title.length - 2)) +
      "┐\n",
  );
  const trustNote =
    report.trust < 1
      ? `  ${DIM}(raw ${report.rawScore}, discounted for proven install base)${RESET}`
      : "";
  line(`${style.color}${BOLD}${style.label}${RESET}  ${DIM}risk score ${score}${RESET}${trustNote}`);
  line();
  line(
    `${DIM}downloads/wk${RESET} ${humanCount(facts.weeklyDownloads).padEnd(9)}` +
      `${DIM}created${RESET} ${humanAge(facts.created).padEnd(16)}` +
      `${DIM}maintainers${RESET} ${facts.maintainers}`,
  );
  line(
    `${DIM}deps${RESET} ${String(facts.dependencies).padEnd(17)}` +
      `${DIM}published${RESET} ${humanAge(facts.published).padEnd(14)}` +
      `${DIM}files${RESET} ${facts.fileCount}`,
  );
  line(
    `${DIM}install hooks${RESET} ${
      facts.installHooks.length ? RED + facts.installHooks.join(", ") : GREEN + "none"
    }`,
  );

  if (findings.length > 0) {
    line();
    line(`${BOLD}findings${RESET}`);
    for (const f of findings) {
      const color = f.severity >= 25 ? RED : f.severity >= 10 ? YELLOW : DIM;
      // The tier is the most decision-relevant fact about a code finding:
      // install-time code runs before you can read it.
      const badge =
        f.tier === "install"
          ? `${RED}[install-time]${RESET}${color} `
          : f.tier === "inert"
            ? `${DIM}[test/example]${RESET}${color} `
            : "";
      for (const [i, l] of wrap(`${f.title}`, "  • ").entries()) {
        line(`${color}  • ${i === 0 ? badge : ""}${l}`);
      }
      if (f.detail) {
        for (const l of wrap(f.detail, "      ")) line(`${DIM}      ${l}`);
      }
    }
  }
  process.stdout.write("└" + "─".repeat(WIDTH - 1) + "┘\n");
}
