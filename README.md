# sx

**See what an npm package will do — before you run it.**

`npx some-package` executes code from the internet with your full user
permissions, instantly. `sx` is a drop-in replacement that shows you a risk
info card first and only runs the package if you approve.

```
$ sx cool-new-cli
┌─ sx · cool-new-cli@1.0.2 ────────────────────────────────────────────┐
│ SUSPICIOUS  risk score 85
│
│ downloads/wk 12       created 3 days ago      maintainers 1
│ deps 0                published today         files 4
│ install hooks preinstall
│
│ findings
│   • Package is 3 days old
│   • Runs a preinstall script on install
│   • Reads process.env and makes network calls (index.js)
│   • Missing or near-empty README
└──────────────────────────────────────────────────────────────────────┘

This package looks suspicious. type "run" to proceed:
```

## Usage

```sh
sx <package>[@version] [args...]   # analyze, then run via npx if you approve
sx scan <package>                  # analyze only, don't run
sx scan --json <package>           # machine-readable report (for CI / agents)
sx <package> --yes                 # skip prompt (still blocks on "suspicious")
```

Exit codes: `0` ok, `2` analysis failed, `3` verdict was suspicious.

## What it checks

- **Install hooks** — `preinstall` / `install` / `postinstall` scripts, the
  main vector for supply-chain attacks
- **Exfiltration patterns** — code that reads `process.env` and makes network
  calls, spawns shells, or contains large base64/hex blobs
- **Typosquats** — names 1–2 edits from a popular package (embedded list,
  works offline)
- **Trust signals** — package age, release recency, weekly downloads,
  maintainer count, shipped binaries

## Use with coding agents (MCP)

`sx` ships an MCP server so agents can check a package *before* they install
it. Register it with any MCP client:

```jsonc
// Claude Code: .mcp.json  (or claude_desktop_config.json)
{
  "mcpServers": {
    "sx": { "command": "npx", "args": ["-y", "sx-cli", "sx-mcp"] }
  }
}
```

Or from a local checkout: `{"command": "node", "args": ["/path/to/sx/src/mcp.js"]}`

Two tools are exposed:

- **`scan_package`** — one spec (`express`, `react@18.2.0`, `@scope/name`)
- **`scan_packages`** — up to 20 specs at once, for evaluating a candidate list

Both return a readable summary plus the full structured report. A `suspicious`
verdict tells the agent, in the response text, not to install without asking
the user. Results are cached on disk per resolved `name@version` (immutable on
npm, so a hit is always valid).

## Scoring model

Findings are split into two kinds, and the split is the whole trick:

- **Reputation** — package age, weekly downloads, maintainer count, missing
  README. Ambient context about the project.
- **Behavior** — what the shipped code actually does: install hooks, reading
  `process.env` next to network calls, obfuscated blobs, shipped binaries.

A proven install base discounts *reputation* findings (esbuild's postinstall
binary download is fine — 261M people would have noticed). It never discounts
*behavior* findings in a release published within 72 hours, because that is
precisely the shape of a compromised-maintainer attack: popularity is the
weapon, so it must not become a hiding place.

Behavior findings are then weighted by **where the code can actually run**.
sx resolves each install hook's entry script and walks its local `require`/
`import` graph, so it knows which files execute on `npm install` — before you
have read a line of them — versus which only run on import, versus which sit
in `test/` or `examples/` and may never run at all:

| tier | weight | shown as |
|---|---|---|
| install-time | 1.5× | `[install-time]` |
| runtime | 1× | — |
| test / example | 0.25× | `[test/example]` |

The same exfiltration payload scores `suspicious` in a `postinstall` script and
`low-risk` in a test fixture — which is the correct reading of both.

## Benchmarks

```sh
npm run bench          # both, exits non-zero if either bar is missed
npm run bench:recall   # synthetic attack samples — target >90% suspicious
npm run bench:fp       # 132 real popular packages — target <2% suspicious
```

Current: **100% recall (10/10)**, **0.0% false positives (0/132)**.

## Principles

- **Zero runtime dependencies.** A tool that judges dependency trees should
  not have one. Everything (including the tar reader) is stdlib.
- **Never cries "malicious".** Verdicts cap at `suspicious` — a heuristic
  score, not an accusation. Low-risk ≠ safe; sx reduces risk, it does not
  eliminate it.
- **Nothing runs without consent.** A `suspicious` verdict requires typing
  `run` explicitly; `--yes` never bypasses it.

## Development

```sh
npm test          # unit tests (node:test, no deps)
node src/index.js scan express
```

## Roadmap

See `docs/ideas/01-better-npm-npx/EXECUTION-PLAN.md` in the planning repo:
verdict API with cached scans, LLM-assisted diff review of new releases,
signed verdicts (sigstore), MCP server so coding agents can call `sx scan`
before installing anything.
