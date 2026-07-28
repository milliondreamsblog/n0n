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
