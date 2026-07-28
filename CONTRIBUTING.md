# Contributing to sx

Thanks for helping make `npx` less of a leap of faith.

## Ground rules

**1. Zero runtime dependencies.** This is not a style preference. sx tells you
whether a dependency is safe to install; it would be absurd for that answer to
arrive through a dependency tree of its own. Everything ships on the Node
standard library — including the tar reader (`src/tar.js`) and the MCP wire
protocol (`src/mcp.js`). Dev-time tooling must also stay empty: tests use
`node --test`.

**2. Verdicts cap at `suspicious`.** sx never labels a package "malicious".
That word is an accusation about a person, and it needs human review, an
appeals path, and legal consideration that this project does not yet have. A
heuristic score is not evidence.

**3. Nothing runs without consent.** `--yes` may skip the prompt for a clean
package; it must never bypass the confirmation on a `suspicious` verdict.

## Getting started

```sh
git clone https://github.com/milliondreamsblog/n0n
cd n0n
npm test              # 25 unit + protocol tests, no install needed
node src/index.js scan express
```

There is no build step and nothing to install.

## The two accuracy bars

Every change to detection logic must clear both, and CI enforces them:

```sh
npm run bench:recall   # synthetic attack samples — must stay >90% suspicious
npm run bench:fp       # 132 real popular packages — must stay <2% suspicious
```

Current baseline: **100% recall, 0.0% false positives.**

Do not tune one at the expense of the other. It is easy to reach 100% recall by
flagging everything, and easy to reach 0% false positives by flagging nothing.
If your change moves either number, say so in the PR description with the
before/after output.

## Adding a heuristic

1. Add the check in `src/analyze.js`. Use `behavior(...)` for findings about
   what the shipped code does and `finding(...)` for reputation signals — the
   two are scored differently and the distinction is load-bearing (see the
   scoring model in the README).
2. Add a unit test in `test/analyze.test.js` with a synthetic package that
   triggers it, and one that must *not* trigger it.
3. If it detects a new attack class, add an inert sample to
   `bench/true-positives.js`. Samples must be non-functional: dead `.invalid`
   hostnames, no working payloads.
4. Run both benchmarks. Report the numbers.

## Reporting detection errors

These are the most useful issues you can file, and they have templates:

- **False positive** — a legitimate package scored `suspicious`
- **False negative** — a package with a real problem scored `low-risk`

Include the exact `sx scan --json <package>` output. For a false negative,
describe what the package does that sx missed; **do not attach live malware.**

## Things that need doing

- More popular packages in the false-positive corpus (`src/typosquat.js`
  `POPULAR` doubles as the benchmark list)
- Attack patterns sx does not yet catch — see `bench/true-positives.js` for
  the shape of a sample
- Registry support beyond npm (PyPI has the same problem)
- LLM-assisted diff review of new releases (the roadmap's next big item)

## Commits and PRs

Conventional-commit prefixes (`feat:`, `fix:`, `docs:`, `test:`). Keep the
subject under ~72 characters and explain *why* in the body. PRs should be
focused; a detection change and a refactor belong in separate commits.
