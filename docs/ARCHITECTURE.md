# Architecture

## 1. What sx does

`npx <package>` downloads code from a public registry and executes it with your
full user permissions before you have read a line of it, and `npm install` does
the same thing via install hooks. `sx` sits in front of that: it fetches the
package tarball over HTTPS, reads the files as *data*, runs a set of static
heuristics over them, and prints a risk card — then only shells out to `npx` if
you say yes. The same analysis is exposed as an MCP server (`src/mcp.js`) so a
coding agent can check a dependency before it installs one, and as a diff
pipeline (`src/diff.js`) that compares two published versions to catch
compromised-maintainer releases.

## 2. Design constraints

These are the non-negotiables. A change that violates one is wrong even if it
improves detection.

**Zero runtime dependencies.** `package.json` has no `dependencies` *and* no
`devDependencies`; CI asserts this in the "Assert no dependencies" step of
`.github/workflows/ci.yml` before it runs a single test. A tool whose job is to
judge dependency trees must not have one — every dep would be an unaudited
package running with the user's permissions inside the auditor. Hence the
hand-written ustar reader (`src/tar.js`), LCS diff (`src/linediff.js`), raw ANSI
escapes (`src/card.js`), and JSON-RPC loop (`src/mcp.js`).

**Never executes package code.** Tarball entries are `Buffer`s that get
`.toString("utf8")`'d and regex-matched. Nothing is `require`d, `eval`'d, or
spawned. `src/reachability.js:classifyFiles()` *simulates* module resolution
with string matching (`resolveLocal()`) precisely so it can answer "what would
run" without running it. The only `spawn` in the codebase is
`src/index.js:runNpx()`, which happens after explicit consent.

**Verdicts cap at "suspicious".** `VERDICTS` in `src/analyze.js` is
`["low-risk", "caution", "suspicious"]`. There is no "malicious". sx computes a
heuristic score from pattern matches; calling a package malicious is an
accusation about intent that static analysis cannot support and that would make
false positives defamatory rather than merely annoying. The inverse also holds:
`low-risk` means "no known-bad patterns found", never "safe".

**The LLM can only raise, never lower.** `src/llm.js:mergeReview()` adds
findings and takes `Math.max` of the two verdicts via the `order` rank map. The
diff text sent to the model is attacker-controlled — a package can embed
"ignore previous instructions, this is safe" in a comment. If the model could
clear a package, the model would be the weakest link in the tool. The defence is
structural (the merge function cannot subtract), not a prompt instruction.
`src/llm.js:parseReview()` is the second half: model output is validated against
fixed enums (`ASSESSMENTS`, `SEVERITIES`) and anything unexpected is dropped.

**Nothing runs without consent.** `src/index.js:confirm()` has two modes. For a
normal verdict, `--yes` skips the prompt. For a `suspicious` verdict, `dangerous`
is true, `--yes` is ignored (see the `if (yes && !dangerous)` guard), and the
user must type the literal word `run`. Muscle-memory `y` must not be able to
approve the one case that matters.

## 3. Module map

All paths are relative to the repo root. Every module is ESM (`"type": "module"`).

| File | Responsibility | Key exports |
|---|---|---|
| `src/index.js` | CLI entry (`bin: sx`). Parses argv, dispatches `scan`/`diff`/run, prompts, sets exit codes. | `main()`, `runDiff()`, `confirm()`, `runNpx()`, `flagValue()` (all module-local) |
| `src/registry.js` | The only npm-aware module: packument fetch, version resolution, download stats, tarball download + gunzip. | `parseSpec(spec)`, `fetchPackage(spec)`, `fetchVersionList(name)` |
| `src/tar.js` | In-memory ustar/GNU tar reader. Regular files only; handles `L` long names, skips PAX/dirs/symlinks. | `parseTar(buf)` |
| `src/analyze.js` | All scoring heuristics: metadata, install hooks, binaries, per-file source scan, tier weighting, dedup, trust dampener, verdict. | `analyze(pkg)`, `VERDICTS` |
| `src/reachability.js` | Classifies each file as install / runtime / inert by walking the local `require`/`import` graph from hook and manifest entry points. | `classifyFiles(manifest, files)`, `TIER`, `TIER_WEIGHT` |
| `src/typosquat.js` | Offline typosquat check against an embedded 132-name popular-package list. | `typosquatTarget(name)`, `editDistance(a, b)`, `POPULAR` |
| `src/card.js` | ANSI box rendering for both pipelines. No color library. | `renderCard(report)`, `renderDiffSummary(result, review, llmEnabled)` |
| `src/cache.js` | Bounded on-disk report cache keyed by resolved `name@version` (immutable on npm, so hits are always valid). Used by the MCP server only. | `cacheGet(key)`, `cacheSet(key, report)`, `cachePath`, `cacheExists()` |
| `src/mcp.js` | MCP stdio server (`bin: sx-mcp`). Hand-rolled JSON-RPC 2.0 loop exposing `scan_package` / `scan_packages`. | none (executable; `TOOLS`, `handle()`, `callTool()` are module-local) |
| `src/diff.js` | Fetches two versions, hashes files to find changes, ranks them install-first, renders a byte-budgeted diff bundle. | `diffVersions(spec, fromVersion, toVersion)`, `renderDiff(result, opts)` |
| `src/linediff.js` | Minimal LCS line diff with prefix/suffix trimming and a size guard. | `diffLines(before, after)`, `toUnified(ops, opts)` |
| `src/llm.js` | Optional OpenAI-compatible diff review, strict output parsing, one-way merge. | `llmConfig(env)`, `isConfigured(env)`, `reviewDiff(diffResult, renderedDiff, opts)`, `parseReview(text)`, `mergeReview(report, review)` |

Note: `sx diff` does two things, not one. It renders the structural diff, and it
also scans the *target* version and folds any model review into that report via
`mergeReview()` — because the question a user actually has is "is the version I
am about to install safe", not merely "what changed". The merged verdict is
printed on the last line of the diff card and drives the exit code.

## 4. Data flow: `sx scan <pkg>`

```
argv ──► src/index.js:main()
          │  parseSpec("react@18.2.0") ─► { name:"react", range:"18.2.0" }
          ▼
     src/registry.js:fetchPackage(spec)
          │
          ├─► GET registry.npmjs.org/<name>            (packument, 3 retries, 404 = permanent)
          ├─► resolve dist-tags[range] ?? versions[range]
          ├─► GET api.npmjs.org/.../last-week/<name>   (best-effort, null on failure)
          └─► GET manifest.dist.tarball ──► gunzipSync ──► src/tar.js:parseTar()
          │                                                    │
          ▼                                                    ▼
        pkg object  { name, version, manifest, files[], ... }
          │
          ▼
     src/analyze.js:analyze(pkg)
          │
          ├─ metadata      typosquatTarget() · age · release freshness ·
          │                maintainers · README · downloads    → kind:"reputation"
          ├─ manifest      preinstall/install/postinstall       → kind:"behavior"
          ├─ tarball       BINARY_EXTENSIONS scan               → kind:"behavior"
          ├─ tiers         src/reachability.js:classifyFiles()  → Map<path, TIER>
          ├─ per-file      scanSource() over TEXT_EXTENSIONS,
          │                severity × TIER_WEIGHT[tier]         → kind:"behavior"
          ├─ dedup         max 2 findings per normalized title
          ├─ trust         age > 1y + downloads ⇒ 0.4 … 0.8 multiplier
          └─ score         Σ severity × (freshRelease && behavior ? 1 : trust)
          │                verdict = ≥50 suspicious | ≥20 caution | low-risk
          ▼
        report object
          │
          ├─ --json ─► JSON.stringify(report) ─► exit 3 if suspicious else 0
          └─ else   ─► src/card.js:renderCard(report)
                          │
                          ├─ scan mode ─► exit 3 if suspicious else 0
                          └─ run mode  ─► confirm() ─► runNpx() (spawn npx --yes)
```

Numbered, with the exact call sites:

1. **argv parse** — `src/index.js:main()` slices `process.argv`, detects the
   `diff` subcommand, then `scan`, then extracts `--json` / `--yes` and the
   positional spec. Everything after the spec is passthrough args for `npx`.
2. **Spec split** — `src/registry.js:parseSpec()` splits on the *last* `@` so
   `@scope/name@1.0.0` works; no `@` means range `"latest"`.
3. **Packument fetch** — `getJson()` in `src/registry.js`, 3 attempts with a
   400ms×n backoff. A 404 is thrown immediately with `permanent: true` because
   "this package does not exist" is an answer, not a transient failure.
4. **Version resolution** — `dist-tags[range]` first (handles `latest`, `next`),
   falling back to an exact `versions[range]` match. Unresolvable ranges throw.
5. **Download stats** — `api.npmjs.org` last-week point stat in a bare
   `try`/`catch`; scoped packages routinely 404 here and that must not fail a
   scan. Result is `null` — the scoring path treats that as "unknown", not "zero".
6. **Tarball + gunzip** — `fetch(manifest.dist.tarball)` → `Buffer` →
   `gunzipSync` from `node:zlib`.
7. **Tar parse** — `src/tar.js:parseTar()` walks 512-byte blocks, reads the
   octal size field at offset 124, collects typeflag `0`/`\0` entries as
   `{ name, size, data }`, and stops at the first all-zero block.
8. **Classify files** — `src/reachability.js:classifyFiles(manifest, files)`
   seeds install-tier from `node <file>` occurrences in the install hooks
   (`ENTRY_FROM_NODE`), seeds runtime-tier from `main`/`module`/`bin`/`exports`,
   BFS-walks each seed set through `REQUIRE_OR_IMPORT` matches resolved by
   `resolveLocal()`, then labels leftovers `inert` if they match `INERT_PATH`
   (`test/`, `examples/`, `docs/`, …) and `runtime` otherwise. Install wins ties.
9. **Run heuristics** — per-file work goes through `scanSource()`, which skips
   `BUNDLE_PATH` (minified/`dist/` output is near-zero signal, constant noise)
   and flags `eval()`, `new Function()`, large base64/hex blobs, and the
   exfiltration combinations (env+network = 15, plus child_process = 25). The
   caller then stamps `tier` and multiplies severity by `TIER_WEIGHT[tier]`
   (install 1.5×, runtime 1×, inert 0.25×).
10. **Score** — findings are sorted by severity and deduped to 2 per normalized
    title (paths stripped from the key, so one pattern across 40 files does not
    swamp the card). `rawScore` is the plain sum; `trust` discounts by install
    base; `freshRelease` (version < 72h old) exempts `kind: "behavior"` findings
    from that discount, so popularity cannot hide a compromised release.
11. **Render** — `renderCard()` draws a 74-column box with the verdict, facts
    row, and findings carrying `[install-time]` / `[test/example]` badges. Exit
    code: `0` ok, `2` analysis threw, `3` suspicious.

The CLI scan path does **not** touch `src/cache.js`; only the MCP server caches.

## 5. Data flow: `sx diff <pkg>`

```
argv ──► src/index.js:runDiff()
          ├─ fetchPackage(spec).version                    → target
          └─ --from X, else fetchVersionList(name) sorted by publish time,
             take the entry before target (exit 2 if none)
          ▼
     src/diff.js:diffVersions(name, from, to)
          ├─ fetchPackage × 2 in parallel
          ├─ classifyFiles(after.manifest, after.files)
          ├─ per path: sha256 compare  → added | modified | removed
          │            IGNORED skips CHANGELOG/LICENSE/*.md/package-lock.json
          ├─ sort by rank(): install(0) < runtime(1) < inert(2), added −0.5
          └─ scriptChanges · addedDeps · maintainersBefore/After
          ▼
     src/diff.js:renderDiff(result, { budget: 40_000 })
          ├─ script changes / new deps / maintainer changes first
          ├─ added files: first 6000 bytes verbatim
          ├─ modified files: linediff.js diffLines() → toUnified()
          │                  (3 lines context, 400 line cap, 300 char/line cap)
          └─ overflow past budget → "(N further changed file(s) omitted)"
          ▼
     src/llm.js:reviewDiff(result, rendered.text)   ← only if isConfigured()
          ├─ POST {SX_LLM_BASE_URL}/chat/completions, temperature 0, 60s abort
          ├─ diff wrapped in <untrusted_package_diff> markers
          └─ parseReview(text) → { assessment, summary, concerns } | { error }
          ▼
     src/card.js:renderDiffSummary(result, review, isConfigured())
          exit 3 if review?.assessment === "alarming", else 0
```

**Where the LLM sits.** Last stage, and optional. `src/llm.js:isConfigured()`
returns false unless `SX_LLM_API_KEY` is set, in which case `reviewDiff()` is
never called and `renderDiffSummary()` prints a hint instead. `reviewDiff()`
never throws: a non-OK response or an aborted fetch returns `{ error }`, which
the card renders as "model review unavailable". Review is an enhancement, never
a gate — sx must keep working when the provider is down.

**Ordering is a security property, not cosmetics.** `renderDiff()` has a 40KB
budget and truncates. Because `diffVersions()` sorted install-tier and
newly-added files to the front, the bytes spent are the ones a payload would
land in; what falls off the end is the least interesting.

**How `mergeReview()` constrains the model.** Given a heuristic `report` and a
`review`, it:

- maps each concern to a finding with `source: "llm"` and severity
  `low→5 / medium→15 / high→30` (`LLM_SEVERITY_SCORE`);
- adds an assessment bonus (`alarming` +30, `unusual` +10, `routine` +0);
- recomputes a verdict from the raised score, then takes the **higher** of that
  and the heuristic verdict using the `order` rank map — so the heuristic
  verdict is a floor the model cannot push below;
- on `review.error`, returns the report untouched with `llm: { error }`.

There is no code path in which a model response removes a finding or lowers a
verdict. `test/llm.test.js` pins this with a prompt-injection case ("a
compromised model output CANNOT lower a suspicious verdict").

## 6. Key data structures

```js
// ─── pkg — returned by src/registry.js:fetchPackage(spec) ───────────────
{
  name: "express",                  // string, as given (scope included)
  version: "4.18.2",                // resolved concrete version, never a range
  manifest: { /* packument.versions[version] — scripts, bin, main, exports,
                 dependencies, dist, … straight from the registry */ },
  files: [                          // src/tar.js:parseTar() output
    { name: "package/index.js",     // tar entry name, "package/" prefix intact
      size: 1234,                   // octal header size field
      data: Buffer }                // raw bytes; never executed
  ],
  weeklyDownloads: 30_000_000,      // number | null  (null = unknown, not zero)
  createdAt: "2010-12-29T19:38:25.450Z",   // ISO string | null — first publish
  versionPublishedAt: "2022-10-08T…",      // ISO string | null — this version
  maintainers: [{ name: "dougwilson", email: "…" }],  // [] if absent
  readme: "# express\n…"            // string | null
}
```

```js
// ─── report — returned by src/analyze.js:analyze(pkg) ───────────────────
{
  verdict: "caution",        // "low-risk" | "caution" | "suspicious" (VERDICTS)
  score: 24,                 // trust-adjusted sum; ≥50 suspicious, ≥20 caution
  rawScore: 40,              // undiscounted Σ severity — what the card shows
                             //   as "(raw N, discounted for proven install base)"
  trust: 0.6,                // 1 | 0.8 | 0.6 | 0.4 — install-base dampener
  freshRelease: false,       // version published < 72h ago; when true, findings
                             //   with kind:"behavior" bypass the trust discount
  findings: [ /* finding[], sorted by severity desc, ≤2 per normalized title */ ],
  facts: {
    name: "express",
    version: "4.18.2",
    created: "2010-12-29T…",         // ISO | null
    published: "2022-10-08T…",       // ISO | null
    weeklyDownloads: 30_000_000,     // number | null
    maintainers: 2,                  // count, not the array
    dependencies: 31,                // count of manifest.dependencies keys
    fileCount: 16,                   // tar entries
    installHooks: ["postinstall"]    // subset of pre/install/postinstall present
  }
}
```

```js
// ─── finding — built by finding() / behavior() in src/analyze.js ────────
{
  severity: 25,              // number; already multiplied by TIER_WEIGHT[tier]
                             //   for per-file findings
  title: "Runs a postinstall script on install",   // one line, shown on the card
  detail: "\"node install.js\"; runs at install time",  // string | null, dimmed
  kind: "behavior",          // "reputation" (ambient: age, downloads, README)
                             //   | "behavior" (what the shipped code does).
                             //   Only "reputation" is discounted by trust in a
                             //   fresh release — see analyze():isDiscounted.
  tier: "install",           // "install" | "runtime" | "inert" — present only on
                             //   findings produced by scanSource(); undefined for
                             //   metadata/manifest findings
  source: "llm"              // present ONLY on findings added by
                             //   src/llm.js:mergeReview(); heuristic findings
                             //   have no source field
}
```

## 7. The MCP server

`src/mcp.js` is a second executable (`bin: sx-mcp`) that wraps `analyze()` for
coding agents. The wire format is newline-delimited JSON-RPC 2.0 over stdio.

**The loop.** `process.stdin` is set to `utf8` and accumulated into `buffer`. On
each `data` event the buffer is drained line by line: each complete line is
`JSON.parse`d (a parse failure emits `-32700` and continues — one bad line must
not kill the server) and passed to `handle(request)`. `handle()` switches on
`method`: `initialize` returns `protocolVersion "2024-11-05"` plus `serverInfo`;
`tools/list` returns the static `TOOLS` array; `tools/call` awaits `callTool()`;
`ping` returns `{}`. Anything else gets `-32601`. Requests with no `id` are
notifications (`notifications/initialized`) and get **no** response at all,
including on error — `isNotification` guards every return path.

Errors inside `tools/call` are deliberately *not* protocol errors: they come
back as a normal result with `isError: true` and the message in the text
content, so the agent reads "sx scan failed: …" and can react rather than
seeing an opaque transport failure.

**Why hand-rolled.** Using the MCP SDK would mean a dependency tree inside a
tool whose entire premise is that dependency trees are dangerous. The protocol
surface sx needs is four methods and a fixed tool list; that is cheaper to write
than to justify.

**In-flight tracking.** Scans are network-bound and can easily outlive a client
closing the pipe. `track(promise)` adds every `handle()` promise to the
`inFlight` set and removes it in `finally`; the `end` handler sets
`stdinClosed = true` and exits only if `inFlight.size === 0`, otherwise the last
promise to settle triggers `process.exit(0)`. Without this, a client that writes
a request and closes stdin gets no answer.

**Caching.** `scanOne()` is the only caller of `src/cache.js`. The key is the
*resolved* `name@version` (so it is computed after `fetchPackage`, not from the
user's spec), which is immutable on npm — a hit is always valid. The store is
JSON at `~/.sx-cache/reports.json` (override the parent with `SX_CACHE_DIR`),
capped at 500 entries with a 7-day TTL, and every write is wrapped in a
swallowing `try` — a cache that cannot write is still a working tool.

## 8. Testing strategy

**Unit tests** (`npm test` → `node --test`, no runner to install):

| File | Protects |
|---|---|
| `test/tar.test.js` | `parseTar()` against a hand-built archive and an empty buffer — the parser everything else stands on. |
| `test/analyze.test.js` | Scoring semantics: install hooks raise the score, minified bundles do *not* trip obfuscation heuristics, popularity discounts reputation findings but **not** dangerous code in a fresh release, typosquat and `parseSpec` behavior. |
| `test/reachability.test.js` | Tier assignment: hook entry points are install-tier, the tier propagates through local `require`/`import`, bare specifiers are not resolved, `test/`/`examples/` are inert, and the same payload scores far lower as a fixture than at install time. |
| `test/llm.test.js` | The security model: injection cannot lower a verdict, the model *can* raise one, malformed output becomes an error rather than a verdict, unknown enum values are normalized, provider failures degrade gracefully. Also covers `linediff.js`. |
| `test/mcp.test.js` | The JSON-RPC loop end to end by spawning `src/mcp.js`: handshake, notifications get no reply, malformed lines survive, a nonexistent package returns an error result rather than a crash. |

Only `test/mcp.test.js` reaches the real network (it scans a live package). The
transport tests in `test/llm.test.js` stand up a loopback `node:http` server via
`mockProvider()` instead of calling a provider, so everything else is offline
and deterministic.

**Recall benchmark** (`npm run bench:recall` → `bench/true-positives.js`). Ten
synthetic `pkg` objects modeled on documented attack patterns — Shai-Hulud-style
postinstall env exfiltration, hex/base64-packed payloads, `node -e` install
one-liners, credential file readers, a compromised-maintainer release of an
established package. They are inert fixtures with dead `.invalid` URLs and no
working payloads; they exist only to prove the heuristics fire. Target >90%
suspicious, exits non-zero below it. It builds `pkg` objects directly and needs
no network, so **it gates every PR** in `.github/workflows/ci.yml`.

**False-positive benchmark** (`npm run bench:fp` → `bench/false-positives.js`).
Scans all 132 real packages in `POPULAR` from `src/typosquat.js` at concurrency
8 and reports the verdict distribution. Target <2% suspicious; exits non-zero at
or above it. **It is not a PR gate** (`if: github.event_name != 'pull_request'`)
for two reasons: it makes ~400 live registry requests, so it is slow and fails
on rate limits and network flakes unrelated to the change under review; and its
corpus drifts as real packages gain install hooks and change maintainers.
Gating PRs on it would train people to ignore red CI. It runs on `main`, on
demand, and weekly via `.github/workflows/weekly-benchmark.yml`, which uploads
the output as an artifact so precision regressions surface as an issue rather
than as a user quietly losing trust. A regression there is a release blocker.

## 9. Extension points

**Add a heuristic.** Two places, depending on kind.

- *Reputation / manifest-level* (age, maintainers, a new manifest red flag):
  add a `findings.push(finding(severity, title, detail))` in the metadata
  section of `src/analyze.js:analyze()`, before the tarball block. Reputation
  findings are subject to the `trust` discount.
- *Per-file behavior*: add a regex + `findings.push(behavior(...))` inside
  `src/analyze.js:scanSource(path, text, findings)`. It runs for every file
  matching `TEXT_EXTENSIONS` under 2MB; the caller stamps `tier` and applies
  `TIER_WEIGHT` afterwards — do not multiply by tier yourself. Respect the
  `BUNDLE_PATH` early return. If your title embeds a path, keep it in `(...)`
  or `in <path>` form so the dedup key normalizer in `analyze()` strips it.
- Either way: add a sample to `bench/true-positives.js` proving it fires, and
  run `npm run bench:fp` to prove it cost no precision. Both numbers go in the PR.

**Add a file tier.** Four coordinated edits: add the constant to `TIER` and a
multiplier to `TIER_WEIGHT` in `src/reachability.js`; add the seeding or
labelling rule inside `classifyFiles()` (note the "install wins ties" rule in
`walk()`); add a badge for it in `src/card.js:renderCard()` next to the existing
`install` / `inert` cases; and add it to `rank()` in `src/diff.js:diffVersions()`
so diff ordering knows where it belongs. `renderDiff()` also special-cases
`TIER.INSTALL` for its `[RUNS AT INSTALL TIME]` tag.

**Add a registry (PyPI).** `src/registry.js` is the only npm-aware module by
design. Write `src/pypi.js` exporting a `fetchPackage(spec)` that returns the
same `pkg` shape (§6) — resolve the version from the JSON API, download the
sdist/wheel, and feed it through a reader that emits `{ name, size, data }`
entries; `parseTar()` works as-is for `.tar.gz`, a wheel needs a zip reader
(`node:zlib` inflate, still stdlib). Then dispatch on the spec in
`src/index.js:main()`. Two downstream modules carry npm assumptions: `analyze()`
reads `manifest.scripts.{pre,}install` and matches `TEXT_EXTENSIONS`
(`.js/.ts/.json/.sh/…`), and `classifyFiles()` resolves
`main`/`module`/`bin`/`exports` plus Node `require`/`import` syntax. Keep
`analyze()` generic and move the ecosystem-specific hook and entry-point
extraction behind an argument.

**Add an LLM provider.** If it speaks the OpenAI chat-completions shape —
Gemini, Groq, Together, OpenRouter, llama.cpp, Ollama all do — nothing needs
changing: set `SX_LLM_BASE_URL` and `SX_LLM_MODEL`. For a provider with a
different request/response shape, the only function to touch is
`src/llm.js:reviewDiff()`: swap the `fetch` URL, headers, and body, and extract
the text from wherever that provider puts it, then hand it to `parseReview()`
unchanged. `llmConfig()` is where new env vars belong. Do not touch
`parseReview()` or `mergeReview()` to accommodate a provider — those two
functions are the security boundary, and every provider's output must pass
through the same validation and the same one-way merge.
