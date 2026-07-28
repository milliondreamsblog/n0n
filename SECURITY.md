# Security Policy

## What sx is, and what it is not

sx is a **heuristic risk signal**, not a guarantee. It reduces the chance that
you run something harmful; it cannot eliminate it.

- A `low-risk` verdict means *no known-suspicious patterns were found*. It does
  not mean the package is safe. A sufficiently careful attacker can defeat
  static heuristics.
- A `suspicious` verdict means *patterns associated with past attacks were
  found*. Legitimate packages do trigger it. It is a prompt to look closer, not
  a verdict about the author's intent.
- sx never labels a package "malicious" — see CONTRIBUTING.md for why.

Do not build a security control that assumes sx is authoritative.

## Reporting a vulnerability in sx itself

If you find a flaw in sx — for example a way to make a crafted tarball crash
the scanner, cause it to execute package code during analysis, or suppress
findings — please report it privately:

1. Open a [private security advisory](https://github.com/milliondreamsblog/n0n/security/advisories/new)
   on GitHub, or
2. Email the maintainers if you cannot use advisories.

Please do not open a public issue for these. Expect an initial response within
7 days.

### Especially interesting classes of bug

sx parses hostile input by design — tarballs from strangers. The following are
in scope and valued:

- **Analysis-time code execution.** sx must never run package code. It reads
  bytes and matches patterns; it never `require`s, evals, or executes anything
  from a scanned package. A path to breaking that invariant is the highest
  severity report possible here.
- **Parser denial of service.** Crafted tar headers or pathological files that
  hang or exhaust memory in `src/tar.js` or the regex heuristics.
- **Detection suppression.** A way to structure a package so that a real
  install-time payload scores `low-risk` — e.g. defeating the reachability
  walker in `src/reachability.js` so dangerous code is misclassified as inert.
- **Cache poisoning.** Anything that lets a scan of package A affect the stored
  report for package B (`src/cache.js`).

## Reporting a malicious package on npm

sx is not a takedown channel. Report the package to npm directly via
`npm@npmjs.com` or the "report malware" link on the package page.

If sx *failed to flag* a package that turned out to be malicious, that is a
false negative — please open a public issue with the version and what it did,
so the heuristics can be improved. Do not attach live payloads; describe them.
