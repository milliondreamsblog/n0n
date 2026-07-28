<!-- Thanks for contributing. Keep PRs focused; separate refactors from
     detection changes so accuracy effects are attributable. -->

## What this changes

<!-- One or two sentences. Why, not just what. -->

## Accuracy impact

If this touches detection logic (`src/analyze.js`, `src/reachability.js`,
`src/typosquat.js`), paste before/after numbers. Baseline is 100% recall,
0.0% false positives.

```
npm run bench:recall   →
npm run bench:fp       →
```

- [ ] Not a detection change, or numbers pasted above
- [ ] New heuristics have a test that triggers them *and* one that must not
- [ ] No runtime or dev dependencies added
- [ ] No verdict stronger than `suspicious` introduced
