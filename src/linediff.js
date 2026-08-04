// Minimal LCS line diff. Stdlib only, like everything else here.

/** Longest-common-subsequence table walk producing +/-/space line ops. */
export function diffLines(before, after) {
  const a = before.split("\n");
  const b = after.split("\n");

  // Trim common prefix/suffix first — most edits touch a few lines, and the
  // O(n*m) table is only affordable on what actually differs.
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let endA = a.length;
  let endB = b.length;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) {
    endA--;
    endB--;
  }

  const midA = a.slice(start, endA);
  const midB = b.slice(start, endB);

  // Guard against pathological inputs (minified single-line files, huge
  // rewrites): fall back to a whole-block replace rather than allocating
  // a giant table.
  if (midA.length * midB.length > 4_000_000) {
    return [
      ...midA.map((line) => ({ op: "-", line })),
      ...midB.map((line) => ({ op: "+", line })),
    ];
  }

  const m = midA.length;
  const n = midB.length;
  const lcs = Array.from({ length: m + 1 }, () => new Uint32Array(n + 1));
  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      lcs[i][j] =
        midA[i] === midB[j]
          ? lcs[i + 1][j + 1] + 1
          : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }

  const ops = [];
  let i = 0;
  let j = 0;
  while (i < m && j < n) {
    if (midA[i] === midB[j]) {
      ops.push({ op: " ", line: midA[i] });
      i++;
      j++;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      ops.push({ op: "-", line: midA[i++] });
    } else {
      ops.push({ op: "+", line: midB[j++] });
    }
  }
  while (i < m) ops.push({ op: "-", line: midA[i++] });
  while (j < n) ops.push({ op: "+", line: midB[j++] });
  return ops;
}

/** Render ops as a unified-style hunk list with limited context. */
export function toUnified(ops, { context = 3, maxLines = 400 } = {}) {
  const keep = new Set();
  ops.forEach((op, idx) => {
    if (op.op === " ") return;
    for (let k = Math.max(0, idx - context); k <= Math.min(ops.length - 1, idx + context); k++) {
      keep.add(k);
    }
  });

  const out = [];
  let lastKept = -1;
  for (let idx = 0; idx < ops.length && out.length < maxLines; idx++) {
    if (!keep.has(idx)) continue;
    if (lastKept !== -1 && idx > lastKept + 1) out.push("@@");
    const { op, line } = ops[idx];
    // Truncate very long lines (minified code) so one line can't eat the budget
    out.push(op + (line.length > 300 ? `${line.slice(0, 300)}…` : line));
    lastKept = idx;
  }
  if (out.length >= maxLines) out.push("… diff truncated …");
  return out.join("\n");
}
