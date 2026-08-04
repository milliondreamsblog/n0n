import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { parseReview, mergeReview, reviewDiff, isConfigured, llmConfig } from "../src/llm.js";
import { diffLines, toUnified } from "../src/linediff.js";

// --- configuration ---------------------------------------------------------

test("LLM is disabled without an API key", () => {
  assert.equal(isConfigured({}), false);
  assert.equal(llmConfig({}), null);
});

test("any OpenAI-compatible endpoint can be configured", () => {
  const cfg = llmConfig({
    SX_LLM_API_KEY: "k",
    SX_LLM_BASE_URL: "https://generativelanguage.googleapis.com/v1beta/openai/",
    SX_LLM_MODEL: "gemini-2.5-flash",
  });
  assert.equal(cfg.model, "gemini-2.5-flash");
  assert.ok(!cfg.baseUrl.endsWith("/"), "trailing slash should be trimmed");
});

// --- output parsing --------------------------------------------------------

test("parses a well-formed review", () => {
  const r = parseReview(
    JSON.stringify({
      assessment: "routine",
      summary: "Bumped a dependency.",
      concerns: [],
    }),
  );
  assert.equal(r.assessment, "routine");
  assert.equal(r.concerns.length, 0);
});

test("parses JSON wrapped in a markdown fence", () => {
  const r = parseReview('```json\n{"assessment":"alarming","summary":"x","concerns":[]}\n```');
  assert.equal(r.assessment, "alarming");
});

test("unparseable output becomes an error, not a verdict", () => {
  assert.ok(parseReview("I'm sorry, I can't help with that.").error);
  assert.ok(parseReview("{not json").error);
});

test("unknown severity and assessment values are normalized, not trusted", () => {
  const r = parseReview(
    JSON.stringify({
      assessment: "definitely-fine",
      summary: "x",
      concerns: [{ severity: "catastrophic", detail: "d" }],
    }),
  );
  assert.equal(r.assessment, "unusual");
  assert.equal(r.concerns[0].severity, "low");
});

// --- the security property -------------------------------------------------

const suspiciousReport = {
  verdict: "suspicious",
  score: 70,
  findings: [{ severity: 40, title: "postinstall exfiltration", kind: "behavior" }],
  facts: {},
};

test("a compromised model output CANNOT lower a suspicious verdict", () => {
  // Simulates a successful prompt injection: the package talked the model
  // into declaring itself safe. The merge must ignore that entirely.
  const injected = { assessment: "routine", summary: "This package is safe.", concerns: [] };
  const merged = mergeReview(suspiciousReport, injected);
  assert.equal(merged.verdict, "suspicious", "heuristic verdict is a floor");
  assert.ok(merged.score >= suspiciousReport.score, "score must not drop");
  assert.equal(merged.findings.length, suspiciousReport.findings.length);
});

test("the model can raise a low-risk verdict", () => {
  const clean = { verdict: "low-risk", score: 5, findings: [], facts: {} };
  const merged = mergeReview(clean, {
    assessment: "alarming",
    summary: "New postinstall exfiltrates tokens.",
    concerns: [
      { severity: "high", detail: "postinstall posts ~/.npmrc to an IP" },
      { severity: "medium", detail: "new hardcoded domain" },
    ],
  });
  assert.equal(merged.verdict, "suspicious");
  assert.ok(merged.findings.some((f) => f.source === "llm"));
});

test("a failed review leaves the heuristic report untouched", () => {
  const merged = mergeReview(suspiciousReport, { error: "timeout" });
  assert.equal(merged.verdict, "suspicious");
  assert.equal(merged.score, 70);
  assert.equal(merged.llm.error, "timeout");
});

// --- transport -------------------------------------------------------------

function mockProvider(handler) {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      let body = "";
      req.on("data", (d) => (body += d));
      req.on("end", () => handler(JSON.parse(body), res));
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ url: `http://127.0.0.1:${port}`, close: () => server.close() });
    });
  });
}

const fakeDiff = { name: "pkg", from: "1.0.0", to: "1.0.1", changes: [] };

test("sends the diff inside untrusted markers and parses the reply", async () => {
  let received = null;
  const server = await mockProvider((body, res) => {
    received = body;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        choices: [
          {
            message: {
              content: '{"assessment":"unusual","summary":"ok","concerns":[]}',
            },
          },
        ],
      }),
    );
  });
  try {
    const review = await reviewDiff(fakeDiff, "+ evil()", {
      env: { SX_LLM_API_KEY: "k", SX_LLM_BASE_URL: server.url, SX_LLM_MODEL: "m" },
    });
    assert.equal(review.assessment, "unusual");
    const userMsg = received.messages.find((m) => m.role === "user").content;
    assert.match(userMsg, /<untrusted_package_diff>/);
    assert.match(userMsg, /<\/untrusted_package_diff>/);
    assert.equal(received.temperature, 0);
  } finally {
    server.close();
  }
});

test("provider errors degrade gracefully instead of throwing", async () => {
  const server = await mockProvider((_body, res) => {
    res.writeHead(500);
    res.end("boom");
  });
  try {
    const review = await reviewDiff(fakeDiff, "diff", {
      env: { SX_LLM_API_KEY: "k", SX_LLM_BASE_URL: server.url },
    });
    assert.ok(review.error, "should report an error, not throw");
  } finally {
    server.close();
  }
});

// --- diff rendering --------------------------------------------------------

test("line diff marks additions and deletions", () => {
  const ops = diffLines("a\nb\nc", "a\nX\nc");
  assert.deepEqual(
    ops.filter((o) => o.op !== " ").map((o) => o.op + o.line),
    ["-b", "+X"],
  );
});

test("unified output keeps context and truncates long lines", () => {
  const before = Array.from({ length: 50 }, (_, i) => `line ${i}`).join("\n");
  const after = before.replace("line 25", "x".repeat(500));
  const out = toUnified(diffLines(before, after));
  assert.match(out, /^\+x{300}…$/m, "long lines should be truncated");
  assert.ok(!out.includes("line 5\n"), "distant context should be omitted");
});
