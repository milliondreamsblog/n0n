#!/usr/bin/env node
// MCP server exposing sx to coding agents over stdio.
//
// Implements the JSON-RPC 2.0 / MCP wire protocol directly rather than using
// the SDK — sx has zero runtime dependencies by design, and a security tool
// adding a dependency tree to describe itself to agents would be absurd.
import { fetchPackage, parseSpec } from "./registry.js";
import { analyze } from "./analyze.js";
import { cacheGet, cacheSet } from "./cache.js";

const PROTOCOL_VERSION = "2024-11-05";

const TOOLS = [
  {
    name: "scan_package",
    description:
      "Analyze an npm package for supply-chain risk BEFORE installing or " +
      "running it. Returns a verdict (low-risk | caution | suspicious), a " +
      "risk score, and specific findings. Call this before `npm install`, " +
      "`npx`, or adding any unfamiliar dependency. A 'suspicious' verdict " +
      "means do not install without asking the user first.",
    inputSchema: {
      type: "object",
      properties: {
        package: {
          type: "string",
          description:
            "Package spec, e.g. 'express', 'react@18.2.0', '@scope/name'. " +
            "Defaults to the latest version.",
        },
      },
      required: ["package"],
    },
  },
  {
    name: "scan_packages",
    description:
      "Analyze several npm packages at once for supply-chain risk. Use when " +
      "evaluating a list of candidate dependencies. Returns one verdict per " +
      "package plus a summary of which ones need attention.",
    inputSchema: {
      type: "object",
      properties: {
        packages: {
          type: "array",
          items: { type: "string" },
          description: "Package specs to scan (max 20).",
        },
      },
      required: ["packages"],
    },
  },
];

async function scanOne(spec) {
  const { name } = parseSpec(spec);
  const pkg = await fetchPackage(spec);
  const key = `${pkg.name}@${pkg.version}`;
  const cached = cacheGet(key);
  if (cached) return cached;
  const report = analyze(pkg);
  cacheSet(key, report);
  return report;
}

function summarize(report) {
  const lines = [
    `${report.facts.name}@${report.facts.version} — ${report.verdict.toUpperCase()} (score ${report.score})`,
    `downloads/week: ${report.facts.weeklyDownloads ?? "unknown"}, ` +
      `maintainers: ${report.facts.maintainers}, ` +
      `install hooks: ${report.facts.installHooks.length ? report.facts.installHooks.join(", ") : "none"}`,
  ];
  if (report.findings.length > 0) {
    lines.push("findings:");
    for (const f of report.findings) {
      lines.push(`  - [${f.kind}] ${f.title}${f.detail ? ` (${f.detail})` : ""}`);
    }
  } else {
    lines.push("findings: none");
  }
  if (report.verdict === "suspicious") {
    lines.push(
      "ACTION: do not install or run this package without explicit user approval.",
    );
  }
  return lines.join("\n");
}

async function callTool(name, args) {
  if (name === "scan_package") {
    const report = await scanOne(String(args?.package ?? ""));
    return {
      content: [{ type: "text", text: summarize(report) }],
      structuredContent: report,
      isError: false,
    };
  }

  if (name === "scan_packages") {
    const specs = (args?.packages ?? []).slice(0, 20).map(String);
    const results = await Promise.all(
      specs.map(async (spec) => {
        try {
          return { spec, report: await scanOne(spec) };
        } catch (err) {
          return { spec, error: err.message };
        }
      }),
    );
    const flagged = results.filter((r) => r.report && r.report.verdict !== "low-risk");
    const text = [
      `Scanned ${results.length} package(s). ${flagged.length} need attention.`,
      "",
      ...results.map((r) =>
        r.error
          ? `${r.spec} — SCAN FAILED (${r.error})`
          : summarize(r.report),
      ),
    ].join("\n\n");
    return {
      content: [{ type: "text", text }],
      structuredContent: { results },
      isError: false,
    };
  }

  throw new Error(`unknown tool: ${name}`);
}

// --- JSON-RPC plumbing -----------------------------------------------------

function send(message) {
  process.stdout.write(JSON.stringify(message) + "\n");
}

function respond(id, result) {
  send({ jsonrpc: "2.0", id, result });
}

function respondError(id, code, message) {
  send({ jsonrpc: "2.0", id, error: { code, message } });
}

async function handle(request) {
  const { id, method, params } = request;
  // Notifications have no id and must never get a response.
  const isNotification = id === undefined || id === null;

  try {
    switch (method) {
      case "initialize":
        return respond(id, {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: "sx", version: "0.1.0" },
        });

      case "tools/list":
        return respond(id, { tools: TOOLS });

      case "tools/call": {
        const result = await callTool(params?.name, params?.arguments);
        return respond(id, result);
      }

      case "ping":
        return respond(id, {});

      default:
        if (isNotification) return; // e.g. notifications/initialized
        return respondError(id, -32601, `method not found: ${method}`);
    }
  } catch (err) {
    if (isNotification) return;
    // Tool failures are reported as results with isError, not protocol errors,
    // so the agent sees the message and can react rather than just failing.
    if (method === "tools/call") {
      return respond(id, {
        content: [{ type: "text", text: `sx scan failed: ${err.message}` }],
        isError: true,
      });
    }
    return respondError(id, -32603, err.message);
  }
}

// Scans are async and can outlive the client closing stdin. Track in-flight
// work so a closed pipe drains pending responses instead of dropping them.
const inFlight = new Set();
let stdinClosed = false;

function track(promise) {
  inFlight.add(promise);
  promise.finally(() => {
    inFlight.delete(promise);
    if (stdinClosed && inFlight.size === 0) process.exit(0);
  });
}

let buffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  let newline;
  while ((newline = buffer.indexOf("\n")) !== -1) {
    const line = buffer.slice(0, newline).trim();
    buffer = buffer.slice(newline + 1);
    if (!line) continue;
    let request;
    try {
      request = JSON.parse(line);
    } catch {
      respondError(null, -32700, "parse error");
      continue;
    }
    track(handle(request));
  }
});
process.stdin.on("end", () => {
  stdinClosed = true;
  if (inFlight.size === 0) process.exit(0);
});
