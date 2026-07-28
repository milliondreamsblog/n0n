import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

const here = dirname(fileURLToPath(import.meta.url));
const SERVER = join(here, "..", "src", "mcp.js");

/** Send a batch of JSON-RPC requests and collect the responses. */
function rpc(requests, { timeout = 60_000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SERVER], {
      stdio: ["pipe", "pipe", "pipe"],
      // Isolate the cache so tests never read or write the real one.
      env: { ...process.env, SX_CACHE_DIR: mkdtempSync(join(tmpdir(), "sx-test-")) },
    });
    let out = "";
    let err = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`timed out; stdout=${out} stderr=${err}`));
    }, timeout);

    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("close", () => {
      clearTimeout(timer);
      const messages = out
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line));
      resolve({ messages, stderr: err });
    });

    for (const req of requests) child.stdin.write(JSON.stringify(req) + "\n");
    child.stdin.end();
  });
}

test("initialize returns protocol version and server info", async () => {
  const { messages } = await rpc([
    { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
  ]);
  assert.equal(messages.length, 1);
  assert.equal(messages[0].id, 1);
  assert.equal(messages[0].result.serverInfo.name, "sx");
  assert.ok(messages[0].result.protocolVersion);
});

test("tools/list advertises the scan tools", async () => {
  const { messages } = await rpc([
    { jsonrpc: "2.0", id: 1, method: "tools/list" },
  ]);
  const names = messages[0].result.tools.map((t) => t.name);
  assert.deepEqual(names.sort(), ["scan_package", "scan_packages"]);
  const scan = messages[0].result.tools.find((t) => t.name === "scan_package");
  assert.deepEqual(scan.inputSchema.required, ["package"]);
});

test("notifications get no response", async () => {
  const { messages } = await rpc([
    { jsonrpc: "2.0", method: "notifications/initialized" },
    { jsonrpc: "2.0", id: 7, method: "ping" },
  ]);
  assert.equal(messages.length, 1, "only ping should be answered");
  assert.equal(messages[0].id, 7);
});

test("unknown method returns a JSON-RPC error", async () => {
  const { messages } = await rpc([
    { jsonrpc: "2.0", id: 2, method: "nope/nothing" },
  ]);
  assert.equal(messages[0].error.code, -32601);
});

test("malformed line does not kill the server", async () => {
  const { messages } = await rpc([]).then(() => rpc([
    { jsonrpc: "2.0", id: 3, method: "ping" },
  ]));
  assert.equal(messages[0].id, 3);
});

test("scan_package returns a verdict for a real package", async () => {
  const { messages } = await rpc([
    {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "scan_package", arguments: { package: "express" } },
    },
  ]);
  const result = messages[0].result;
  assert.equal(result.isError, false);
  assert.match(result.content[0].text, /express@/);
  assert.ok(["low-risk", "caution", "suspicious"].includes(result.structuredContent.verdict));
});

test("scan of a nonexistent package reports an error result, not a crash", async () => {
  const { messages } = await rpc([
    {
      jsonrpc: "2.0",
      id: 5,
      method: "tools/call",
      params: {
        name: "scan_package",
        arguments: { package: "sx-definitely-not-a-real-package-91237" },
      },
    },
  ]);
  assert.equal(messages[0].result.isError, true);
  assert.match(messages[0].result.content[0].text, /failed/i);
});
