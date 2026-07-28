import { test } from "node:test";
import assert from "node:assert/strict";
import { parseTar } from "../src/tar.js";

// Build a minimal single-file ustar archive by hand.
function tarEntry(name, content) {
  const header = Buffer.alloc(512);
  header.write(name, 0, "utf8");
  header.write("0000644\0", 100); // mode
  header.write("0000000\0", 108); // uid
  header.write("0000000\0", 116); // gid
  header.write(content.length.toString(8).padStart(11, "0") + "\0", 124);
  header.write("00000000000\0", 136); // mtime
  header.write("        ", 148); // checksum placeholder = spaces
  header.write("0", 156); // typeflag: regular file
  header.write("ustar\0", 257);
  let sum = 0;
  for (const byte of header) sum += byte;
  header.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);

  const body = Buffer.alloc(Math.ceil(content.length / 512) * 512);
  Buffer.from(content).copy(body);
  return Buffer.concat([header, body]);
}

test("parses a hand-built archive", () => {
  const archive = Buffer.concat([
    tarEntry("package/index.js", "console.log(1)"),
    tarEntry("package/README.md", "hello"),
    Buffer.alloc(1024), // end-of-archive
  ]);
  const entries = parseTar(archive);
  assert.equal(entries.length, 2);
  assert.equal(entries[0].name, "package/index.js");
  assert.equal(entries[0].data.toString(), "console.log(1)");
  assert.equal(entries[1].name, "package/README.md");
});

test("empty buffer yields no entries", () => {
  assert.deepEqual(parseTar(Buffer.alloc(0)), []);
});
