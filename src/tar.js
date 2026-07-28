// Minimal in-memory ustar/GNU tar reader. sx deliberately has zero runtime
// dependencies — a tool that inspects packages for supply-chain risk should
// not itself pull in a dependency tree.

const BLOCK = 512;

function readString(buf, offset, length) {
  const slice = buf.subarray(offset, offset + length);
  const end = slice.indexOf(0);
  return slice.toString("utf8", 0, end === -1 ? length : end);
}

function readOctal(buf, offset, length) {
  const raw = readString(buf, offset, length).trim();
  if (raw === "") return 0;
  return parseInt(raw, 8) || 0;
}

/**
 * Parse a tar archive buffer into a list of { name, size, data } entries
 * for regular files. Handles GNU long names ('L') and skips PAX headers.
 */
export function parseTar(buf) {
  const entries = [];
  let offset = 0;
  let pendingLongName = null;

  while (offset + BLOCK <= buf.length) {
    const header = buf.subarray(offset, offset + BLOCK);
    // Two consecutive zero blocks mark end-of-archive; one is enough to stop.
    if (header.every((b) => b === 0)) break;

    let name = readString(header, 0, 100);
    const prefix = readString(header, 345, 155);
    if (prefix) name = `${prefix}/${name}`;
    const size = readOctal(header, 124, 12);
    const typeflag = String.fromCharCode(header[156] || 48);
    const dataStart = offset + BLOCK;
    const data = buf.subarray(dataStart, dataStart + size);

    if (typeflag === "L") {
      pendingLongName = data.toString("utf8").replace(/\0+$/, "");
    } else if (typeflag === "0" || typeflag === "\0" || typeflag === "\x00") {
      entries.push({
        name: pendingLongName ?? name,
        size,
        data: Buffer.from(data),
      });
      pendingLongName = null;
    } else {
      // Directories, symlinks, PAX headers ('x'/'g') — irrelevant for scanning.
      pendingLongName = null;
    }

    offset = dataStart + Math.ceil(size / BLOCK) * BLOCK;
  }
  return entries;
}
