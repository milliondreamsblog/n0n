// Tiny on-disk cache keyed by name@version. Agents scan the same packages
// repeatedly; a resolved version is immutable on npm, so a hit is always
// valid. Bounded by entry count, not bytes — reports are ~1-3KB.
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir, homedir } from "node:os";

const DIR = join(process.env.SX_CACHE_DIR ?? homedir() ?? tmpdir(), ".sx-cache");
const FILE = join(DIR, "reports.json");
const MAX_ENTRIES = 500;
const TTL_MS = 7 * 24 * 60 * 60 * 1000;

let store = null;

function load() {
  if (store) return store;
  try {
    store = JSON.parse(readFileSync(FILE, "utf8"));
  } catch {
    store = {};
  }
  return store;
}

function persist() {
  try {
    mkdirSync(DIR, { recursive: true });
    const entries = Object.entries(store);
    if (entries.length > MAX_ENTRIES) {
      entries.sort((a, b) => b[1].at - a[1].at);
      store = Object.fromEntries(entries.slice(0, MAX_ENTRIES));
    }
    writeFileSync(FILE, JSON.stringify(store));
  } catch {
    // A cache that can't write is still a working tool — never fail the scan.
  }
}

export function cacheGet(key) {
  const hit = load()[key];
  if (!hit) return null;
  if (Date.now() - hit.at > TTL_MS) return null;
  return hit.report;
}

export function cacheSet(key, report) {
  load()[key] = { at: Date.now(), report };
  persist();
}

export const cachePath = FILE;
export const cacheExists = () => existsSync(FILE);
