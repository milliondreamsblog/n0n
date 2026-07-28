import { gunzipSync } from "node:zlib";
import { parseTar } from "./tar.js";

const REGISTRY = "https://registry.npmjs.org";
const DOWNLOADS_API = "https://api.npmjs.org/downloads/point/last-week";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getJson(url, attempts = 3) {
  let lastError;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, { headers: { accept: "application/json" } });
      if (res.ok) return res.json();
      // 404 is a real answer (package/stats don't exist) — don't retry it.
      if (res.status === 404) {
        throw Object.assign(new Error(`${url} responded 404`), { permanent: true });
      }
      lastError = new Error(`${url} responded ${res.status} ${res.statusText}`);
    } catch (err) {
      if (err.permanent) throw err;
      lastError = err;
    }
    await sleep(400 * (i + 1));
  }
  throw lastError;
}

/** Split "name@version" / "@scope/name@version" into { name, range }. */
export function parseSpec(spec) {
  const at = spec.lastIndexOf("@");
  if (at > 0) {
    return { name: spec.slice(0, at), range: spec.slice(at + 1) };
  }
  return { name: spec, range: "latest" };
}

/**
 * Fetch everything sx needs to judge a package:
 * registry metadata, weekly downloads, and the extracted tarball contents.
 */
export async function fetchPackage(spec) {
  const { name, range } = parseSpec(spec);
  const packument = await getJson(`${REGISTRY}/${encodeURIComponent(name).replace("%2F", "/")}`);

  const version =
    packument["dist-tags"]?.[range] ??
    (packument.versions?.[range] ? range : null);
  if (!version || !packument.versions?.[version]) {
    throw new Error(`version "${range}" not found for ${name}`);
  }
  const manifest = packument.versions[version];

  let weeklyDownloads = null;
  try {
    const dl = await getJson(`${DOWNLOADS_API}/${name}`);
    weeklyDownloads = dl.downloads ?? null;
  } catch {
    // downloads API is best-effort; scoped-package stats sometimes 404
  }

  const tarballRes = await fetch(manifest.dist.tarball);
  if (!tarballRes.ok) {
    throw new Error(`tarball download failed: ${tarballRes.status}`);
  }
  const gz = Buffer.from(await tarballRes.arrayBuffer());
  const files = parseTar(gunzipSync(gz));

  return {
    name,
    version,
    manifest,
    files,
    weeklyDownloads,
    createdAt: packument.time?.created ?? null,
    versionPublishedAt: packument.time?.[version] ?? null,
    maintainers: packument.maintainers ?? [],
    readme: packument.readme ?? null,
  };
}
