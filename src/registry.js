import { gunzipSync } from "node:zlib";
import { parseTar } from "./tar.js";

const REGISTRY = "https://registry.npmjs.org";
const DOWNLOADS_API = "https://api.npmjs.org/downloads/point/last-week";

async function getJson(url) {
  const res = await fetch(url, { headers: { accept: "application/json" } });
  if (!res.ok) {
    throw new Error(`${url} responded ${res.status} ${res.statusText}`);
  }
  return res.json();
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
