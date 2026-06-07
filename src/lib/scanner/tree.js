/**
 * Site map / "Sources" tree.
 *
 * Single responsibility: build a tree of the files/paths a site exposes, from
 * three published sources — robots.txt (Disallow/Allow + Sitemap refs),
 * sitemap.xml (<loc> URLs), and every resource the homepage references
 * (src/href/srcset: scripts, styles, images, iframes, links). Results are
 * grouped by host (like DevTools "Sources"). PASSIVE and static: bodies are read
 * as text under a hard size cap and parsed by regex — nothing is executed and no
 * real filesystem is enumerated. Failures collapse into { ok:false }.
 */

import { readCappedText } from "./http.js";

const MAX_BYTES = 3_000_000;
const MAX_ENTRIES = 400;
const UA = "Vantasec-Scanner/0.1 (+security self-audit)";

/**
 * GET a text resource (capped), returning its text or throwing.
 * @param {string} url @param {number} timeout @returns {Promise<string>}
 */
async function getText(url, timeout) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, { redirect: "follow", signal: controller.signal, headers: { "user-agent": UA } });
    if (!res.ok) throw new Error(`status ${res.status}`);
    return await readCappedText(res, MAX_BYTES);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Normalize a path: drop query/fragment and wildcard segments, ensure leading /.
 * @param {string} p @returns {string}
 */
function cleanPath(p) {
  let out = String(p).split("?")[0].split("#")[0].trim();
  if (!out) return "";
  if (!out.startsWith("/")) out = `/${out}`;
  return out.replace(/\*+/g, "").replace(/\/{2,}/g, "/");
}

/**
 * Yield every resource URL referenced in the HTML (src/href/srcset).
 * @param {string} html
 * @returns {Generator<string>}
 */
function* resourceUrls(html) {
  for (const m of html.matchAll(/(?:src|href)\s*=\s*["']([^"']+)["']/gi)) yield m[1];
  for (const m of html.matchAll(/srcset\s*=\s*["']([^"']+)["']/gi)) {
    for (const part of m[1].split(",")) {
      const u = part.trim().split(/\s+/)[0];
      if (u) yield u;
    }
  }
}

/**
 * Build a site map grouped by host.
 *
 * @param {string} baseUrl - Origin or URL, e.g. "https://example.com".
 * @param {object} [opts]
 * @param {number} [opts.timeout=8000] - Per-request timeout in ms.
 * @returns {Promise<{ok:boolean, total?:number, hosts?:number, tree?:object, sources?:string[], error?:string}>}
 */
export async function mapSite(baseUrl, opts = {}) {
  const timeout = opts.timeout ?? 8000;
  let origin;
  let originHost;
  try {
    const u = new URL(baseUrl);
    origin = u.origin;
    originHost = u.host;
  } catch {
    return { ok: false, error: "Invalid target URL" };
  }

  const seen = new Set();
  const entries = [];
  const sources = [];
  /** Record a (host, path) pair once, up to the cap. */
  const add = (host, rawPath) => {
    const path = cleanPath(rawPath);
    if (!path || seen.size >= MAX_ENTRIES) return;
    const key = `${host}|${path}`;
    if (seen.has(key)) return;
    seen.add(key);
    entries.push({ host, path });
  };

  // Homepage resources — every file the page actually loads (the "Sources" view).
  try {
    const html = await getText(baseUrl, timeout);
    let any = false;
    for (const raw of resourceUrls(html)) {
      if (/^(?:data|mailto|tel|javascript):/i.test(raw) || raw.startsWith("#")) continue;
      try {
        const u = new URL(raw, baseUrl);
        if (u.protocol !== "http:" && u.protocol !== "https:") continue;
        add(u.host, u.pathname);
        any = true;
      } catch {
        // skip unparseable reference
      }
      if (seen.size >= MAX_ENTRIES) break;
    }
    if (any) sources.push("page resources");
  } catch {
    // homepage unreadable — fine.
  }

  // robots.txt — Disallow/Allow paths + Sitemap references.
  let sitemapUrls = [];
  try {
    const robots = await getText(`${origin}/robots.txt`, timeout);
    sources.push("robots.txt");
    for (const line of robots.split(/\r?\n/)) {
      const rule = line.match(/^\s*(?:dis)?allow\s*:\s*(\S+)/i);
      if (rule && rule[1] && rule[1] !== "*") add(originHost, rule[1]);
      const sm = line.match(/^\s*sitemap\s*:\s*(\S+)/i);
      if (sm) sitemapUrls.push(sm[1]);
    }
  } catch {
    // no robots.txt — fine.
  }

  // sitemap.xml — explicit ones from robots, else the conventional location.
  if (!sitemapUrls.length) sitemapUrls = [`${origin}/sitemap.xml`];
  for (const sm of sitemapUrls.slice(0, 3)) {
    if (seen.size >= MAX_ENTRIES) break;
    try {
      const xml = await getText(sm, timeout);
      if (!sources.includes("sitemap.xml")) sources.push("sitemap.xml");
      for (const m of xml.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)) {
        try {
          const u = new URL(m[1]);
          add(u.host, u.pathname);
        } catch {
          // skip malformed URL
        }
        if (seen.size >= MAX_ENTRIES) break;
      }
    } catch {
      // sitemap missing/unreadable — fine.
    }
  }

  if (!entries.length) {
    return {
      ok: false,
      sources,
      error: sources.length ? "No paths/resources discovered" : "No robots.txt, sitemap.xml, or page resources found",
    };
  }

  // Build a host-grouped tree: { host: { seg: { ... } } }.
  const tree = {};
  for (const { host, path } of entries) {
    tree[host] = tree[host] || {};
    let node = tree[host];
    for (const seg of path.split("/").filter(Boolean)) {
      node[seg] = node[seg] || {};
      node = node[seg];
    }
  }

  return { ok: true, total: entries.length, hosts: Object.keys(tree).length, tree, sources };
}
