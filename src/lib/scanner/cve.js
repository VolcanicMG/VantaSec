/**
 * CVE lookup against the NVD (NIST National Vulnerability Database).
 *
 * Single responsibility: turn the version fingerprints we already captured
 * (server header, x-powered-by, SSH banner, etc.) into product/version
 * candidates, query the NVD 2.0 API for known CVEs, and return a compact,
 * de-duplicated findings list. Network + rate-limit handling lives here only.
 *
 * Auth: works keyless (NVD allows ~5 req / 30s). Set NVD_API_KEY for higher
 * limits — it's read from the environment and never logged.
 */

import { readCappedText } from "./http.js";

const NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/** Hard cap on a single NVD response body (defense-in-depth against a runaway payload). */
const MAX_RESPONSE_BYTES = 10_000_000;

/** Cap how many distinct product/version pairs we look up, to respect rate limits. */
const MAX_CANDIDATES = 3;

/**
 * Extract a product + version from a free-form fingerprint string.
 * Handles forms like "nginx/1.18.0", "OpenSSH_8.9p1", "PHP/7.4.3".
 *
 * @param {string} raw - The fingerprint/banner text.
 * @returns {{product:string, version:string}|null} Parsed pair, or null.
 */
export function parseFingerprint(raw) {
  if (!raw) return null;
  const m = raw.match(/([A-Za-z][A-Za-z0-9._-]*?)[\/_ ]v?(\d+\.\d+(?:\.\d+)?)/);
  if (!m) return null;
  const product = m[1].toLowerCase().replace(/[_-]+$/, "");
  return { product, version: m[2] };
}

/**
 * Build the de-duplicated list of product/version candidates to query, drawn
 * from header fingerprints and open-port service banners.
 *
 * @param {object} results - Collected scan results ({ ports, headers, ... }).
 * @returns {Array<{product:string, version:string, source:string}>}
 */
export function buildCandidates(results = {}) {
  const seen = new Set();
  const out = [];
  /** Add a candidate if it parses and is new. @param {string} raw @param {string} source */
  const add = (raw, source) => {
    const parsed = parseFingerprint(raw);
    if (!parsed) return;
    const key = `${parsed.product}@${parsed.version}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ ...parsed, source });
  };

  const fp = results.headers?.fingerprint || {};
  if (fp.server) add(fp.server, "server header");
  if (fp["x-powered-by"]) add(fp["x-powered-by"], "x-powered-by header");

  for (const p of results.ports?.openPorts || []) {
    if (p.version) add(p.version, `port ${p.port}`);
  }
  return out.slice(0, MAX_CANDIDATES);
}

/**
 * Query NVD for a single product/version candidate.
 *
 * @param {{product:string, version:string, source:string}} cand - Candidate.
 * @param {object} opts - { apiKey, timeout, max }.
 * @returns {Promise<{candidate:object, cves:Array, rateLimited:boolean, error:(string|null)}>}
 */
async function queryOne(cand, opts) {
  const { apiKey, timeout, max } = opts;
  const params = new URLSearchParams({
    keywordSearch: `${cand.product} ${cand.version}`,
    resultsPerPage: String(max),
  });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(`${NVD_ENDPOINT}?${params}`, {
      signal: controller.signal,
      headers: apiKey ? { apiKey } : {},
    });
    if (res.status === 403 || res.status === 429) {
      return { candidate: cand, cves: [], rateLimited: true, error: "NVD rate limit" };
    }
    if (!res.ok) return { candidate: cand, cves: [], rateLimited: false, error: `NVD ${res.status}` };
    const json = JSON.parse(await readCappedText(res, MAX_RESPONSE_BYTES));
    const cves = (json.vulnerabilities || []).map((v) => {
      const c = v.cve || {};
      const desc = (c.descriptions || []).find((d) => d.lang === "en")?.value || "";
      const metric =
        c.metrics?.cvssMetricV31?.[0] || c.metrics?.cvssMetricV30?.[0] || c.metrics?.cvssMetricV2?.[0];
      const cvss = metric?.cvssData || {};
      // CWE weakness ids (e.g. "CWE-79"), skipping NVD's placeholder values.
      const cwes = [];
      for (const w of c.weaknesses || []) {
        for (const d of w.description || []) {
          if (d.lang === "en" && /^CWE-/.test(d.value)) cwes.push(d.value);
        }
      }
      // A few primary reference links.
      const references = (c.references || []).slice(0, 4).map((r) => r.url).filter(Boolean);
      return {
        id: c.id,
        severity: cvss.baseSeverity || metric?.baseSeverity || "UNKNOWN",
        score: cvss.baseScore ?? null,
        summary: desc.slice(0, 240),
        // Richer detail surfaced behind the card's "more details" disclosure:
        fullDescription: desc,
        vector: cvss.vectorString || null,
        attackVector: cvss.attackVector || null,
        published: c.published || null,
        lastModified: c.lastModified || null,
        cwes: [...new Set(cwes)],
        references,
        url: `https://nvd.nist.gov/vuln/detail/${c.id}`,
      };
    });
    return { candidate: cand, cves, rateLimited: false, error: null };
  } catch (err) {
    const msg = err.name === "AbortError" ? "NVD request timed out" : err.message;
    return { candidate: cand, cves: [], rateLimited: false, error: msg };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Look up known CVEs for the fingerprints found in a scan.
 *
 * Candidates are queried sequentially with a small delay to stay within NVD's
 * rate limits. Failures degrade gracefully — a rate-limited or errored lookup
 * is reported, never thrown.
 *
 * @param {object} results - Collected scan results.
 * @param {object} [opts]
 * @param {string} [opts.apiKey] - NVD API key (defaults to process.env.NVD_API_KEY).
 * @param {number} [opts.timeout=10000] - Per-request timeout in ms.
 * @param {number} [opts.max=5] - Max CVEs to keep per candidate.
 * @returns {Promise<object>} { ok, findings[], rateLimited, note }.
 */
export async function lookupCves(results, opts = {}) {
  const apiKey = opts.apiKey ?? process.env.NVD_API_KEY ?? null;
  const timeout = opts.timeout ?? 10000;
  const max = opts.max ?? 5;

  const candidates = buildCandidates(results);
  if (candidates.length === 0) {
    return { ok: true, findings: [], rateLimited: false, note: "No version fingerprints to check." };
  }

  const findings = [];
  let rateLimited = false;
  // Without a key, NVD allows ~5 requests / 30s — space the calls out a little.
  const delayMs = apiKey ? 200 : 1200;

  for (let i = 0; i < candidates.length; i++) {
    if (i > 0) await new Promise((r) => setTimeout(r, delayMs));
    const result = await queryOne(candidates[i], { apiKey, timeout, max });
    if (result.rateLimited) rateLimited = true;
    if (result.cves.length > 0) {
      findings.push({ ...result.candidate, cves: result.cves });
    }
  }

  const note = rateLimited
    ? "Some lookups were rate-limited by NVD — set NVD_API_KEY for complete results."
    : findings.length === 0
      ? "No known CVEs matched the detected versions."
      : null;

  return { ok: true, findings, rateLimited, note };
}
