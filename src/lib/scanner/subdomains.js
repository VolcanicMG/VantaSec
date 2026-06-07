/**
 * Passive subdomain discovery via Certificate Transparency (CertSpotter API).
 *
 * Single responsibility: query the public CertSpotter CT-log API for
 * certificates issued under a domain and extract the unique subdomain names
 * seen. This is a passive lookup against a third party — no traffic is sent to
 * the target, so it cannot be used to probe internal hosts. IP targets are
 * skipped (CT logs are domain-keyed). Network/parse failures collapse into
 * { ok:false }, never throw.
 *
 * CertSpotter is used instead of crt.sh because crt.sh's JSON endpoint is
 * frequently slow enough to time out on larger domains. Works keyless
 * (rate-limited); CERTSPOTTER_API_KEY is honored if set, for higher limits and
 * is read from the environment, never logged.
 */

import { isIPv4 } from "./target.js";
import { readCappedText } from "./http.js";

/** CertSpotter Certificate Transparency issuances endpoint. */
const CERTSPOTTER_ENDPOINT = "https://api.certspotter.com/v1/issuances";

/** Cap results so a wildcard-heavy domain can't flood the UI. */
const MAX_SUBDOMAINS = 50;

/** Hard cap on the API response body (defense-in-depth against a runaway payload). */
const MAX_RESPONSE_BYTES = 10_000_000;

/**
 * Discover subdomains of a host from Certificate Transparency logs.
 *
 * @param {string} host - Registrable domain or hostname (IPs are skipped).
 * @param {object} [opts]
 * @param {number} [opts.timeout=15000] - Request timeout in ms.
 * @returns {Promise<{ok:boolean, subdomains:string[], total:number, error?:string}>}
 */
export async function discoverSubdomains(host, opts = {}) {
  if (isIPv4(host)) {
    return { ok: false, subdomains: [], total: 0, error: "Not applicable to IP targets" };
  }
  const timeout = opts.timeout ?? 15000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const url = `${CERTSPOTTER_ENDPOINT}?domain=${encodeURIComponent(host)}&include_subdomains=true&expand=dns_names`;
    const headers = { "user-agent": "Vantasec-Scanner/0.1 (+security self-audit)" };
    // Optional API key (read from env, never logged) raises the rate limit.
    const key = process.env.CERTSPOTTER_API_KEY;
    if (key) headers.authorization = `Bearer ${key}`;

    const res = await fetch(url, { signal: controller.signal, headers });
    if (!res.ok) {
      const hint = res.status === 429 ? "CT API rate limited — try again shortly" : `CT API responded ${res.status}`;
      return { ok: false, subdomains: [], total: 0, error: hint };
    }
    const issuances = JSON.parse(await readCappedText(res, MAX_RESPONSE_BYTES));

    // Each issuance lists its cert's dns_names; some are wildcards or unrelated
    // SANs (a multi-domain cert can name other sites). Normalize, keep only real
    // subdomains of host, dedupe.
    const set = new Set();
    for (const cert of Array.isArray(issuances) ? issuances : []) {
      for (const raw of cert.dns_names || []) {
        const name = String(raw).trim().toLowerCase().replace(/^\*\./, "");
        if (!name || name === host) continue;
        if (!name.endsWith(`.${host}`)) continue;
        // Drop anything that isn't a valid DNS name (a-z, 0-9, dot, hyphen,
        // underscore). This rejects injection-shaped entries outright, so the
        // list handed to the UI can only ever be inert hostnames.
        if (!/^[a-z0-9._-]+$/.test(name)) continue;
        set.add(name);
      }
    }

    const all = [...set].sort();
    return { ok: true, subdomains: all.slice(0, MAX_SUBDOMAINS), total: all.length };
  } catch (err) {
    const msg = err.name === "AbortError" ? "Subdomain lookup timed out" : err.message;
    return { ok: false, subdomains: [], total: 0, error: msg };
  } finally {
    clearTimeout(timer);
  }
}
