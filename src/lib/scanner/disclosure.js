/**
 * Disclosure-file checker (security.txt / robots.txt) + sensitive-file exposure.
 *
 * Single responsibility: check for the well-known disclosure/policy files a
 * well-run public site should expose, AND probe for commonly-leaked sensitive
 * files (.git, .env, backups, etc.). To preserve the operator-safety property
 * that we never read a target's response body, exposure is judged from the
 * status code + Content-Type header only — never the body.
 */

import { safeFetch } from "./safeFetch.js";

/** Files to probe, with where they live and whether absence is a finding. */
const FILES = [
  { key: "securityTxt", paths: ["/.well-known/security.txt", "/security.txt"], graded: true },
  { key: "robotsTxt", paths: ["/robots.txt"], graded: false },
];

/**
 * Commonly-leaked sensitive paths. A 200 here (that isn't an HTML catch-all)
 * usually means a real leak: source control, secrets, backups, or status pages.
 */
const SENSITIVE_PATHS = [
  "/.git/HEAD",
  "/.git/config",
  "/.env",
  "/.env.local",
  "/.env.production",
  "/.svn/entries",
  "/.DS_Store",
  "/.htaccess",
  "/server-status",
  "/phpinfo.php",
  "/config.php.bak",
  "/wp-config.php.bak",
  "/backup.sql",
  "/database.sql",
];

/**
 * Issue a GET and report whether the resource exists (HTTP 200).
 *
 * @param {string} url - Absolute URL to probe.
 * @param {number} timeout - Timeout in ms.
 * @returns {Promise<boolean>} True if the file returned a 200.
 */
async function exists(url, timeout) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await safeFetch(url, { method: "GET", signal: controller.signal });
    return res.status === 200;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Probe a path for exposure using status + Content-Type only (no body read).
 * Redirects are NOT followed (a 30x to a login page is not an exposure), and a
 * 200 served as text/html is treated as a soft-404 catch-all, not a leak.
 *
 * @param {string} url - Absolute URL to probe.
 * @param {number} timeout - Timeout in ms.
 * @returns {Promise<{exposed:boolean, contentType:string}>}
 */
async function probeSensitive(url, timeout) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: controller.signal,
      headers: { "user-agent": "Vantasec-Scanner/0.1 (+security self-audit)" },
    });
    const ct = res.headers.get("content-type") || "";
    return { exposed: res.status === 200 && !/^text\/html/i.test(ct), contentType: ct.split(";")[0] || "unknown" };
  } catch {
    return { exposed: false, contentType: "" };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Check the disclosure + sensitive files for a target.
 *
 * @param {string} baseUrl - Origin, e.g. "https://example.com".
 * @param {object} [opts]
 * @param {number} [opts.timeout=6000] - Per-file timeout in ms.
 * @returns {Promise<object>} { ok, securityTxt, robotsTxt, exposedFiles:[{path,contentType}] }.
 */
export async function checkDisclosure(baseUrl, opts = {}) {
  const timeout = opts.timeout ?? 6000;
  const out = { ok: true };

  for (const file of FILES) {
    let found = false;
    for (const path of file.paths) {
      // Stop at the first path variant that exists.
      if (await exists(baseUrl + path, timeout)) {
        found = true;
        break;
      }
    }
    out[file.key] = found;
  }

  // Probe the sensitive paths concurrently — they're independent.
  const probes = await Promise.all(
    SENSITIVE_PATHS.map((p) => probeSensitive(baseUrl + p, timeout).then((r) => ({ path: p, ...r })))
  );
  out.exposedFiles = probes
    .filter((r) => r.exposed)
    .map((r) => ({ path: r.path, contentType: r.contentType }));

  return out;
}
