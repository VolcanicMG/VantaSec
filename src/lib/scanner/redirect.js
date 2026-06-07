/**
 * HTTP-to-HTTPS redirect + HSTS checker.
 *
 * Single responsibility: determine whether plain http:// is redirected to
 * https:// (no insecure landing), and inspect the HSTS policy on the secure
 * response (max-age, includeSubDomains, preload). A common misconfiguration is
 * serving content over http without forcing an upgrade.
 */

/**
 * Parse an HSTS header value into its component directives.
 *
 * @param {string|null} value - The strict-transport-security header value.
 * @returns {{present:boolean, maxAge:(number|null), includeSubDomains:boolean, preload:boolean}}
 */
function parseHsts(value) {
  if (!value) return { present: false, maxAge: null, includeSubDomains: false, preload: false };
  const lower = value.toLowerCase();
  const maxAgeMatch = lower.match(/max-age=(\d+)/);
  return {
    present: true,
    maxAge: maxAgeMatch ? Number(maxAgeMatch[1]) : null,
    includeSubDomains: lower.includes("includesubdomains"),
    preload: lower.includes("preload"),
  };
}

/**
 * Check the http->https redirect behavior and HSTS posture for a host.
 *
 * @param {string} host - Bare hostname.
 * @param {object} [opts]
 * @param {number} [opts.timeout=8000] - Request timeout in ms.
 * @returns {Promise<object>} { ok, redirects:boolean, finalUrl, hsts{...}, error }.
 */
export async function checkRedirect(host, opts = {}) {
  const timeout = opts.timeout ?? 8000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    // Hit plain http and follow redirects; check we end up on https.
    const res = await fetch(`http://${host}`, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: { "user-agent": "Vantasec-Scanner/0.1 (+security self-audit)" },
    });
    const finalUrl = res.url || "";
    const redirects = finalUrl.startsWith("https://");
    const hsts = parseHsts(res.headers.get("strict-transport-security"));
    return { ok: true, redirects, finalUrl, hsts };
  } catch (err) {
    const msg = err.name === "AbortError" ? "Request timed out" : err.message;
    return { ok: false, error: msg };
  } finally {
    clearTimeout(timer);
  }
}
