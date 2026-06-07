/**
 * HTTP security-header + cookie audit.
 *
 * Single responsibility: fetch the target over HTTPS and grade the presence of
 * the security headers that lock down a public site (HSTS, CSP, etc.), surface
 * tech-fingerprint headers, and audit Set-Cookie flags (Secure/HttpOnly/
 * SameSite). Uses global fetch (undici).
 */

/** Headers we grade, with a short rationale shown in the UI. */
const GRADED_HEADERS = [
  ["strict-transport-security", "Forces HTTPS (HSTS) — prevents protocol downgrade."],
  ["content-security-policy", "Restricts script/resource origins — mitigates XSS."],
  ["x-frame-options", "Blocks clickjacking via framing."],
  ["x-content-type-options", "Stops MIME-type sniffing."],
  ["referrer-policy", "Controls referrer leakage to other sites."],
  ["permissions-policy", "Restricts powerful browser features."],
];

/** Headers that quietly leak stack/tech info an attacker can use. */
const FINGERPRINT_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "via"];

/**
 * CDN / WAF detection signatures: [header name, optional value regex, label].
 * Presence of the header (matching the regex, if any) reveals a provider in
 * front of the origin. Informational — it shapes how other findings read.
 */
const CDN_SIGNATURES = [
  ["cf-ray", null, "Cloudflare"],
  ["x-amz-cf-id", null, "Amazon CloudFront"],
  ["x-amz-cf-pop", null, "Amazon CloudFront"],
  ["x-fastly-request-id", null, "Fastly"],
  ["x-served-by", /cache-/i, "Fastly"],
  ["x-sucuri-id", null, "Sucuri WAF"],
  ["x-sucuri-cache", null, "Sucuri WAF"],
  ["x-vercel-id", null, "Vercel"],
  ["x-akamai-transformed", null, "Akamai"],
  ["x-cdn", null, "CDN"],
  ["x-azure-ref", null, "Azure Front Door"],
  ["server", /cloudflare/i, "Cloudflare"],
  ["server", /akamai/i, "Akamai"],
  ["server", /sucuri/i, "Sucuri WAF"],
];

/**
 * Inspect a Content-Security-Policy value for common weaknesses.
 *
 * @param {string} csp - The raw CSP header value.
 * @returns {string[]} Human-readable weakness descriptions (empty if none).
 */
function analyzeCsp(csp) {
  const issues = [];
  const lower = csp.toLowerCase();
  if (lower.includes("'unsafe-inline'")) {
    issues.push("Allows 'unsafe-inline' — inline scripts/styles run, weakening XSS protection.");
  }
  if (lower.includes("'unsafe-eval'")) {
    issues.push("Allows 'unsafe-eval' — eval()/Function() permitted.");
  }
  if (/(?:^|[\s;])(?:default-src|script-src)[^;]*\*(?![.\w])/.test(lower)) {
    issues.push("Wildcard (*) source allowed in default-src/script-src.");
  }
  if (/(?:^|[\s;])(?:default-src|script-src)[^;]*\bhttp:/.test(lower)) {
    issues.push("Allows insecure http: sources.");
  }
  if (!/(?:^|[\s;])default-src/.test(lower) && !/(?:^|[\s;])script-src/.test(lower)) {
    issues.push("No default-src or script-src directive — script origins unrestricted.");
  }
  return issues;
}

/**
 * Detect any CDN/WAF in front of the origin from response headers.
 *
 * @param {Headers} headers - The fetch Response headers.
 * @returns {string[]} De-duplicated provider names detected (empty if none).
 */
function detectCdn(headers) {
  const found = new Set();
  for (const [name, valRe, label] of CDN_SIGNATURES) {
    const v = headers.get(name);
    if (v == null) continue;
    if (valRe && !valRe.test(v)) continue;
    found.add(label);
  }
  return [...found];
}

/**
 * Parse Set-Cookie strings into per-cookie security-flag findings.
 *
 * @param {string[]} cookieStrings - Raw Set-Cookie header values.
 * @returns {Array<{name:string, secure:boolean, httpOnly:boolean, sameSite:(string|null)}>}
 */
function auditCookies(cookieStrings) {
  return cookieStrings.map((raw) => {
    const name = raw.split("=")[0].trim();
    const lower = raw.toLowerCase();
    const sameSiteMatch = lower.match(/samesite=([^;]+)/);
    return {
      name,
      secure: /(^|;)\s*secure(;|$)/.test(lower),
      httpOnly: /(^|;)\s*httponly(;|$)/.test(lower),
      sameSite: sameSiteMatch ? sameSiteMatch[1].trim() : null,
    };
  });
}

/**
 * Fetch the target and audit its response headers + cookies.
 *
 * @param {string} url - Full https URL to request.
 * @param {object} [opts]
 * @param {number} [opts.timeout=8000] - Request timeout in ms.
 * @returns {Promise<object>} { ok, status, present[], missing[], fingerprint{}, cookies[], cspIssues[], cdn[], error }.
 */
export async function auditHeaders(url, opts = {}) {
  const timeout = opts.timeout ?? 8000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: { "user-agent": "Vantasec-Scanner/0.1 (+security self-audit)" },
    });

    const present = [];
    const missing = [];
    for (const [name, why] of GRADED_HEADERS) {
      const value = res.headers.get(name);
      if (value) present.push({ name, value, why });
      else missing.push({ name, why });
    }

    const fingerprint = {};
    for (const name of FINGERPRINT_HEADERS) {
      const value = res.headers.get(name);
      if (value) fingerprint[name] = value;
    }

    // getSetCookie() (undici) returns each Set-Cookie separately; fall back gracefully.
    const rawCookies = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
    const cookies = auditCookies(rawCookies);

    // Flag a present-but-weak CSP and any CDN/WAF fronting the origin.
    const cspEntry = present.find((h) => h.name === "content-security-policy");
    const cspIssues = cspEntry ? analyzeCsp(cspEntry.value) : [];
    const cdn = detectCdn(res.headers);
    // HTTP/3 is advertised via Alt-Svc (e.g. `h3=":443"`).
    const http3 = /\bh3(-\d+)?=/.test(res.headers.get("alt-svc") || "");

    // CORS posture: a wildcard Allow-Origin combined with credentials is exploitable.
    const acao = res.headers.get("access-control-allow-origin");
    const cors = acao
      ? {
          allowOrigin: acao,
          allowCredentials: (res.headers.get("access-control-allow-credentials") || "").toLowerCase() === "true",
        }
      : null;
    // A cacheable response that also sets cookies risks caching authenticated content.
    const cc = (res.headers.get("cache-control") || "").toLowerCase();
    const cacheableWithCookies = rawCookies.length > 0 && !/no-store|private/.test(cc);

    return {
      ok: true,
      status: res.status,
      present,
      missing,
      fingerprint,
      cookies,
      cspIssues,
      cdn,
      http3,
      cors,
      cacheableWithCookies,
    };
  } catch (err) {
    const msg = err.name === "AbortError" ? "Request timed out" : err.message;
    return { ok: false, error: msg };
  } finally {
    clearTimeout(timer);
  }
}
