/**
 * HTTP method audit.
 *
 * Single responsibility: ask the server (via OPTIONS) which HTTP methods it
 * advertises and flag risky ones (TRACE/PUT/DELETE/CONNECT/PATCH). Status +
 * headers only — never the body. Failures collapse into { ok:false }.
 */

/** Methods that are risky to expose on a public site without good reason. */
const RISKY_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"];

/**
 * Probe allowed HTTP methods.
 *
 * @param {string} url - Full https URL.
 * @param {object} [opts]
 * @param {number} [opts.timeout=6000] - Timeout in ms.
 * @returns {Promise<{ok:boolean, allow:string[], dangerous:string[], error?:string}>}
 */
export async function checkMethods(url, opts = {}) {
  const timeout = opts.timeout ?? 6000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, {
      method: "OPTIONS",
      redirect: "manual",
      signal: controller.signal,
      headers: { "user-agent": "Vantasec-Scanner/0.1 (+security self-audit)" },
    });
    const raw = res.headers.get("allow") || res.headers.get("access-control-allow-methods") || "";
    const allow = [...new Set(raw.split(",").map((m) => m.trim().toUpperCase()).filter(Boolean))];
    const dangerous = allow.filter((m) => RISKY_METHODS.includes(m));
    return { ok: true, allow, dangerous };
  } catch (err) {
    const msg = err.name === "AbortError" ? "OPTIONS request timed out" : err.message;
    return { ok: false, allow: [], dangerous: [], error: msg };
  } finally {
    clearTimeout(timer);
  }
}
