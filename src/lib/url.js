/**
 * URL safety helpers (shared, no client/server deps).
 *
 * Single responsibility: decide whether a URL is safe to use as a clickable
 * link target. Scan results can contain URLs derived from third-party data
 * (NVD references, etc.), and an `href` is an injection sink — a `javascript:`
 * or `data:` scheme in an href executes on click. This gates hrefs to http(s).
 */

/**
 * Return the URL only if it is a well-formed http(s) URL, else undefined.
 * Use as `href={safeHref(value)}` so a hostile scheme can never become a
 * clickable sink (the anchor renders inert instead).
 *
 * @param {string} url - Candidate URL from (possibly untrusted) scan data.
 * @returns {string|undefined} The URL when safe to link, otherwise undefined.
 */
export function safeHref(url) {
  if (typeof url !== "string") return undefined;
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:" ? url : undefined;
  } catch {
    return undefined;
  }
}
