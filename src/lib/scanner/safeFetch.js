/**
 * SSRF-safe fetch wrapper for the scanner's HTTP checks.
 *
 * Single responsibility: perform an HTTP(S) request against a target while
 * keeping the safety guarantees of `assertScannable` intact across redirects.
 *
 * Why this exists: the global `fetch` follows redirects internally with no hook
 * to inspect each hop, so a target that passes the initial guard can return a
 * `30x Location: http://169.254.169.254/...` (or any internal address) and the
 * runtime will happily follow it inward. This wrapper instead follows redirects
 * MANUALLY and validates every redirect TARGET's host through `assertScannable`
 * before following it — so an attacker-controlled public target cannot bounce us
 * onto the internal network or cloud metadata.
 *
 * Contract: the host of the INITIAL `url` is assumed already validated by the
 * caller (runScan gates every scan through `assertScannable` before any check
 * runs). This wrapper adds the protection base fetch lacks — guarding each
 * redirect hop. It does NOT re-validate hop 0.
 *
 * Note: this closes the redirect vector. Pinning the resolved IP for the request
 * itself (full DNS-rebinding protection on the fetch path) would require a custom
 * undici dispatcher; the socket-based checks (ports/TLS) pin via the guard's
 * returned IP instead.
 */

import { assertScannable } from "./guard.js";

/** Hard cap on redirects we will follow before giving up. */
const MAX_REDIRECTS = 5;

/**
 * Fetch a URL, validating the host of every redirect hop against the SSRF guard.
 *
 * Behaves like `fetch` but always follows redirects manually. The returned
 * Response carries an extra `finalUrl` property (the URL of the hop that
 * actually produced the response) so callers can report the redirect target.
 *
 * @param {string} url - Absolute http(s) URL to request.
 * @param {RequestInit} [opts] - Standard fetch options. Any `redirect` option is
 *   ignored — redirects are always handled here.
 * @returns {Promise<Response & {finalUrl: string}>} The final response.
 * @throws {Error} If a hop resolves to a non-public address, the redirect chain
 *   is too long, or the underlying fetch fails.
 */
export async function safeFetch(url, opts = {}) {
  // Strip any caller-supplied redirect mode; we own redirect handling.
  const { redirect: _ignored, ...rest } = opts;
  let current = url;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const res = await fetch(current, { ...rest, redirect: "manual" });

    // Not a redirect (or no Location) — this is our answer.
    const location = res.headers.get("location");
    if (res.status < 300 || res.status >= 400 || !location) {
      // Expose the URL that produced the response for callers that need it.
      Object.defineProperty(res, "finalUrl", { value: current, enumerable: true });
      return res;
    }

    // Resolve the redirect target relative to the current URL and validate its
    // host BEFORE following — this is the SSRF gate the base fetch lacks. A
    // target that 30x-bounces toward an internal/loopback/metadata address is
    // rejected here instead of being requested.
    const next = new URL(location, current).href;
    await assertScannable(new URL(next).hostname);

    // Drain the redirect body so the connection can be reused/closed.
    try {
      await res.body?.cancel?.();
    } catch {
      // best-effort
    }
    current = next;
  }

  throw new Error(`Too many redirects (>${MAX_REDIRECTS})`);
}
