import { NextResponse } from "next/server";

/**
 * Proxy (Next 16 renamed middleware) — per-request client hardening.
 *
 * Single responsibility: mint a fresh nonce per request and emit a strict,
 * nonce-based Content-Security-Policy so this app ships with NO \'unsafe-inline\'
 * script execution — the same posture the scanner grades other sites against.
 * The nonce is exposed via the x-nonce request header so Next can attach it to
 * its own framework/bundle scripts automatically.
 *
 * Note: nonce-based CSP requires dynamic rendering; the root layout opts in via
 * `export const dynamic = "force-dynamic"`.
 */

/**
 * @param {import("next/server").NextRequest} request - Incoming request.
 * @returns {NextResponse} Response carrying the CSP (and propagating the nonce).
 */
export function proxy(request) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const isDev = process.env.NODE_ENV === "development";

  // Dev needs \'unsafe-eval\' (React debug) and inline styles (HMR); prod is strict.
  // connect-src is 'self' because the browser only ever calls our own /api/scan —
  // all third-party lookups (NVD, CertSpotter, DNS, TLS) happen server-side.
  const csp = `
    default-src 'self';
    script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""};
    style-src 'self' ${isDev ? "'unsafe-inline'" : `'nonce-${nonce}'`};
    img-src 'self' blob: data:;
    font-src 'self';
    connect-src 'self';
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    frame-ancestors 'none';
    upgrade-insecure-requests;
  `
    .replace(/\s{2,}/g, " ")
    .trim();

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

/** Run on document routes only; skip API, static assets, the favicon, and prefetches. */
export const config = {
  matcher: [
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
