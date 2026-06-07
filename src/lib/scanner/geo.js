/**
 * Target IP enrichment: GeoIP, ASN/org, and reverse DNS.
 *
 * Single responsibility: resolve the target to an IP and annotate it with
 * geographic + network-ownership context (country/city, ASN, hosting org) plus
 * its PTR record. GeoIP/ASN come from keyless HTTPS providers tried in order
 * (ipwho.is, then ipapi.co as a fallback when the first 403s/rate-limits);
 * reverse DNS uses the system resolver. All failures collapse into a result that
 * still returns IP + PTR with an `error` note.
 */

import { reverse, resolve4 } from "node:dns/promises";
import { isIPv4 } from "./target.js";
import { readCappedText } from "./http.js";

/** Hard cap on a GeoIP API response body. */
const MAX_RESPONSE_BYTES = 1_000_000;
const UA = "Vantasec-Scanner/0.1 (+security self-audit)";

/**
 * GeoIP via ipwho.is.
 * @param {string} ip
 * @param {AbortSignal} signal
 * @returns {Promise<object>} Normalized geo fields.
 */
async function fromIpwhois(ip, signal) {
  const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, { signal, headers: { "user-agent": UA } });
  if (!res.ok) throw new Error(`ipwho.is ${res.status}`);
  const d = JSON.parse(await readCappedText(res, MAX_RESPONSE_BYTES));
  if (d.success === false) throw new Error(d.message || "ipwho.is failed");
  const c = d.connection || {};
  return {
    country: d.country || null,
    city: d.city || null,
    region: d.region || null,
    asn: c.asn != null ? `AS${c.asn}` : null,
    org: c.org || c.isp || null,
  };
}

/**
 * GeoIP via ipapi.co (fallback).
 * @param {string} ip
 * @param {AbortSignal} signal
 * @returns {Promise<object>} Normalized geo fields.
 */
async function fromIpapi(ip, signal) {
  const res = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, { signal, headers: { "user-agent": UA } });
  if (!res.ok) throw new Error(`ipapi.co ${res.status}`);
  const d = JSON.parse(await readCappedText(res, MAX_RESPONSE_BYTES));
  if (d.error) throw new Error(d.reason || "ipapi.co failed");
  return {
    country: d.country_name || null,
    city: d.city || null,
    region: d.region || null,
    asn: d.asn || null,
    org: d.org || null,
  };
}

/** Providers tried in order until one succeeds. */
const GEO_PROVIDERS = [fromIpwhois, fromIpapi];

/**
 * Resolve and enrich the target's IP.
 *
 * @param {string} host - Hostname or IPv4 address.
 * @param {object} [opts]
 * @param {number} [opts.timeout=8000] - GeoIP request timeout in ms (whole chain).
 * @returns {Promise<{ok:boolean, ip?:string, ptr?:string, country?:string,
 *   city?:string, region?:string, asn?:string, org?:string, error?:string}>}
 */
export async function lookupGeo(host, opts = {}) {
  const timeout = opts.timeout ?? 8000;

  // Resolve to an IP (or use the host directly if it already is one).
  let ip = host;
  if (!isIPv4(host)) {
    try {
      const a = await resolve4(host);
      ip = a[0];
    } catch {
      return { ok: false, error: "Could not resolve an IPv4 address" };
    }
  }
  if (!ip) return { ok: false, error: "No IP to enrich" };

  // Reverse DNS (PTR) — best-effort, independent of GeoIP.
  let ptr = null;
  try {
    ptr = (await reverse(ip))[0] || null;
  } catch {
    ptr = null;
  }

  // GeoIP + ASN: try each provider until one works.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  let geo = null;
  let lastErr = null;
  try {
    for (const provider of GEO_PROVIDERS) {
      try {
        geo = await provider(ip, controller.signal);
        if (geo) break;
      } catch (err) {
        lastErr = err;
      }
    }
  } finally {
    clearTimeout(timer);
  }

  if (geo) return { ok: true, ip, ptr, ...geo };
  return { ok: true, ip, ptr, error: `GeoIP unavailable${lastErr ? `: ${lastErr.message}` : ""}` };
}
