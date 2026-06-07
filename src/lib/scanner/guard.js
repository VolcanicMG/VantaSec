/**
 * Scan safety guard (SSRF / abuse / resource protection).
 *
 * Single responsibility: decide whether a target is allowed to be scanned, and
 * enforce sane limits, so this tool can't be turned into a weapon against our
 * own infrastructure or the internal network it runs on. It performs DNS
 * resolution and rejects any target that resolves to a private, loopback,
 * link-local, or otherwise reserved address.
 *
 * Defensive rationale: an attacker (or a careless user) could point a scanner
 * at "localhost", "169.254.169.254" (cloud metadata), or an internal "10.x"
 * host to probe systems they shouldn't reach. We resolve first, then block.
 */

import { lookup } from "node:dns/promises";
import { isIPv4 } from "./target.js";

/** Hard cap on how many ports a single scan may probe (range abuse guard). */
export const MAX_PORTS = 2048;

/**
 * Classify an IPv4 address: return a block reason, or null if public.
 *
 * @param {string} ip - Dotted-quad IPv4 address.
 * @returns {string|null} Human-readable reason to block, or null if allowed.
 */
function blockReasonV4(ip) {
  const o = ip.split(".").map(Number);
  if (o.length !== 4 || o.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return "Unparseable IPv4 address";
  }
  const [a, b] = o;
  if (a === 0) return "Reserved (0.0.0.0/8)";
  if (a === 10) return "Private network (10.0.0.0/8)";
  if (a === 127) return "Loopback (127.0.0.0/8)";
  if (a === 169 && b === 254) return "Link-local / cloud metadata (169.254.0.0/16)";
  if (a === 172 && b >= 16 && b <= 31) return "Private network (172.16.0.0/12)";
  if (a === 192 && b === 168) return "Private network (192.168.0.0/16)";
  if (a === 100 && b >= 64 && b <= 127) return "Carrier-grade NAT (100.64.0.0/10)";
  if (a === 192 && b === 0) return "Reserved (192.0.0.0/24 / TEST-NET)";
  if (a >= 224) return "Multicast / reserved (224.0.0.0+)";
  return null;
}

/**
 * Classify an IPv6 address: return a block reason, or null if public.
 * Best-effort coverage of the ranges that matter for SSRF.
 *
 * @param {string} ip - IPv6 address (may be IPv4-mapped).
 * @returns {string|null} Reason to block, or null if allowed.
 */
function blockReasonV6(ip) {
  const lower = ip.toLowerCase();
  if (lower === "::1") return "IPv6 loopback (::1)";
  if (lower === "::") return "Unspecified address (::)";
  // IPv4-mapped (::ffff:a.b.c.d) — defer to the IPv4 classifier.
  const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return blockReasonV4(mapped[1]);
  if (/^f[cd][0-9a-f]{2}:/.test(lower)) return "Unique-local address (fc00::/7)";
  if (/^fe[89ab][0-9a-f]:/.test(lower)) return "Link-local (fe80::/10)";
  if (/^ff[0-9a-f]{2}:/.test(lower)) return "Multicast (ff00::/8)";
  return null;
}

/**
 * Return a block reason for any IP literal, or null if it is a public address.
 *
 * @param {string} ip - IPv4 or IPv6 literal.
 * @returns {string|null} Reason to block, or null if allowed.
 */
export function ipBlockReason(ip) {
  return isIPv4(ip) ? blockReasonV4(ip) : blockReasonV6(ip);
}

/**
 * Resolve a host and assert every resolved address is publicly routable.
 * Throws if the host resolves (even partially) to a protected range, which
 * prevents DNS-rebinding-style tricks where a name points inward.
 *
 * @param {string} host - Hostname or IP literal to validate.
 * @returns {Promise<void>} Resolves if safe to scan.
 * @throws {Error} With a clear reason if the target must not be scanned.
 */
export async function assertScannable(host) {
  const lower = host.toLowerCase();
  if (lower === "localhost" || lower.endsWith(".localhost")) {
    throw new Error("Refusing to scan localhost");
  }

  // If the user passed an IP literal, check it directly.
  const literalReason = ipBlockReason(host);
  if (literalReason) {
    throw new Error(`Refusing to scan non-public address: ${literalReason}`);
  }

  // Otherwise resolve the name to all addresses and check each one.
  if (!isIPv4(host) && !host.includes(":")) {
    let addrs;
    try {
      addrs = await lookup(host, { all: true });
    } catch {
      throw new Error(`Could not resolve host: ${host}`);
    }
    if (!addrs.length) throw new Error(`Host did not resolve: ${host}`);
    for (const { address } of addrs) {
      const reason = ipBlockReason(address);
      if (reason) {
        throw new Error(`Refusing to scan ${host} — resolves to non-public address: ${reason}`);
      }
    }
  }
}
