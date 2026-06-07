/**
 * Service identification data + helpers.
 *
 * Single responsibility: map port numbers to well-known service names, hold
 * the curated port presets we scan, and extract a human-readable service /
 * version guess from a raw banner. No sockets here — pure data + string work.
 */

/** Well-known port -> default service label. */
export const PORT_SERVICES = {
  21: "ftp",
  22: "ssh",
  23: "telnet",
  25: "smtp",
  53: "dns",
  80: "http",
  110: "pop3",
  111: "rpcbind",
  135: "msrpc",
  139: "netbios-ssn",
  143: "imap",
  161: "snmp",
  389: "ldap",
  443: "https",
  445: "smb",
  465: "smtps",
  587: "smtp-submission",
  993: "imaps",
  995: "pop3s",
  1433: "mssql",
  1521: "oracle",
  2049: "nfs",
  2375: "docker",
  2376: "docker-tls",
  3000: "node-dev",
  3306: "mysql",
  3389: "rdp",
  5432: "postgresql",
  5601: "kibana",
  5672: "amqp",
  5900: "vnc",
  5984: "couchdb",
  6379: "redis",
  8080: "http-alt",
  8443: "https-alt",
  8888: "http-alt",
  9000: "http-alt",
  9200: "elasticsearch",
  11211: "memcached",
  27017: "mongodb",
};

/**
 * The "common" preset: a curated list of the most security-relevant ports.
 * Roughly mirrors nmap's intent of catching the services people actually run.
 */
export const COMMON_PORTS = Object.keys(PORT_SERVICES)
  .map(Number)
  .sort((a, b) => a - b);

/** A small "top" preset for quick scans. */
export const TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017];

/**
 * Build the list of ports to scan for a named preset or explicit range.
 *
 * @param {object} opts
 * @param {"top"|"common"|"range"} opts.preset - Which set of ports to scan.
 * @param {number} [opts.from] - Range start (inclusive), used when preset==="range".
 * @param {number} [opts.to] - Range end (inclusive), used when preset==="range".
 * @returns {number[]} Sorted, de-duplicated list of port numbers.
 */
export function resolvePorts({ preset, from, to }) {
  if (preset === "top") return [...TOP_PORTS];
  if (preset === "range") {
    const start = Math.max(1, Math.min(65535, from ?? 1));
    const end = Math.max(start, Math.min(65535, to ?? start));
    const out = [];
    for (let p = start; p <= end; p++) out.push(p);
    return out;
  }
  return [...COMMON_PORTS];
}

/**
 * Guess a service label and version string from a captured banner.
 *
 * @param {number} port - The port the banner came from.
 * @param {string} banner - Raw banner text (may be empty).
 * @returns {{ service: string, version: string|null }}
 */
export function identifyService(port, banner) {
  const base = PORT_SERVICES[port] || "unknown";
  if (!banner) return { service: base, version: null };

  const b = banner.trim();
  // SSH announces itself as "SSH-2.0-OpenSSH_8.9p1 ...".
  const ssh = b.match(/^SSH-[\d.]+-(\S+)/);
  if (ssh) return { service: "ssh", version: ssh[1] };

  // HTTP responses carry a Server: header we can surface.
  const server = b.match(/server:\s*(.+)/i);
  if (server) return { service: base, version: server[1].trim() };

  // SMTP greeting: "220 mail.example.com ESMTP Postfix".
  const smtp = b.match(/^220[ -](.+)/);
  if (smtp) return { service: base, version: smtp[1].trim().slice(0, 80) };

  return { service: base, version: null };
}
