/**
 * TCP connect port scanner with banner grabbing.
 *
 * Single responsibility: determine open/closed/filtered status for a set of
 * ports on a host, and capture any service banner the port volunteers. This is
 * a pure-Node implementation (net.Socket) — no native deps, no root needed.
 * It is the connect-scan ("-sT") equivalent of nmap.
 */

import net from "node:net";
import { identifyService } from "./services.js";

/**
 * Probe bytes to send after connecting, so quiet services reveal themselves.
 * HTTP-ish ports get a HEAD request; everything else we just listen.
 *
 * @param {number} port - The port being probed.
 * @returns {string|null} Probe payload to write, or null to only listen.
 */
function probeFor(port) {
  const httpPorts = new Set([80, 443, 8080, 8443, 8888, 9000, 3000, 5601, 9200]);
  if (httpPorts.has(port)) return "HEAD / HTTP/1.0\r\n\r\n";
  return null;
}

/**
 * Scan a single TCP port via a connect attempt, optionally grabbing a banner.
 *
 * Status semantics mirror nmap:
 *   - "open": TCP handshake completed.
 *   - "closed": connection actively refused (RST).
 *   - "filtered": no response before timeout (firewall likely dropping).
 *
 * @param {string} host - Target hostname or IP.
 * @param {number} port - Port number to probe.
 * @param {object} [opts]
 * @param {number} [opts.timeout=2500] - Per-port timeout in ms.
 * @param {number} [opts.bannerWait=600] - Extra ms to wait for banner data after connect.
 * @param {string} [opts.connectIp] - Pre-validated public IP to connect to
 *   instead of re-resolving `host` (prevents DNS-rebinding to an internal IP).
 * @returns {Promise<{port:number,status:string,service:string,version:(string|null),banner:(string|null)}>}
 */
export function scanPort(host, port, opts = {}) {
  const timeout = opts.timeout ?? 2500;
  const bannerWait = opts.bannerWait ?? 600;
  // Connect to the guard-validated IP when provided; never re-resolve the name.
  const connectHost = opts.connectIp ?? host;

  return new Promise((resolve) => {
    const socket = new net.Socket();
    let banner = "";
    let settled = false;

    /**
     * Resolve exactly once with an identified result, then tear down the socket.
     * @param {string} status - open|closed|filtered.
     */
    const finish = (status) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      const { service, version } = identifyService(port, banner);
      resolve({
        port,
        status,
        service,
        version,
        banner: banner ? banner.slice(0, 256).trim() : null,
      });
    };

    socket.setTimeout(timeout);

    socket.on("connect", () => {
      // Connected => port is open. Try to coax a banner, then finish.
      const probe = probeFor(port);
      if (probe) socket.write(probe);
      setTimeout(() => finish("open"), bannerWait);
    });

    socket.on("data", (chunk) => {
      banner += chunk.toString("utf8");
      if (banner.length > 1024) finish("open");
    });

    socket.on("timeout", () => finish(banner ? "open" : "filtered"));

    socket.on("error", (err) => {
      // ECONNREFUSED => closed; anything else (host unreach, reset) => filtered.
      finish(err.code === "ECONNREFUSED" ? "closed" : "filtered");
    });

    socket.connect(port, connectHost);
  });
}

/**
 * Scan many ports with a bounded concurrency pool, reporting progress.
 *
 * @param {string} host - Target hostname or IP.
 * @param {number[]} ports - Ports to scan.
 * @param {object} [opts]
 * @param {number} [opts.concurrency=100] - Max simultaneous socket probes.
 * @param {number} [opts.timeout=2500] - Per-port timeout in ms.
 * @param {string} [opts.connectIp] - Pre-validated public IP to connect to
 *   instead of re-resolving `host` (DNS-rebinding protection); forwarded to scanPort.
 * @param {(done:number,total:number,result:object)=>void} [opts.onProgress] -
 *   Called after each port resolves, for live UI updates.
 * @returns {Promise<Array<object>>} Per-port results (see scanPort).
 */
export async function scanPorts(host, ports, opts = {}) {
  const concurrency = opts.concurrency ?? 100;
  const total = ports.length;
  const results = [];
  let index = 0;
  let done = 0;

  /** A single worker that pulls ports off the shared queue until empty. */
  const worker = async () => {
    while (index < ports.length) {
      const port = ports[index++];
      const res = await scanPort(host, port, opts);
      results.push(res);
      done++;
      if (opts.onProgress) opts.onProgress(done, total, res);
    }
  };

  const workers = Array.from({ length: Math.min(concurrency, total || 1) }, worker);
  await Promise.all(workers);

  results.sort((a, b) => a.port - b.port);
  return results;
}
