/**
 * Scan orchestrator.
 *
 * Single responsibility: coordinate the individual checker modules for one
 * target and emit a stream of progress events as an async generator. It owns
 * sequencing and event shape only — never the checking logic itself
 * (dependency inversion: checkers are injected as plain functions).
 */

import { parseTarget } from "./target.js";
import { resolvePorts } from "./services.js";
import { scanPorts } from "./ports.js";
import { inspectTls } from "./tls.js";
import { lookupDns } from "./dns.js";
import { auditHeaders } from "./headers.js";
import { assertScannable, MAX_PORTS } from "./guard.js";
import { checkRedirect } from "./redirect.js";
import { checkDisclosure } from "./disclosure.js";
import { lookupCves } from "./cve.js";
import { discoverSubdomains } from "./subdomains.js";
import { auditContent } from "./content.js";
import { checkMethods } from "./methods.js";
import { mapSite } from "./tree.js";
import { lookupGeo } from "./geo.js";
import { computeScore } from "./score.js";

/**
 * @typedef {Object} ScanEvent
 * @property {string} type - "meta" | "phase" | "progress" | "result" | "done" | "error".
 * @property {*} [data] - Event payload (shape depends on type).
 */

/**
 * Run a full scan, yielding events as work completes.
 *
 * Event sequence (happy path):
 *   meta            -> resolved target info
 *   phase ports     -> begin port scan
 *   progress        -> repeated, per port resolved
 *   result ports    -> open ports summary
 *   result tls/dns/headers -> each check's findings
 *   done            -> final summary
 *
 * @param {string} rawTarget - Raw user input (host, IP, or URL).
 * @param {object} [opts]
 * @param {"top"|"common"|"range"} [opts.preset="common"] - Port preset.
 * @param {number} [opts.from] - Range start when preset==="range".
 * @param {number} [opts.to] - Range end when preset==="range".
 * @returns {AsyncGenerator<ScanEvent>}
 */
export async function* runScan(rawTarget, opts = {}) {
  let target;
  try {
    target = parseTarget(rawTarget);
  } catch (err) {
    yield { type: "error", data: { message: err.message } };
    return;
  }

  yield { type: "meta", data: { host: target.host, displayName: target.displayName, startedAt: Date.now() } };

  // Safety gate: refuse private/loopback/internal targets before any socket
  // opens, so this tool can't be used to probe our own network (SSRF/pivot).
  try {
    await assertScannable(target.host);
  } catch (err) {
    yield { type: "error", data: { message: err.message } };
    return;
  }

  // --- Phase 1: port scan (the long-running one, so it streams progress) ---
  let ports = resolvePorts({ preset: opts.preset ?? "common", from: opts.from, to: opts.to });
  if (ports.length > MAX_PORTS) {
    // Cap range scans so a huge range can't exhaust sockets/memory.
    ports = ports.slice(0, MAX_PORTS);
  }
  yield { type: "phase", data: { phase: "ports", total: ports.length } };

  // Bridge the callback-based progress into our generator via a queue.
  const queue = [];
  let resolveWaiter = null;
  /** Push a progress event and wake any pending consumer. @param {object} ev */
  const push = (ev) => {
    queue.push(ev);
    if (resolveWaiter) {
      resolveWaiter();
      resolveWaiter = null;
    }
  };

  const portsPromise = scanPorts(target.host, ports, {
    concurrency: 150,
    onProgress: (done, total, result) => {
      // Only stream meaningful events: every open port, plus a heartbeat.
      if (result.status === "open" || done % 25 === 0 || done === total) {
        push({ type: "progress", data: { done, total, port: result.port, status: result.status } });
      }
    },
  }).then((res) => {
    push({ type: "__ports_done__", data: res });
  });

  // Drain the queue until the port scan signals completion.
  let portResults = null;
  while (portResults === null) {
    if (queue.length === 0) {
      await new Promise((r) => (resolveWaiter = r));
    }
    while (queue.length) {
      const ev = queue.shift();
      if (ev.type === "__ports_done__") portResults = ev.data;
      else yield ev;
    }
  }
  await portsPromise;

  const openPorts = portResults.filter((p) => p.status === "open");
  yield { type: "result", data: { check: "ports", openPorts, scanned: ports.length } };

  // --- Phase 2: the remaining checks run in parallel; emit as each lands ---
  yield { type: "phase", data: { phase: "services" } };

  // crt.sh is often slow, so kick subdomain discovery off now and let it run
  // concurrently with the service checks AND the CVE lookup. We await it at the
  // very end — that way a slow or timed-out lookup never delays the other cards.
  const subdomainsPromise = discoverSubdomains(target.host);

  const checks = [
    ["tls", inspectTls(target.host)],
    ["dns", lookupDns(target.host)],
    ["headers", auditHeaders(target.httpUrl)],
    ["redirect", checkRedirect(target.host)],
    ["disclosure", checkDisclosure(target.httpUrl)],
    ["content", auditContent(target.httpUrl)],
    ["geo", lookupGeo(target.host)],
    ["methods", checkMethods(target.httpUrl)],
    ["tree", mapSite(target.httpUrl)],
  ];

  // Accumulate every result so we can compute one overall score at the end.
  const collected = { ports: { openPorts, scanned: ports.length } };

  const settled = await Promise.allSettled(checks.map(([, p]) => p));
  for (let i = 0; i < checks.length; i++) {
    const [name] = checks[i];
    const outcome = settled[i];
    const data = outcome.status === "fulfilled" ? outcome.value : { ok: false, error: String(outcome.reason) };
    collected[name] = data;
    yield { type: "result", data: { check: name, ...data } };
  }

  // --- Phase 3: CVE lookup, which depends on fingerprints gathered above ---
  yield { type: "phase", data: { phase: "cve" } };
  let cve;
  try {
    cve = await lookupCves(collected);
  } catch (err) {
    cve = { ok: false, error: String(err), findings: [] };
  }
  collected.cve = cve;
  yield { type: "result", data: { check: "cve", ...cve } };

  // --- Phase 4: subdomain discovery (started back in phase 2) lands now ---
  yield { type: "phase", data: { phase: "subdomains" } };
  const subdomains = await subdomainsPromise.then(
    (v) => v,
    (reason) => ({ ok: false, subdomains: [], total: 0, error: String(reason) })
  );
  collected.subdomains = subdomains;
  yield { type: "result", data: { check: "subdomains", ...subdomains } };

  // Overall verdict: a single 0-100 score + grade derived from all findings.
  const score = computeScore(collected);
  yield { type: "score", data: score };

  yield {
    type: "done",
    data: { host: target.host, openCount: openPorts.length, score: score.score, grade: score.grade, finishedAt: Date.now() },
  };
}
