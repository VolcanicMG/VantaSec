"use client";

/**
 * Dashboard page.
 *
 * Single responsibility: compose the scan UI — form, progress, actions, history
 * and result cards — and bind them to the useScan hook. No scanning or parsing
 * logic lives here; it delegates to the hook and renders what comes back.
 */

import { useEffect, useRef, useState } from "react";
import { useScan } from "@/lib/useScan.js";
import { loadHistory, addHistory, clearHistory, previousFor, diffScans } from "@/lib/history.js";
import { getCachedScan, setCachedScan } from "@/lib/scanCache.js";
import ScanForm from "./components/ScanForm.js";
import ProgressBar from "./components/ProgressBar.js";
import ScanActions from "./components/ScanActions.js";
import ScanHistory from "./components/ScanHistory.js";
import ScoreBanner from "./components/ScoreBanner.js";
import ScanDiff from "./components/ScanDiff.js";
import RescanPopover from "./components/RescanPopover.js";
import {
  PortsCard,
  TlsCard,
  DnsCard,
  HeadersCard,
  RedirectCard,
  DisclosureCard,
  CveCard,
  SubdomainsCard,
  SkeletonCard,
  GeoCard,
  ContentCard,
  MethodsCard,
  TreeCard,
} from "./components/ResultCards.js";
import AttackSurface from "./components/AttackSurface.js";
import { runQuickScan } from "@/lib/surfaceScan.js";

/**
 * Checks we expect every scan to produce, in display order. Used to render a
 * skeleton placeholder for each check whose result hasn't streamed in yet.
 * @type {Array<[string, string]>}
 */
const EXPECTED_CHECKS = [
  ["ports", "Open Ports"],
  ["cve", "Known CVEs"],
  ["tls", "TLS / Certificate"],
  ["redirect", "HTTP \u2192 HTTPS Redirect"],
  ["headers", "HTTP Security Headers"],
  ["dns", "DNS & Email Security"],
  ["disclosure", "Disclosure Files"],
  ["content", "Page Content"],
  ["methods", "HTTP Methods"],
  ["tree", "Site Map"],
  ["geo", "IP / Network"],
  ["subdomains", "Subdomains"],
];

/**
 * @returns {JSX.Element}
 */
export default function Home() {
  const { status, meta, progress, results, score, error, start, cancel, hydrate } = useScan();
  const busy = status === "scanning";
  const [history, setHistory] = useState([]);
  const [diff, setDiff] = useState(null);
  const [surface, setSurface] = useState([]);
  // Navigation: the "main" target we drilled in from, and whether the current
  // view was loaded from cache (vs freshly scanned). presetRef tracks the preset
  // used so the cache key matches.
  const [rootTarget, setRootTarget] = useState(null);
  const [fromCache, setFromCache] = useState(false);
  const presetRef = useRef("common");

  // Load saved history once on mount. localStorage is client-only, so this must
  // happen after mount — a legitimate external-store sync, not a render cascade.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setHistory(loadHistory());
  }, []);

  // Persist a summary whenever a scan finishes with a score, and compute the
  // delta against the previous scan of the same target (before we overwrite it).
  useEffect(() => {
    /* eslint-disable react-hooks/set-state-in-effect -- persisting/diffing on scan
       completion is a deliberate side effect keyed off the status transition. */
    if (status === "done" && score && meta && !fromCache) {
      const ports = (results.ports?.openPorts || []).map((p) => p.port);
      const cves = (results.cve?.findings || []).flatMap((f) => (f.cves || []).map((c) => c.id));
      const prev = previousFor(meta.displayName);
      setDiff(diffScans(prev, { score: score.score, ports, cves }));
      setHistory(
        addHistory({ target: meta.displayName, score: score.score, grade: score.grade, at: Date.now(), ports, cves })
      );
      // Cache the full result so revisiting this target needs no rescan.
      setCachedScan(meta.displayName, presetRef.current, { meta, results, score });
    }
    /* eslint-enable react-hooks/set-state-in-effect */
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status]);

  /**
   * Start a scan, clearing any prior diff banner first.
   * @param {string} target - Target to scan.
   * @param {object} [opts] - Scan options forwarded to the hook.
   */
  const handleScan = (target, opts = {}) => {
    const preset = opts.preset || "common";
    presetRef.current = preset;
    setDiff(null);
    // A non-drill navigation (form / history) establishes the "main" target and
    // resets the attack-surface list; drilling into a subdomain preserves both.
    if (!opts.drill) {
      setRootTarget(target);
      setSurface([]);
    }
    // Serve from the session cache unless a re-scan is explicitly forced.
    if (!opts.force) {
      const cached = getCachedScan(target, preset);
      if (cached) {
        setFromCache(true);
        hydrate(cached);
        return;
      }
    }
    setFromCache(false);
    start(target, { preset, from: opts.from, to: opts.to });
  };

  /**
   * Opt-in attack-surface pivot: scan the main target plus all discovered
   * subdomains with limited concurrency, collecting each host's grade as it lands.
   * @param {string[]} hosts - Discovered subdomain hostnames.
   */
  const scanAll = async (hosts) => {
    const targets = [meta?.displayName, ...hosts].filter(Boolean);
    setSurface(targets.map((h) => ({ host: h, status: "pending" })));
    let idx = 0;
    const worker = async () => {
      while (idx < targets.length) {
        const i = idx;
        idx += 1;
        const host = targets[i];
        const r = await runQuickScan(host);
        if (r.snapshot) setCachedScan(host, "common", r.snapshot);
        setSurface((prev) =>
          prev.map((row, j) =>
            j === i
              ? { host, status: "done", score: r.score, grade: r.grade, openPorts: r.openPorts, error: r.error }
              : row
          )
        );
      }
    };
    await Promise.all(Array.from({ length: Math.min(3, targets.length) }, worker));
  };

  /** Clear saved history and update the view. */
  const handleClear = () => {
    clearHistory();
    setHistory([]);
  };

  return (
    <main className="mx-auto min-h-screen max-w-3xl px-5 py-12">
      <header className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight text-slate-100">
          Vanta<span className="text-emerald-400">sec</span>
        </h1>
        <p className="mt-1 text-sm text-slate-400">
          Scan a site or IP you own for open ports, TLS, DNS, headers, redirects, disclosure files, and known CVEs.
        </p>
      </header>

      <section className="mb-6 no-print">
        <ScanForm onScan={handleScan} busy={busy} />
      </section>

      {history.length > 0 && !busy && status === "idle" && (
        <section className="mb-8 no-print">
          <ScanHistory items={history} onRescan={(t) => handleScan(t, { preset: "common" })} onClear={handleClear} />
        </section>
      )}

      {meta && (
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            {rootTarget && meta.displayName !== rootTarget && (
              <button
                onClick={() => handleScan(rootTarget, { drill: true })}
                className="no-print rounded-lg border border-slate-700 px-2 py-1 text-xs text-slate-300 transition hover:border-slate-500 hover:text-slate-100"
                title={`Back to ${rootTarget}`}
              >
                ← {rootTarget}
              </button>
            )}
            <p className="font-mono text-xs text-slate-500">
              target: <span className="text-slate-300">{meta.displayName}</span>
            </p>
            {fromCache && status === "done" && (
              <span className="no-print flex items-center gap-2">
                <span className="rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-400">cached</span>
                <RescanPopover
                  onRescan={(opts) =>
                    handleScan(meta.displayName, { ...opts, force: true, drill: meta.displayName !== rootTarget })
                  }
                />
              </span>
            )}
          </div>
          {busy ? (
            <button
              onClick={cancel}
              className="no-print rounded-lg border border-red-700/60 px-3 py-1.5 text-xs text-red-300 transition hover:bg-red-950/40"
            >
              Cancel scan
            </button>
          ) : (
            status === "done" && <ScanActions meta={meta} results={results} score={score} />
          )}
        </div>
      )}

      {(busy || progress.total > 0) && (
        <section className="mb-8 no-print">
          <ProgressBar progress={progress} complete={status === "done"} />
        </section>
      )}

      {error && (
        <div className="mb-8 rounded-lg border border-red-700/50 bg-red-950/40 p-4 text-sm text-red-300">
          {error}
        </div>
      )}

      {score && (
        <section className="mb-6">
          <ScoreBanner score={score} />
        </section>
      )}

      {diff && status === "done" && (
        <section className="mb-6">
          <ScanDiff diff={diff} />
        </section>
      )}

      <section className="grid grid-cols-1 gap-4">
        {results.ports && <PortsCard data={results.ports} />}
        {results.cve && <CveCard data={results.cve} />}
        {results.tls && <TlsCard data={results.tls} />}
        {results.redirect && <RedirectCard data={results.redirect} />}
        {results.headers && <HeadersCard data={results.headers} />}
        {results.methods && <MethodsCard data={results.methods} />}
        {results.dns && <DnsCard data={results.dns} />}
        {results.content && <ContentCard data={results.content} />}
        {results.disclosure && <DisclosureCard data={results.disclosure} />}
        {results.geo && <GeoCard data={results.geo} />}
        {results.tree && <TreeCard data={results.tree} />}
        {results.subdomains && (
          <SubdomainsCard
            data={results.subdomains}
            onRescan={(s) => handleScan(s, { preset: "common", drill: true })}
            onScanAll={(subs) => scanAll(subs)}
          />
        )}
        {busy &&
          EXPECTED_CHECKS.filter(([k]) => !results[k]).map(([k, title]) => (
            <SkeletonCard key={k} title={title} />
          ))}
      </section>

      {surface.length > 0 && (
        <section className="mt-4">
          <AttackSurface rows={surface} onSelect={(h) => handleScan(h, { drill: true })} />
        </section>
      )}
    </main>
  );
}
