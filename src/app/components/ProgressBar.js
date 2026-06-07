"use client";

/**
 * ProgressBar — live scan progress indicator.
 *
 * Single responsibility: while a scan runs, render the current phase and a fill
 * bar from a done/total pair; once finished, render a completion indicator (a
 * check icon + label) in place of the bar. Purely presentational.
 */

/**
 * @param {object} props
 * @param {{done:number,total:number,phase:string}} props.progress - Scan progress state.
 * @param {boolean} [props.complete] - True once the scan has fully finished.
 * @returns {JSX.Element|null}
 */
export default function ProgressBar({ progress, complete }) {
  const { done, total, phase } = progress;
  if (!total && phase !== "services" && phase !== "cve" && phase !== "subdomains") return null;

  // Finished: drop the bar entirely and show a check icon + completion text.
  if (complete) {
    return (
      <div className="flex items-center gap-2 text-sm font-medium text-emerald-400">
        <svg
          xmlns="http://www.w3.org/2000/svg"
          viewBox="0 0 20 20"
          fill="currentColor"
          aria-hidden="true"
          className="h-5 w-5 shrink-0"
        >
          <path
            fillRule="evenodd"
            d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z"
            clipRule="evenodd"
          />
        </svg>
        <span>Scan complete</span>
      </div>
    );
  }

  // The bar advances through the scan's phases but tops out at ~95% before the
  // final result lands — it never reads "done" while CVE/subdomain data is still
  // being fetched. The port scan owns the first 60%; the parallel service checks,
  // the CVE lookup, and subdomain discovery fill the rest.
  const portPct = total ? Math.round((done / total) * 100) : 100;
  const pct =
    phase === "subdomains"
      ? 95
      : phase === "cve"
        ? 90
        : phase === "services"
          ? 70
          : Math.round(portPct * 0.6);

  const label =
    phase === "subdomains"
      ? "Discovering subdomains (CT logs)…"
      : phase === "cve"
        ? "Checking known CVEs…"
        : phase === "services"
          ? "Running TLS, DNS, headers, redirect & disclosure checks…"
          : `Scanning ports ${done}/${total}`;

  // The post-port phases have no granular progress, so pulse the fill to signal
  // ongoing work rather than implying the partial bar is stalled.
  const working = phase === "services" || phase === "cve" || phase === "subdomains";

  return (
    <div className="w-full">
      <div className="mb-1 flex justify-between text-xs text-slate-400">
        <span>{label}</span>
        <span>{`${pct}%`}</span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
        <div
          className={`h-full rounded-full bg-emerald-500 transition-all duration-300 ${working ? "animate-pulse" : ""}`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}
