"use client";

/**
 * ScanActions — export/share controls for a finished scan.
 *
 * Single responsibility: turn the in-memory scan result into a downloadable
 * JSON file or a copyable text summary. Purely a view + clipboard/file glue;
 * it derives everything from the props it is given.
 */

import { useState } from "react";

/**
 * Build a plain-text summary of the scan suitable for pasting into a ticket.
 *
 * @param {object} meta - Scan meta ({ displayName }).
 * @param {object} results - Collected results by check.
 * @param {object} score - { score, grade, findings }.
 * @returns {string} Multi-line summary.
 */
function buildSummary(meta, results, score) {
  const lines = [];
  lines.push(`Vantasec scan — ${meta?.displayName || "target"}`);
  if (score) lines.push(`Score: ${score.score}/100 (grade ${score.grade})`);
  const open = results.ports?.openPorts || [];
  lines.push(`Open ports: ${open.length ? open.map((p) => `${p.port}/${p.service}`).join(", ") : "none"}`);
  if (score?.findings?.length) {
    lines.push("Findings:");
    for (const f of score.findings) lines.push(`  - [-${f.points}] ${f.label}`);
  }
  return lines.join("\n");
}

/**
 * @param {object} props
 * @param {object} props.meta - Scan meta.
 * @param {object} props.results - Collected results.
 * @param {object} props.score - Score payload.
 * @returns {JSX.Element}
 */
export default function ScanActions({ meta, results, score }) {
  const [copied, setCopied] = useState(false);

  /** Download the full result set as a JSON file. */
  const downloadJson = () => {
    const payload = { target: meta?.displayName, generatedAt: new Date().toISOString(), score, results };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `vantasec-${meta?.displayName || "scan"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  /** Copy a text summary to the clipboard. */
  const copySummary = async () => {
    await navigator.clipboard.writeText(buildSummary(meta, results, score));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  /**
   * Print the report. Native <details> sections are collapsed by default and
   * won't render their content in print, so expand them all first, then restore
   * their state once printing finishes.
   */
  const printReport = () => {
    if (typeof window === "undefined") return;
    const all = Array.from(document.querySelectorAll("details"));
    const prev = all.map((d) => d.open);
    all.forEach((d) => {
      d.open = true;
    });
    const restore = () => {
      all.forEach((d, i) => {
        d.open = prev[i];
      });
      window.removeEventListener("afterprint", restore);
    };
    window.addEventListener("afterprint", restore);
    window.print();
  };

  return (
    <div className="flex gap-2 no-print">
      <button
        onClick={downloadJson}
        className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 transition hover:border-slate-500 hover:text-slate-100"
      >
        Download JSON
      </button>
      <button
        onClick={copySummary}
        className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 transition hover:border-slate-500 hover:text-slate-100"
      >
        {copied ? "Copied!" : "Copy summary"}
      </button>
      <button
        onClick={printReport}
        className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 transition hover:border-slate-500 hover:text-slate-100"
      >
        Print / PDF
      </button>
    </div>
  );
}
