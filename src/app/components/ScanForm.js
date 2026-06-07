"use client";

/**
 * ScanForm — target input + scan options.
 *
 * Single responsibility: collect the target and port-preset choice, then hand
 * them to a parent callback. Holds no scan logic or results.
 */

import { useState } from "react";

/**
 * @param {object} props
 * @param {(target:string, opts:object)=>void} props.onScan - Invoked on submit.
 * @param {boolean} props.busy - Disables the form while a scan runs.
 * @returns {JSX.Element}
 */
export default function ScanForm({ onScan, busy }) {
  const [target, setTarget] = useState("");
  const [preset, setPreset] = useState("common");
  const [from, setFrom] = useState(1);
  const [to, setTo] = useState(1024);

  /**
   * Validate and forward the submission.
   * @param {React.FormEvent} e - Form submit event.
   */
  const handleSubmit = (e) => {
    e.preventDefault();
    const t = target.trim();
    if (!t || busy) return;
    // For a custom range, forward numeric bounds the API understands.
    onScan(t, preset === "range" ? { preset, from: Number(from), to: Number(to) } : { preset });
  };

  return (
    <form onSubmit={handleSubmit} className="w-full">
      <div className="flex flex-col gap-3 sm:flex-row">
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="example.com or 203.0.113.10"
          disabled={busy}
          className="flex-1 rounded-lg border border-slate-700 bg-slate-900/60 px-4 py-3 font-mono text-sm text-slate-100 placeholder:text-slate-500 focus:border-emerald-500 focus:outline-none disabled:opacity-50"
        />
        <select
          value={preset}
          onChange={(e) => setPreset(e.target.value)}
          disabled={busy}
          className="rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-3 text-sm text-slate-200 focus:border-emerald-500 focus:outline-none disabled:opacity-50"
        >
          <option value="top">Top ports (fast)</option>
          <option value="common">Common ports</option>
          <option value="range">Custom range…</option>
        </select>
        <button
          type="submit"
          disabled={busy || !target.trim()}
          className="rounded-lg bg-emerald-500 px-6 py-3 text-sm font-semibold text-slate-950 transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {busy ? "Scanning…" : "Scan"}
        </button>
      </div>
      {preset === "range" && (
        <div className="mt-3 flex items-center gap-2 text-sm">
          <span className="text-slate-400">Ports</span>
          <input
            type="number"
            min={1}
            max={65535}
            value={from}
            onChange={(e) => setFrom(e.target.value)}
            disabled={busy}
            className="w-24 rounded-lg border border-slate-700 bg-slate-900/60 px-2 py-2 font-mono text-slate-100 focus:border-emerald-500 focus:outline-none disabled:opacity-50"
          />
          <span className="text-slate-500">to</span>
          <input
            type="number"
            min={1}
            max={65535}
            value={to}
            onChange={(e) => setTo(e.target.value)}
            disabled={busy}
            className="w-24 rounded-lg border border-slate-700 bg-slate-900/60 px-2 py-2 font-mono text-slate-100 focus:border-emerald-500 focus:outline-none disabled:opacity-50"
          />
          <span className="text-xs text-slate-600">(max 2048 ports scanned)</span>
        </div>
      )}
      <p className="mt-2 text-xs text-slate-500">
        Only scan systems you own or are authorized to test.
      </p>
    </form>
  );
}
