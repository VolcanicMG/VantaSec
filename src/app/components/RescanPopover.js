"use client";

/**
 * RescanPopover — a "Re-scan" button that opens a modal popout to choose the
 * port preset (and a custom range) before re-running a scan.
 *
 * Single responsibility: collect rescan options and hand them to a callback. It
 * owns only its open/preset state; the actual scan is run by the parent. The
 * options UI is a centered modal overlay (dimmed backdrop), not an inline panel.
 */

import { useEffect, useState } from "react";

/**
 * @param {object} props
 * @param {(opts:{preset:string, from?:number, to?:number})=>void} props.onRescan
 *   Called with the chosen options when the user confirms.
 * @returns {JSX.Element}
 */
export default function RescanPopover({ onRescan }) {
  const [open, setOpen] = useState(false);
  const [preset, setPreset] = useState("common");
  const [from, setFrom] = useState(1);
  const [to, setTo] = useState(1024);

  // Close the modal on Escape while it's open.
  useEffect(() => {
    if (!open) return undefined;
    const onKey = (e) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open]);

  /** Confirm and run the scan with the chosen options. */
  const run = () => {
    const opts = { preset };
    if (preset === "range") {
      opts.from = Number(from);
      opts.to = Number(to);
    }
    setOpen(false);
    onRescan(opts);
  };

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="rounded-lg border border-slate-700 px-2 py-1 text-xs text-slate-300 transition hover:border-slate-500 hover:text-slate-100"
      >
        Re-scan…
      </button>

      {open && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
          onClick={() => setOpen(false)}
          role="presentation"
        >
          <div
            className="w-full max-w-sm rounded-xl border border-slate-700 bg-slate-900 p-5 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-label="Re-scan options"
          >
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200">Re-scan</h3>
              <button
                type="button"
                onClick={() => setOpen(false)}
                aria-label="Close"
                className="text-slate-500 transition hover:text-slate-200"
              >
                {"✕"}
              </button>
            </div>

            <label className="block text-xs text-slate-400">
              Port preset
              <select
                value={preset}
                onChange={(e) => setPreset(e.target.value)}
                className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200"
              >
                <option value="top">Top (~17 ports, fastest)</option>
                <option value="common">Common</option>
                <option value="range">Custom range</option>
              </select>
            </label>

            {preset === "range" && (
              <div className="mt-3 flex items-center gap-2 text-xs text-slate-400">
                <input
                  type="number"
                  min="1"
                  max="65535"
                  value={from}
                  onChange={(e) => setFrom(e.target.value)}
                  className="w-full rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200"
                  aria-label="From port"
                />
                <span>to</span>
                <input
                  type="number"
                  min="1"
                  max="65535"
                  value={to}
                  onChange={(e) => setTo(e.target.value)}
                  className="w-full rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200"
                  aria-label="To port"
                />
              </div>
            )}

            <div className="mt-5 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setOpen(false)}
                className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 transition hover:border-slate-500 hover:text-slate-100"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={run}
                className="rounded-lg bg-emerald-600 px-4 py-1.5 text-xs font-medium text-white transition hover:bg-emerald-500"
              >
                Run scan
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
