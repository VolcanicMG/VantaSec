"use client";

/**
 * ScanHistory — recent-scans list.
 *
 * Single responsibility: render saved scan summaries and let the user re-run
 * one or clear the list. Receives data + callbacks via props (it does not read
 * storage itself), keeping it a pure presentational component.
 */

/** Grade -> text color. */
const GRADE_COLOR = {
  A: "text-emerald-400",
  B: "text-emerald-300",
  C: "text-amber-400",
  D: "text-orange-400",
  F: "text-red-400",
};

/**
 * @param {object} props
 * @param {Array<{target:string, score:number, grade:string, at:number}>} props.items - History entries.
 * @param {(target:string)=>void} props.onRescan - Re-run a scan for a target.
 * @param {()=>void} props.onClear - Clear the history.
 * @returns {JSX.Element|null}
 */
export default function ScanHistory({ items, onRescan, onClear }) {
  if (!items?.length) return null;
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
      <div className="mb-2 flex items-center justify-between">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Recent scans</h3>
        <button onClick={onClear} className="text-xs text-slate-500 hover:text-slate-300">
          Clear
        </button>
      </div>
      <ul className="space-y-1">
        {items.map((it, i) => (
          <li key={`${it.target}-${it.at}-${i}`}>
            <button
              onClick={() => onRescan(it.target)}
              className="flex w-full items-center justify-between gap-3 rounded px-2 py-1.5 text-left text-sm transition hover:bg-slate-800/60"
            >
              <span className="font-mono text-slate-300">{it.target}</span>
              <span className="flex items-center gap-2 text-xs">
                <span className={GRADE_COLOR[it.grade] || "text-slate-400"}>
                  {it.grade} · {it.score}
                </span>
                <span className="text-slate-600">{new Date(it.at).toLocaleDateString()}</span>
              </span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
