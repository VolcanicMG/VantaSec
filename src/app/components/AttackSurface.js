"use client";

/**
 * AttackSurface — rollup of an opt-in multi-host pivot scan.
 *
 * Single responsibility: render each scanned host (the main target + discovered
 * subdomains) with its grade/score as results stream in. Purely presentational;
 * the scanning/concurrency is orchestrated by the page via runQuickScan.
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
 * @param {Array<{host:string, status:string, score?:number, grade?:string, openPorts?:number, error?:string}>} props.rows
 * @param {(host:string)=>void} [props.onSelect] - Load a finished host's (cached) full scan.
 * @returns {JSX.Element|null}
 */
export default function AttackSurface({ rows, onSelect }) {
  if (!rows?.length) return null;
  const done = rows.filter((r) => r.status === "done").length;
  return (
    <div className="rounded-xl border border-slate-700 bg-slate-900/60 p-5">
      <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-300">
        Attack surface <span className="text-slate-500">({done}/{rows.length})</span>
      </h3>
      <ul className="space-y-1 text-sm">
        {rows.map((r) => {
          const clickable = r.status === "done" && !r.error && onSelect;
          return (
            <li key={r.host} className="flex items-center justify-between gap-3">
              {clickable ? (
                <button
                  type="button"
                  onClick={() => onSelect(r.host)}
                  className="break-all text-left font-mono text-slate-300 transition hover:text-emerald-400 hover:underline"
                  title={`View ${r.host} (cached)`}
                >
                  {r.host}
                </button>
              ) : (
                <span className="break-all font-mono text-slate-300">{r.host}</span>
              )}
              {r.status === "pending" ? (
                <span className="text-xs text-slate-500">scanning…</span>
              ) : r.error ? (
                <span className="text-xs text-red-400">{r.error}</span>
              ) : (
                <span className="flex items-center gap-2 text-xs">
                  <span className="text-slate-500">{r.openPorts} open · {r.score}/100</span>
                  <span className={`font-bold ${GRADE_COLOR[r.grade] || "text-slate-400"}`}>{r.grade}</span>
                </span>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
