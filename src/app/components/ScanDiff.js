"use client";

/**
 * ScanDiff — "what changed since last scan" banner.
 *
 * Single responsibility: render the delta between the current scan and the most
 * recent previous scan of the same target (score move, ports opened/closed,
 * CVEs gained/resolved). Purely presentational — the diff is computed in
 * history.js (diffScans) and passed in. Renders nothing without a prior scan.
 */

/**
 * @param {object} props
 * @param {{prevAt:number, scoreDelta:number, portsOpened:number[],
 *   portsClosed:number[], cvesNew:string[], cvesResolved:string[]}|null} props.diff
 * @returns {JSX.Element|null}
 */
export default function ScanDiff({ diff }) {
  if (!diff) return null;
  const { scoreDelta, portsOpened, portsClosed, cvesNew, cvesResolved, prevAt } = diff;
  const nothingChanged =
    scoreDelta === 0 &&
    portsOpened.length === 0 &&
    portsClosed.length === 0 &&
    cvesNew.length === 0 &&
    cvesResolved.length === 0;

  const when = prevAt ? new Date(prevAt).toLocaleString() : "last scan";

  return (
    <div className="rounded-xl border border-slate-700 bg-slate-900/60 p-4 text-sm">
      <p className="mb-2 text-xs uppercase tracking-wider text-slate-400">Changes since {when}</p>
      {nothingChanged ? (
        <p className="text-slate-400">No changes since the last scan of this target.</p>
      ) : (
        <ul className="space-y-1">
          {scoreDelta !== 0 && (
            <li className={scoreDelta > 0 ? "text-emerald-400" : "text-red-400"}>
              Score {scoreDelta > 0 ? "\u25b2" : "\u25bc"} {Math.abs(scoreDelta)} points
            </li>
          )}
          {portsOpened.length > 0 && (
            <li className="text-red-400">Newly open ports: {portsOpened.join(", ")}</li>
          )}
          {portsClosed.length > 0 && (
            <li className="text-emerald-400">Closed ports: {portsClosed.join(", ")}</li>
          )}
          {cvesNew.length > 0 && (
            <li className="text-red-400">New CVEs: {cvesNew.join(", ")}</li>
          )}
          {cvesResolved.length > 0 && (
            <li className="text-emerald-400">Resolved CVEs: {cvesResolved.join(", ")}</li>
          )}
        </ul>
      )}
    </div>
  );
}
