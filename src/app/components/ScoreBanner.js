"use client";

/**
 * ScoreBanner — the headline security verdict.
 *
 * Single responsibility: render the overall 0-100 score, its letter grade, and
 * the top point-costing findings. Purely presentational — the score is
 * computed server-side by score.js.
 */

/** Grade -> tailwind color classes for ring/text. */
const GRADE_COLORS = {
  A: "text-emerald-400 border-emerald-500/60",
  B: "text-emerald-300 border-emerald-500/50",
  C: "text-amber-400 border-amber-500/60",
  D: "text-orange-400 border-orange-500/60",
  F: "text-red-400 border-red-500/60",
};

/** Severity -> dot color. */
const SEV_DOT = { high: "bg-red-500", medium: "bg-amber-500", low: "bg-slate-500" };

/**
 * @param {object} props
 * @param {{score:number, grade:string, findings:Array<{label:string,points:number,severity:string}>}} props.score
 * @returns {JSX.Element|null}
 */
export default function ScoreBanner({ score }) {
  if (!score) return null;
  const color = GRADE_COLORS[score.grade] || GRADE_COLORS.F;
  const top = score.findings.slice(0, 5);

  return (
    <div className={`flex flex-col gap-4 rounded-xl border bg-slate-900/60 p-5 sm:flex-row sm:items-center ${color}`}>
      <div className="flex items-center gap-4">
        <div className={`flex h-20 w-20 shrink-0 items-center justify-center rounded-full border-2 ${color}`}>
          <span className="text-4xl font-bold">{score.grade}</span>
        </div>
        <div>
          <p className="text-3xl font-bold text-slate-100">
            {score.score}
            <span className="text-base font-normal text-slate-500">/100</span>
          </p>
          <p className="text-xs uppercase tracking-wider text-slate-400">Security score</p>
        </div>
      </div>
      <div className="flex-1 sm:border-l sm:border-slate-700 sm:pl-5">
        {top.length === 0 ? (
          <p className="text-sm text-emerald-400">No issues found — nicely locked down.</p>
        ) : (
          <ul className="space-y-1 text-sm">
            {top.map((f, i) => (
              <li key={i} className="text-slate-300">
                <div className="flex items-center justify-between gap-3">
                  <span className="flex items-center gap-2">
                    <span className={`h-2 w-2 shrink-0 rounded-full ${SEV_DOT[f.severity] || SEV_DOT.low}`} />
                    {f.label}
                  </span>
                  <span className="font-mono text-xs text-slate-500">-{f.points}</span>
                </div>
                {f.fix && <p className="ml-4 mt-0.5 text-xs text-slate-500">↳ {f.fix}</p>}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
