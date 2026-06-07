#!/usr/bin/env node
/**
 * vantasec-scan — command-line scanner / CI gate.
 *
 * Single responsibility: run a scan from the terminal and (optionally) fail the
 * process when the result is below a score/grade threshold, so teams can gate a
 * pipeline on it. Reuses the same scanner the web app uses — no duplicate logic.
 *
 * Usage:
 *   node bin/vantasec-scan.mjs <target> [options]
 *   npm run scan -- <target> [options]
 *
 * Options:
 *   --preset <common|top|range>   Port preset (default: common)
 *   --min-score <0-100>           Fail (exit 1) if the score is below this
 *   --min-grade <A-F>             Fail (exit 1) if the grade is below this
 *   --json                        Print the full result as JSON
 *
 * Exit codes: 0 = passed, 1 = below threshold, 2 = scan or usage error.
 */

import { runScan } from "../src/lib/scanner/index.js";

const GRADE_RANK = { A: 5, B: 4, C: 3, D: 2, F: 1 };

/**
 * Parse argv into an options object.
 * @param {string[]} argv - Arguments after the script name.
 * @returns {{target?:string, preset:string, minScore:(number|null), minGrade:(string|null), json:boolean}}
 */
function parseArgs(argv) {
  const out = { target: undefined, preset: "common", minScore: null, minGrade: null, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") out.json = true;
    else if (a === "--preset") out.preset = argv[++i];
    else if (a === "--min-score") out.minScore = Number(argv[++i]);
    else if (a === "--min-grade") out.minGrade = String(argv[++i] || "").toUpperCase();
    else if (!a.startsWith("-") && !out.target) out.target = a;
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
if (!args.target) {
  console.error("Usage: vantasec-scan <target> [--preset common|top|range] [--min-score N] [--min-grade A-F] [--json]");
  process.exit(2);
}

let score = null;
const results = {};
try {
  for await (const ev of runScan(args.target, { preset: args.preset })) {
    if (ev.type === "result") results[ev.data.check] = ev.data;
    else if (ev.type === "score") score = ev.data;
    else if (ev.type === "error") {
      console.error(`Scan error: ${ev.data.message}`);
      process.exit(2);
    }
  }
} catch (err) {
  console.error(`Scan failed: ${err.message}`);
  process.exit(2);
}

if (args.json) {
  console.log(JSON.stringify({ target: args.target, score, results }, null, 2));
} else {
  const openPorts = results.ports?.openPorts || [];
  console.log(`\nVantasec scan — ${args.target}`);
  console.log(`Score: ${score ? `${score.score}/100 (grade ${score.grade})` : "n/a"}`);
  console.log(`Open ports: ${openPorts.length ? openPorts.map((p) => `${p.port}/${p.service}`).join(", ") : "none"}`);
  if (score?.findings?.length) {
    console.log("Top findings:");
    for (const f of score.findings.slice(0, 8)) console.log(`  - [-${f.points}] ${f.label}`);
  }
  console.log("");
}

// Threshold gate.
let failed = false;
if (args.minScore != null && !Number.isNaN(args.minScore) && (score?.score ?? 0) < args.minScore) {
  console.error(`FAIL: score ${score?.score ?? 0} is below --min-score ${args.minScore}`);
  failed = true;
}
if (args.minGrade && GRADE_RANK[args.minGrade] && (GRADE_RANK[score?.grade] ?? 0) < GRADE_RANK[args.minGrade]) {
  console.error(`FAIL: grade ${score?.grade ?? "n/a"} is below --min-grade ${args.minGrade}`);
  failed = true;
}
process.exit(failed ? 1 : 0);
