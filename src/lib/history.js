"use client";

/**
 * Scan history persistence.
 *
 * Single responsibility: store and retrieve a short list of recent scan
 * summaries in localStorage. Holds no UI and no scanning logic — just the
 * read/write/clear primitives, guarded for server-side rendering.
 */

const KEY = "vantasec.history";
const MAX = 10;

/**
 * Load the saved scan history (most-recent first).
 *
 * @returns {Array<{target:string, score:number, grade:string, at:number, ports?:number[], cves?:string[]}>}
 */
export function loadHistory() {
  if (typeof window === "undefined") return [];
  try {
    return JSON.parse(window.localStorage.getItem(KEY) || "[]");
  } catch {
    return [];
  }
}

/**
 * Prepend a scan summary to the history, capped at MAX entries.
 *
 * @param {{target:string, score:number, grade:string, at:number, ports?:number[], cves?:string[]}} entry - Summary to add.
 * @returns {Array} The updated history list.
 */
export function addHistory(entry) {
  if (typeof window === "undefined") return [];
  const next = [entry, ...loadHistory()].slice(0, MAX);
  window.localStorage.setItem(KEY, JSON.stringify(next));
  return next;
}

/**
 * Find the most recent stored scan for a target (to diff a new run against it).
 * History is most-recent-first, so the first match is the latest prior scan.
 *
 * @param {string} target - Target display name to match.
 * @returns {object|null} The latest matching entry, or null if none.
 */
export function previousFor(target) {
  return loadHistory().find((e) => e.target === target) || null;
}

/**
 * Compute the delta between a previous and current scan of the same target.
 *
 * @param {object|null} prev - Previous entry ({ score, ports[], cves[], at }).
 * @param {{score:number, ports:number[], cves:string[]}} curr - Current summary.
 * @returns {null|{prevAt:number, scoreDelta:number, portsOpened:number[],
 *   portsClosed:number[], cvesNew:string[], cvesResolved:string[]}}
 *   Diff, or null when there's no comparable previous scan.
 */
export function diffScans(prev, curr) {
  if (!prev) return null;
  const prevPorts = prev.ports || [];
  const currPorts = curr.ports || [];
  const prevCves = prev.cves || [];
  const currCves = curr.cves || [];
  return {
    prevAt: prev.at,
    scoreDelta: (curr.score ?? 0) - (prev.score ?? 0),
    portsOpened: currPorts.filter((p) => !prevPorts.includes(p)),
    portsClosed: prevPorts.filter((p) => !currPorts.includes(p)),
    cvesNew: currCves.filter((c) => !prevCves.includes(c)),
    cvesResolved: prevCves.filter((c) => !currCves.includes(c)),
  };
}

/**
 * Clear all saved scan history.
 * @returns {void}
 */
export function clearHistory() {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(KEY);
}
