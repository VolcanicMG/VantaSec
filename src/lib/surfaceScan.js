"use client";

/**
 * Quick-scan client for the attack-surface pivot.
 *
 * Single responsibility: POST /api/scan for one host and return only the summary
 * verdict (score, grade, open-port count), discarding per-check detail. Lets the
 * dashboard scan many discovered subdomains without rendering each in full.
 */

/**
 * Run a scan and return its headline result.
 *
 * @param {string} target - Host to scan.
 * @param {object} [opts]
 * @param {AbortSignal} [opts.signal] - Optional abort signal.
 * @param {string} [opts.preset="common"] - Port preset.
 * @returns {Promise<{target:string, score:(number|null), grade:(string|null), openPorts:number, snapshot?:object, error?:string}>}
 */
export async function runQuickScan(target, opts = {}) {
  const { signal, preset = "common" } = opts;
  let res;
  try {
    res = await fetch("/api/scan", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ target, preset }),
      signal,
    });
  } catch (err) {
    return { target, score: null, grade: null, openPorts: 0, error: err.message };
  }
  if (res.status === 429) return { target, score: null, grade: null, openPorts: 0, error: "rate limited" };
  if (!res.ok || !res.body) return { target, score: null, grade: null, openPorts: 0, error: `server ${res.status}` };

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let meta = null;
  const results = {};
  let score = null;
  let openPorts = 0;
  let errored = null;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let nl;
      while ((nl = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, nl).trim();
        buffer = buffer.slice(nl + 1);
        if (!line) continue;
        let ev;
        try {
          ev = JSON.parse(line);
        } catch {
          continue;
        }
        if (ev.type === "meta") meta = ev.data;
        else if (ev.type === "score") score = ev.data;
        else if (ev.type === "result") {
          results[ev.data.check] = ev.data;
          if (ev.data.check === "ports") openPorts = (ev.data.openPorts || []).length;
        } else if (ev.type === "error") errored = ev.data.message;
      }
    }
  } catch (err) {
    return { target, score: null, grade: null, openPorts: 0, error: err.message };
  }
  if (errored) return { target, score: null, grade: null, openPorts: 0, error: errored };
  // The full snapshot lets the caller cache it so revisiting the host needs no rescan.
  return {
    target,
    score: score?.score ?? null,
    grade: score?.grade ?? null,
    openPorts,
    snapshot: { meta, results, score },
  };
}
