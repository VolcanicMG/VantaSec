"use client";

/**
 * useScan — client-side hook that drives a streaming scan.
 *
 * Single responsibility: POST to /api/scan, parse the NDJSON event stream, and
 * expose reactive state (progress, per-check results, status) to the UI. It
 * owns no presentation — components read its return value and render.
 */

import { useCallback, useRef, useState } from "react";

/** @typedef {"idle"|"scanning"|"done"|"error"} ScanStatus */

/**
 * @returns {{
 *   status: ScanStatus,
 *   meta: (object|null),
 *   progress: {done:number,total:number,phase:string},
 *   results: Record<string, object>,
 *   error: (string|null),
 *   start: (target:string, opts?:object)=>Promise<void>,
 *   reset: ()=>void,
 * }}
 */
export function useScan() {
  const [status, setStatus] = useState("idle");
  const [meta, setMeta] = useState(null);
  const [progress, setProgress] = useState({ done: 0, total: 0, phase: "" });
  const [results, setResults] = useState({});
  const [score, setScore] = useState(null);
  const [error, setError] = useState(null);
  const abortRef = useRef(null);
  const cancelledRef = useRef(false);

  /**
   * Load a previously-cached scan snapshot into state without re-scanning.
   * Leaves the hook in the "done" state as if the scan had just finished.
   * @param {{meta:object, results:object, score:object}} snapshot - Cached result.
   */
  const hydrate = useCallback((snapshot) => {
    cancelledRef.current = false;
    abortRef.current?.abort();
    setError(null);
    setMeta(snapshot.meta || null);
    setResults(snapshot.results || {});
    setScore(snapshot.score || null);
    setProgress({ done: 0, total: 0, phase: "" });
    setStatus("done");
  }, []);

  /** Clear all state back to the initial idle view. */
  const reset = useCallback(() => {
    setStatus("idle");
    setMeta(null);
    setProgress({ done: 0, total: 0, phase: "" });
    setResults({});
    setScore(null);
    setError(null);
    cancelledRef.current = false;
  }, []);

  /**
   * Kick off a scan and consume the streamed events.
   *
   * @param {string} target - Host, IP, or URL to scan.
   * @param {object} [opts] - { preset, from, to } forwarded to the API.
   */
  const start = useCallback(async (target, opts = {}) => {
    reset();
    setStatus("scanning");

    const controller = new AbortController();
    abortRef.current = controller;

    let res;
    try {
      res = await fetch("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ target, ...opts }),
        signal: controller.signal,
      });
    } catch (err) {
      setError(err.message);
      setStatus("error");
      return;
    }

    if (!res.ok || !res.body) {
      setError(`Server responded ${res.status}`);
      setStatus("error");
      return;
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    // Read the stream chunk-by-chunk, splitting on newlines into JSON events.
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        let nl;
        while ((nl = buffer.indexOf("\n")) >= 0) {
          const line = buffer.slice(0, nl).trim();
          buffer = buffer.slice(nl + 1);
          if (!line) continue;
          let event;
          try {
            event = JSON.parse(line);
          } catch {
            continue;
          }
          applyEvent(event, { setMeta, setProgress, setResults, setScore, setError, setStatus });
        }
      }
    } catch (err) {
      // A user-initiated cancel aborts the fetch; that's not an error.
      if (!cancelledRef.current) {
        setError(err.message);
        setStatus("error");
        return;
      }
    }

    setStatus((s) => (cancelledRef.current ? "idle" : s === "error" ? s : "done"));
  }, [reset]);

  /** Cancel an in-flight scan; aborts the stream and returns to idle. */
  const cancel = useCallback(() => {
    cancelledRef.current = true;
    abortRef.current?.abort();
  }, []);

  return { status, meta, progress, results, score, error, start, cancel, reset, hydrate };
}

/**
 * Fold a single scan event into React state.
 *
 * @param {{type:string,data:*}} event - One parsed NDJSON event.
 * @param {object} setters - State setter functions from the hook.
 */
function applyEvent(event, setters) {
  const { setMeta, setProgress, setResults, setScore, setError, setStatus } = setters;
  switch (event.type) {
    case "meta":
      setMeta(event.data);
      break;
    case "phase":
      setProgress((p) => ({ ...p, phase: event.data.phase, total: event.data.total ?? p.total }));
      break;
    case "progress":
      setProgress((p) => ({ ...p, done: event.data.done, total: event.data.total }));
      break;
    case "result":
      setResults((r) => ({ ...r, [event.data.check]: event.data }));
      break;
    case "score":
      setScore(event.data);
      break;
    case "error":
      setError(event.data.message);
      setStatus("error");
      break;
    default:
      break;
  }
}
