"use client";

/**
 * Cache of completed scans, backed by sessionStorage so it survives a page
 * reload within the same tab (and clears when the tab closes).
 *
 * Single responsibility: store and retrieve full scan snapshots keyed by
 * target + preset, so the UI can revisit a host (or a previously-pivoted
 * subdomain) without re-scanning it. SSR-safe (no-ops on the server); writes
 * that exceed the storage quota are swallowed (the in-memory copy still works).
 */

const STORAGE_KEY = "vantasec.scanCache";

/** In-memory mirror; the source of truth, persisted to sessionStorage on write. */
let cache = null;

/** @param {string} target @param {string} [preset="common"] @returns {string} */
function keyOf(target, preset = "common") {
  return `${String(target).toLowerCase()}|${preset}`;
}

/** Lazily load the cache from sessionStorage (once). */
function ensure() {
  if (cache) return cache;
  cache = new Map();
  if (typeof window === "undefined") return cache;
  try {
    const raw = window.sessionStorage.getItem(STORAGE_KEY);
    if (raw) cache = new Map(Object.entries(JSON.parse(raw)));
  } catch {
    cache = new Map();
  }
  return cache;
}

/** Persist the in-memory cache to sessionStorage (best-effort). */
function persist() {
  if (typeof window === "undefined") return;
  try {
    window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(Object.fromEntries(cache)));
  } catch {
    // Quota exceeded or storage unavailable — keep the in-memory copy only.
  }
}

/**
 * Get a cached snapshot, or null.
 * @param {string} target @param {string} [preset] @returns {object|null}
 */
export function getCachedScan(target, preset) {
  return ensure().get(keyOf(target, preset)) || null;
}

/**
 * Store a scan snapshot (and persist).
 * @param {string} target @param {string} preset
 * @param {{meta:object, results:object, score:object}} snapshot
 */
export function setCachedScan(target, preset, snapshot) {
  ensure().set(keyOf(target, preset), { ...snapshot, at: Date.now() });
  persist();
}

/**
 * Whether a snapshot is cached.
 * @param {string} target @param {string} [preset] @returns {boolean}
 */
export function hasCachedScan(target, preset) {
  return ensure().has(keyOf(target, preset));
}
