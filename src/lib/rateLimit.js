/**
 * In-memory per-key fixed-window rate limiter.
 *
 * Single responsibility: track request counts per key (client IP) within a
 * fixed time window and report whether a new request is allowed. Process-local
 * only — it resets on restart and is not shared across instances — which is
 * enough to blunt casual abuse of the scan API on a single-instance deploy.
 */

/** Default window length in ms. */
const WINDOW_MS = 60_000;
/** Default max requests allowed per key per window. */
const MAX_PER_WINDOW = 20;

/** key -> { count, resetAt }. Module-scoped so it persists across requests. */
const buckets = new Map();

/**
 * Record a hit for `key` and report whether it is within the limit.
 *
 * @param {string} key - Identifier to bucket on (e.g. client IP).
 * @param {object} [opts]
 * @param {number} [opts.windowMs=60000] - Window length in ms.
 * @param {number} [opts.max=10] - Max requests per window.
 * @returns {{allowed:boolean, remaining:number, retryAfter:number, limit:number}}
 */
export function rateLimit(key, { windowMs = WINDOW_MS, max = MAX_PER_WINDOW } = {}) {
  const now = Date.now();
  let bucket = buckets.get(key);
  if (!bucket || now >= bucket.resetAt) {
    bucket = { count: 0, resetAt: now + windowMs };
    buckets.set(key, bucket);
  }
  bucket.count += 1;

  // Opportunistic cleanup so the map can't grow unbounded on a long-lived process.
  if (buckets.size > 5000) {
    for (const [k, v] of buckets) {
      if (now >= v.resetAt) buckets.delete(k);
    }
  }

  return {
    allowed: bucket.count <= max,
    remaining: Math.max(0, max - bucket.count),
    retryAfter: Math.ceil((bucket.resetAt - now) / 1000),
    limit: max,
  };
}
