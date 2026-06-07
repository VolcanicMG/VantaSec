/**
 * POST /api/scan — stream a live scan as newline-delimited JSON (NDJSON).
 *
 * Single responsibility: adapt the runScan() generator to an HTTP streaming
 * response. Each yielded event is written as one JSON line, so the browser can
 * render progress in real time without websockets.
 *
 * Request body: { target: string, preset?: "top"|"common"|"range", from?, to? }
 */

import { runScan } from "@/lib/scanner/index.js";
import { rateLimit } from "@/lib/rateLimit.js";

// Port/TLS/DNS sockets require the Node.js runtime (not the Edge runtime).
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Handle a scan request and stream results.
 *
 * @param {Request} request - Incoming request with a JSON body.
 * @returns {Response} A streaming NDJSON response.
 */
export async function POST(request) {
  // Per-IP rate limit (in-memory) to blunt casual abuse of the scan API.
  const ip =
    request.headers.get("x-forwarded-for")?.split(",")[0].trim() ||
    request.headers.get("x-real-ip") ||
    "local";
  const limit = rateLimit(ip);
  if (!limit.allowed) {
    return Response.json(
      { error: "Rate limit exceeded — please wait a moment and try again." },
      { status: 429, headers: { "retry-after": String(limit.retryAfter) } }
    );
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const { target, preset, from, to } = body || {};
  if (!target) {
    return Response.json({ error: "Missing 'target'" }, { status: 400 });
  }

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      try {
        for await (const event of runScan(target, { preset, from, to })) {
          controller.enqueue(encoder.encode(JSON.stringify(event) + "\n"));
        }
      } catch (err) {
        controller.enqueue(
          encoder.encode(JSON.stringify({ type: "error", data: { message: err.message } }) + "\n")
        );
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "content-type": "application/x-ndjson; charset=utf-8",
      "cache-control": "no-cache, no-transform",
    },
  });
}
