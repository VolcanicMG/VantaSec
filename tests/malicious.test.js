/**
 * Malicious-input / "can a scanned target hit back at the operator?" tests.
 *
 * These lock in the operator-safety properties of the scanner against hostile
 * data returned by a target or a third-party API:
 *  - discovered subdomains are always inert, valid hostnames (no injection);
 *  - oversized / malformed / rate-limited API responses degrade gracefully;
 *  - hostile CSP/CDN headers are parsed without ReDoS;
 *  - untrusted URLs can never become clickable javascript:/data: sinks.
 *
 * (SSRF/internal-pivot protection is covered separately in guard.test.js.)
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { discoverSubdomains } from "@/lib/scanner/subdomains.js";
import { readCappedText } from "@/lib/scanner/http.js";
import { auditHeaders } from "@/lib/scanner/headers.js";
import { identifyService } from "@/lib/scanner/services.js";
import { safeHref } from "@/lib/url.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

/**
 * Build a real fetch Response (so body streaming / size-capping is exercised).
 * @param {object|string} payload - Object (JSON-stringified) or raw string body.
 * @param {number} [status=200]
 * @param {object} [headers={}]
 * @returns {Response}
 */
function jsonResponse(payload, status = 200, headers = {}) {
  const body = typeof payload === "string" ? payload : JSON.stringify(payload);
  return new Response(body, { status, headers: { "content-type": "application/json", ...headers } });
}

describe("safeHref — only http(s) URLs become clickable", () => {
  it("allows http and https", () => {
    expect(safeHref("https://nvd.nist.gov/vuln/detail/CVE-2021-1")).toBe(
      "https://nvd.nist.gov/vuln/detail/CVE-2021-1"
    );
    expect(safeHref("http://example.com/x")).toBe("http://example.com/x");
  });
  it("rejects dangerous schemes", () => {
    expect(safeHref("javascript:alert(1)")).toBeUndefined();
    expect(safeHref("data:text/html,<script>alert(1)</script>")).toBeUndefined();
    expect(safeHref("vbscript:msgbox(1)")).toBeUndefined();
    expect(safeHref("file:///etc/passwd")).toBeUndefined();
  });
  it("rejects malformed or non-string values", () => {
    expect(safeHref("not a url")).toBeUndefined();
    expect(safeHref("")).toBeUndefined();
    expect(safeHref(null)).toBeUndefined();
    expect(safeHref(undefined)).toBeUndefined();
    expect(safeHref(12345)).toBeUndefined();
  });
});

describe("readCappedText — bounds response body size", () => {
  it("returns the body when under the cap", async () => {
    await expect(readCappedText(new Response("x".repeat(1000)), 10_000)).resolves.toHaveLength(1000);
  });
  it("throws when the body exceeds the cap", async () => {
    await expect(readCappedText(new Response("x".repeat(5000)), 100)).rejects.toThrow(/cap/i);
  });
});

describe("discoverSubdomains — hostile CT data filtered to inert hostnames", () => {
  it("keeps only valid subdomains; strips wildcards, unrelated SANs, injection-shaped names", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse([
          { dns_names: ["www.example.com", "*.api.example.com", "example.com", "attacker.com", "WWW.example.com"] },
          { dns_names: ["<script>alert(1)</script>.example.com", "a b.example.com", "ok.sub.example.com"] },
          { dns_names: [12345, null] },
        ])
      )
    );
    const r = await discoverSubdomains("example.com");
    expect(r.ok).toBe(true);
    expect(r.subdomains).toContain("www.example.com");
    expect(r.subdomains).toContain("api.example.com"); // wildcard prefix stripped
    expect(r.subdomains).toContain("ok.sub.example.com");
    expect(r.subdomains).not.toContain("example.com"); // apex excluded
    expect(r.subdomains).not.toContain("attacker.com"); // unrelated SAN excluded
    // No injection-shaped or invalid names survive:
    expect(r.subdomains.some((s) => /[<>\s]/.test(s))).toBe(false);
    // Case-folded + deduped:
    expect(r.subdomains.filter((s) => s === "www.example.com")).toHaveLength(1);
  });

  it("caps the returned list while reporting the true total", async () => {
    const many = Array.from({ length: 80 }, (_, i) => `h${i}.example.com`);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse([{ dns_names: many }])));
    const r = await discoverSubdomains("example.com");
    expect(r.ok).toBe(true);
    expect(r.total).toBe(80);
    expect(r.subdomains).toHaveLength(50);
  });

  it("handles malformed JSON gracefully", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse("this is not json")));
    const r = await discoverSubdomains("example.com");
    expect(r.ok).toBe(false);
    expect(r.subdomains).toEqual([]);
  });

  it("handles an unexpected non-array body", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ unexpected: true })));
    const r = await discoverSubdomains("example.com");
    expect(r.ok).toBe(true);
    expect(r.subdomains).toEqual([]);
  });

  it("reports rate limiting (429) without throwing", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse([], 429)));
    const r = await discoverSubdomains("example.com");
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/rate/i);
  });

  it("skips IP targets without making a request", async () => {
    const f = vi.fn();
    vi.stubGlobal("fetch", f);
    const r = await discoverSubdomains("8.8.8.8");
    expect(r.ok).toBe(false);
    expect(f).not.toHaveBeenCalled();
  });
});

describe("auditHeaders — hostile CSP/CDN headers parse safely", () => {
  it("flags a weak CSP and detects a fronting CDN", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response("", {
          status: 200,
          headers: {
            "content-security-policy": "default-src *; script-src 'unsafe-inline' 'unsafe-eval' http://evil.example",
            server: "cloudflare",
            "cf-ray": "abc123",
          },
        })
      )
    );
    const r = await auditHeaders("https://example.com");
    expect(r.ok).toBe(true);
    const joined = r.cspIssues.join(" ");
    expect(joined).toMatch(/unsafe-inline/i);
    expect(joined).toMatch(/unsafe-eval/i);
    expect(joined).toMatch(/wildcard/i);
    expect(joined).toMatch(/http:/i);
    expect(r.cdn).toContain("Cloudflare");
  });

  it("is ReDoS-safe on a pathological CSP value", async () => {
    const evil = "script-src " + "a ".repeat(60000);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("", { status: 200, headers: { "content-security-policy": evil } }))
    );
    const t0 = performance.now();
    const r = await auditHeaders("https://example.com");
    expect(r.ok).toBe(true);
    expect(performance.now() - t0).toBeLessThan(1000);
  });
});

describe("identifyService — hostile banners parse without hanging", () => {
  it("handles a huge/garbage banner quickly and returns a bounded result", () => {
    const evil = "\x00".repeat(100) + "A".repeat(200000) + "<script>".repeat(1000);
    const t0 = performance.now();
    const out = identifyService(80, evil);
    expect(performance.now() - t0).toBeLessThan(1000);
    expect(out).toHaveProperty("service");
    expect(out).toHaveProperty("version");
  });
});
