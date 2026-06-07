/**
 * Tests for CVE fingerprint parsing + candidate building (no network).
 */

import { describe, it, expect } from "vitest";
import { parseFingerprint, buildCandidates } from "@/lib/scanner/cve.js";

describe("parseFingerprint", () => {
  it("parses product/version from a server header", () => {
    expect(parseFingerprint("nginx/1.18.0")).toEqual({ product: "nginx", version: "1.18.0" });
  });
  it("parses an OpenSSH banner", () => {
    expect(parseFingerprint("OpenSSH_8.9p1 Ubuntu")).toEqual({ product: "openssh", version: "8.9" });
  });
  it("parses x-powered-by PHP", () => {
    expect(parseFingerprint("PHP/7.4.3")).toEqual({ product: "php", version: "7.4.3" });
  });
  it("returns null when there is no version", () => {
    expect(parseFingerprint("cloudflare")).toBeNull();
    expect(parseFingerprint("")).toBeNull();
  });
});

describe("buildCandidates", () => {
  it("collects and de-duplicates candidates from headers and ports", () => {
    const cands = buildCandidates({
      headers: { fingerprint: { server: "nginx/1.18.0", "x-powered-by": "PHP/7.4.3" } },
      ports: { openPorts: [{ port: 22, version: "OpenSSH_8.9p1" }, { port: 80, version: "nginx/1.18.0" }] },
    });
    const keys = cands.map((c) => `${c.product}@${c.version}`);
    expect(keys).toContain("nginx@1.18.0");
    expect(keys).toContain("php@7.4.3");
    expect(keys).toContain("openssh@8.9");
    // nginx appears twice but should be de-duplicated.
    expect(keys.filter((k) => k === "nginx@1.18.0")).toHaveLength(1);
  });
  it("caps at three candidates", () => {
    const cands = buildCandidates({
      headers: { fingerprint: { server: "nginx/1.18.0", "x-powered-by": "PHP/7.4.3" } },
      ports: { openPorts: [{ port: 22, version: "OpenSSH_8.9p1" }, { port: 25, version: "Postfix/3.4.1" }] },
    });
    expect(cands.length).toBeLessThanOrEqual(3);
  });
});
