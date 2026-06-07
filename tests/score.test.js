/**
 * Tests for overall security scoring policy.
 */

import { describe, it, expect } from "vitest";
import { computeScore, isRiskyPort } from "@/lib/scanner/score.js";

describe("computeScore", () => {
  it("gives a perfect, A-grade score for a clean target", () => {
    const r = computeScore({
      ports: { openPorts: [{ port: 443, service: "https" }], scanned: 17 },
      tls: { ok: true, daysRemaining: 90, authError: null },
      dns: { spf: ["v=spf1 -all"], dmarc: ["v=DMARC1;p=reject"] },
      headers: { ok: true, missing: [], fingerprint: {} },
    });
    expect(r.score).toBe(100);
    expect(r.grade).toBe("A");
    expect(r.findings).toHaveLength(0);
  });

  it("penalizes an exposed database port as a high-severity finding", () => {
    const r = computeScore({
      ports: { openPorts: [{ port: 6379, service: "redis" }], scanned: 17 },
    });
    expect(r.score).toBeLessThan(100);
    expect(r.findings.some((f) => f.severity === "high" && /redis/i.test(f.label))).toBe(true);
  });

  it("deducts for expired TLS as high severity", () => {
    const r = computeScore({ tls: { ok: true, daysRemaining: -3 } });
    expect(r.findings.some((f) => /expired/i.test(f.label))).toBe(true);
    expect(r.score).toBeLessThanOrEqual(75);
  });

  it("deducts for missing SPF and DMARC", () => {
    const r = computeScore({ dns: { spf: [], dmarc: [] } });
    expect(r.findings.some((f) => /SPF/i.test(f.label))).toBe(true);
    expect(r.findings.some((f) => /DMARC/i.test(f.label))).toBe(true);
  });

  it("deducts for missing security headers and leaked fingerprint", () => {
    const r = computeScore({
      headers: {
        ok: true,
        missing: [{ name: "strict-transport-security" }, { name: "content-security-policy" }],
        fingerprint: { server: "nginx/1.18.0" },
      },
    });
    expect(r.score).toBeLessThan(100);
    expect(r.findings.some((f) => /strict-transport-security/.test(f.label))).toBe(true);
  });

  it("never drops below 0 and sorts findings by cost", () => {
    const r = computeScore({
      ports: { openPorts: [{ port: 23 }, { port: 445 }, { port: 2375 }, { port: 3389 }] },
      tls: { ok: false },
      dns: { spf: [], dmarc: [] },
      headers: { ok: true, missing: [{ name: "strict-transport-security" }], fingerprint: {} },
    });
    expect(r.score).toBeGreaterThanOrEqual(0);
    expect(r.grade).toBe("F");
    for (let i = 1; i < r.findings.length; i++) {
      expect(r.findings[i - 1].points).toBeGreaterThanOrEqual(r.findings[i].points);
    }
  });
});

describe("isRiskyPort", () => {
  it("flags database/admin/remote-access ports as risky", () => {
    expect(isRiskyPort(6379)).toBe(true); // redis
    expect(isRiskyPort(3389)).toBe(true); // rdp
    expect(isRiskyPort(3306)).toBe(true); // mysql
    expect(isRiskyPort(23)).toBe(true); // telnet
  });
  it("treats standard web/dns/mail ports as NOT risky", () => {
    expect(isRiskyPort(80)).toBe(false);
    expect(isRiskyPort(443)).toBe(false);
    expect(isRiskyPort(53)).toBe(false);
    expect(isRiskyPort(8080)).toBe(false);
    expect(isRiskyPort(8443)).toBe(false);
  });
});

describe("computeScore — extended checks", () => {
  it("penalizes accepting deprecated TLS protocols", () => {
    const r = computeScore({ tls: { ok: true, daysRemaining: 90, weakProtocols: ["TLSv1", "TLSv1.1"] } });
    expect(r.findings.some((f) => /deprecated TLS/i.test(f.label))).toBe(true);
  });
  it("penalizes plain HTTP not redirecting to HTTPS", () => {
    const r = computeScore({ redirect: { ok: true, redirects: false, hsts: { present: false } } });
    expect(r.findings.some((f) => /not redirected/i.test(f.label))).toBe(true);
  });
  it("penalizes insecure cookies", () => {
    const r = computeScore({
      headers: { ok: true, missing: [], fingerprint: {}, cookies: [{ name: "sid", secure: false, httpOnly: false, sameSite: null }] },
    });
    expect(r.findings.some((f) => /Secure flag/i.test(f.label))).toBe(true);
  });
  it("penalizes a missing security.txt", () => {
    const r = computeScore({ disclosure: { ok: true, securityTxt: false, robotsTxt: true } });
    expect(r.findings.some((f) => /security\.txt/i.test(f.label))).toBe(true);
  });
  it("penalizes known CVEs weighted by severity", () => {
    const r = computeScore({
      cve: { ok: true, findings: [{ product: "nginx", version: "1.18.0", cves: [{ id: "CVE-2021-1", score: 9.8, severity: "CRITICAL" }] }] },
    });
    const f = r.findings.find((x) => /known CVE/i.test(x.label));
    expect(f).toBeTruthy();
    expect(f.severity).toBe("high");
  });
});
