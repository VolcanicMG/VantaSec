/**
 * Tests for the SSRF / abuse guard — the security-critical module that decides
 * what we're allowed to scan. These assert that protected ranges stay blocked.
 */

import { describe, it, expect } from "vitest";
import { ipBlockReason, assertScannable, MAX_PORTS } from "@/lib/scanner/guard.js";

describe("ipBlockReason — IPv4", () => {
  it("blocks loopback", () => {
    expect(ipBlockReason("127.0.0.1")).toMatch(/loopback/i);
  });
  it("blocks the three private ranges", () => {
    expect(ipBlockReason("10.0.0.5")).toMatch(/private/i);
    expect(ipBlockReason("172.16.4.4")).toMatch(/private/i);
    expect(ipBlockReason("192.168.1.10")).toMatch(/private/i);
  });
  it("blocks cloud-metadata link-local 169.254.169.254", () => {
    expect(ipBlockReason("169.254.169.254")).toMatch(/link-local|metadata/i);
  });
  it("blocks carrier-grade NAT", () => {
    expect(ipBlockReason("100.64.0.1")).toMatch(/carrier/i);
  });
  it("allows a normal public address", () => {
    expect(ipBlockReason("203.0.113.10")).toBeNull();
    expect(ipBlockReason("8.8.8.8")).toBeNull();
  });
  it("does NOT misclassify 172.32.x as private (outside /12)", () => {
    expect(ipBlockReason("172.32.0.1")).toBeNull();
  });
});

describe("ipBlockReason — IPv6", () => {
  it("blocks loopback ::1", () => {
    expect(ipBlockReason("::1")).toMatch(/loopback/i);
  });
  it("blocks unique-local and link-local", () => {
    expect(ipBlockReason("fc00::1")).toMatch(/unique-local/i);
    expect(ipBlockReason("fe80::1")).toMatch(/link-local/i);
  });
  it("blocks IPv4-mapped private addresses", () => {
    expect(ipBlockReason("::ffff:10.0.0.1")).toMatch(/private/i);
  });
});

describe("assertScannable", () => {
  it("rejects localhost by name", async () => {
    await expect(assertScannable("localhost")).rejects.toThrow(/localhost/i);
  });
  it("rejects a private IP literal", async () => {
    await expect(assertScannable("192.168.0.1")).rejects.toThrow(/non-public/i);
  });
});

describe("limits", () => {
  it("exposes a sane MAX_PORTS cap", () => {
    expect(MAX_PORTS).toBeGreaterThan(0);
    expect(MAX_PORTS).toBeLessThanOrEqual(65535);
  });
});
