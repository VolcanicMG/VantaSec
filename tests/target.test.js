/**
 * Tests for target parsing/normalization.
 */

import { describe, it, expect } from "vitest";
import { parseTarget, isIPv4 } from "@/lib/scanner/target.js";

describe("parseTarget", () => {
  it("accepts a bare hostname and derives an https url", () => {
    const t = parseTarget("example.com");
    expect(t.host).toBe("example.com");
    expect(t.httpUrl).toBe("https://example.com");
  });
  it("strips scheme, path, and query down to the host", () => {
    const t = parseTarget("http://example.com/path?x=1");
    expect(t.host).toBe("example.com");
  });
  it("handles an IP literal", () => {
    const t = parseTarget("203.0.113.10");
    expect(t.host).toBe("203.0.113.10");
  });
  it("throws on empty input", () => {
    expect(() => parseTarget("")).toThrow();
    expect(() => parseTarget("   ")).toThrow();
  });
});

describe("isIPv4", () => {
  it("recognizes valid IPv4", () => {
    expect(isIPv4("1.2.3.4")).toBe(true);
    expect(isIPv4("255.255.255.255")).toBe(true);
  });
  it("rejects non-IPv4", () => {
    expect(isIPv4("example.com")).toBe(false);
    expect(isIPv4("1.2.3")).toBe(false);
    expect(isIPv4("256.0.0.1")).toBe(false);
  });
});
