/**
 * Tests for service data + banner fingerprinting.
 */

import { describe, it, expect } from "vitest";
import { resolvePorts, identifyService, TOP_PORTS } from "@/lib/scanner/services.js";

describe("resolvePorts", () => {
  it("returns the top preset", () => {
    expect(resolvePorts({ preset: "top" })).toEqual(TOP_PORTS);
  });
  it("expands an inclusive range", () => {
    expect(resolvePorts({ preset: "range", from: 80, to: 83 })).toEqual([80, 81, 82, 83]);
  });
  it("clamps a range to valid port bounds", () => {
    const ports = resolvePorts({ preset: "range", from: 0, to: 2 });
    expect(ports[0]).toBe(1);
  });
  it("defaults to the common preset", () => {
    const ports = resolvePorts({ preset: "common" });
    expect(ports).toContain(443);
    expect(ports).toContain(22);
  });
});

describe("identifyService", () => {
  it("maps a known port with no banner", () => {
    expect(identifyService(443, "")).toEqual({ service: "https", version: null });
  });
  it("extracts an SSH version from its banner", () => {
    const r = identifyService(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu");
    expect(r.service).toBe("ssh");
    expect(r.version).toMatch(/OpenSSH_8\.9/);
  });
  it("extracts a Server header for http", () => {
    const r = identifyService(80, "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n");
    expect(r.version).toMatch(/nginx/);
  });
});
