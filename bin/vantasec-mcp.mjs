#!/usr/bin/env node
/**
 * vantasec-mcp — Model Context Protocol server (stdio, zero-dependency).
 *
 * Single responsibility: expose the Vantasec scanner as an MCP `scan` tool over
 * stdio JSON-RPC, importing runScan IN-PROCESS so no web server has to be
 * running. Returns a table-formatted Markdown report (overall/TLS/email grades,
 * snapshot, strengths, findings, focus) for the assistant/human, plus
 * machine-readable `structuredContent`. Protocol messages are newline-delimited
 * JSON-RPC 2.0 on stdout; all logging goes to stderr so it never corrupts the
 * protocol stream.
 *
 * Run: npm run mcp   (or: node bin/vantasec-mcp.mjs)
 */

import { runScan } from "../src/lib/scanner/index.js";
import { isRiskyPort } from "../src/lib/scanner/score.js";

const PROTOCOL_VERSION = "2025-06-18";
const SERVER_INFO = { name: "vantasec", version: "0.1.0" };

/** Write one JSON-RPC message to stdout (newline-delimited). */
function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}
/** Log to stderr (never stdout — that's the protocol channel). */
function log(...a) {
  process.stderr.write(a.join(" ") + "\n");
}

/** Escape a value for use inside a Markdown table cell. */
function esc(s) {
  return String(s).replace(/\|/g, "\\|").replace(/\n+/g, " ").trim();
}

const SCAN_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    target: { type: "string" },
    score: { type: ["number", "null"] },
    grade: { type: ["string", "null"] },
    tlsGrade: { type: ["string", "null"] },
    emailGrade: { type: ["string", "null"] },
    counts: {
      type: "object",
      properties: {
        openPorts: { type: "number" },
        subdomains: { type: "number" },
        cveProducts: { type: "number" },
        findings: { type: "number" },
      },
    },
    strengths: { type: "array", items: { type: "string" } },
    findings: {
      type: "array",
      items: {
        type: "object",
        properties: {
          severity: { type: "string" },
          points: { type: "number" },
          label: { type: "string" },
          fix: { type: "string" },
        },
      },
    },
  },
};

const TOOLS = [
  {
    name: "scan",
    title: "Security scan",
    description:
      "Run a Vantasec public-surface security scan of a host/IP/URL you own (open ports, TLS grade, DNS/email auth, security headers, known CVEs, subdomains, page-content secrets). Returns a table-formatted graded report — including what is configured WELL plus the problems — and structured data. After calling, summarize the overall risk, acknowledge the strengths, and give your own prioritized remediation plan. Refuses private/internal targets.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Host, IP, or URL to scan (e.g. example.com)." },
        preset: {
          type: "string",
          enum: ["common", "top", "range"],
          description: "Port preset to scan (default: common; 'top' is fastest).",
        },
      },
      required: ["target"],
    },
    outputSchema: SCAN_OUTPUT_SCHEMA,
  },
];

/** Severity sort order for grouping. */
const SEV_ORDER = ["high", "medium", "low"];

/**
 * Derive the positive "what's set up well" list from the scan results.
 * @param {object} results
 * @returns {string[]}
 */
function computeStrengths(results) {
  const s = [];
  const { tls, dns, redirect, headers, ports, cve, disclosure, content } = results;

  if (tls?.ok) {
    s.push(`TLS working${tls.grade ? ` — grade ${tls.grade}` : ""}${tls.protocol ? ` (${tls.protocol})` : ""}`);
    if (!tls.protocolWeak && !tls.weakProtocols?.length) s.push("No deprecated TLS (1.0/1.1) accepted");
    if (tls.keyType && !tls.keyWeak) s.push(`Strong key: ${tls.keyType}${tls.keyBits ? ` ${tls.keyBits}-bit` : ""}`);
    if (tls.cipher && !tls.weakCipher) s.push(`Modern cipher (${tls.cipher})`);
    if (tls.http2) s.push("HTTP/2 supported");
    if (tls.daysRemaining != null && tls.daysRemaining >= 21) s.push(`Certificate not expiring soon (${tls.daysRemaining}d left)`);
  }
  if (redirect?.ok && redirect.redirects) s.push("Forces HTTPS (http → https redirect)");
  if (redirect?.hsts?.present) s.push("HSTS enabled");
  if (headers?.http3) s.push("HTTP/3 supported");
  if (headers?.ok && headers.present?.length) {
    s.push(`${headers.present.length} security header(s) present: ${headers.present.map((h) => h.name).join(", ")}`);
  }
  if (headers?.cdn?.length) s.push(`Behind a CDN/WAF (${headers.cdn.join(", ")})`);
  if (dns?.spf?.length) s.push(`SPF configured${dns.spfQualifier ? ` (${dns.spfQualifier}all)` : ""}`);
  if (dns?.dmarc?.length) s.push(`DMARC present${dns.dmarcPolicy ? ` (p=${dns.dmarcPolicy})` : ""}`);
  if (dns?.dkim?.length) s.push(`DKIM key(s) found (${dns.dkim.join(", ")})`);
  if (dns?.caa?.length) s.push("CAA restricts which CAs can issue certs");
  if (dns?.dnssec === true) s.push("DNSSEC enabled");
  if (ports?.openPorts && !ports.openPorts.some((p) => isRiskyPort(p.port))) {
    s.push("No risky services exposed on open ports");
  }
  if (cve?.ok && !cve.findings?.length) s.push("No known CVEs matched detected versions");
  if (results.methods?.ok && !results.methods.dangerous?.length) s.push("No risky HTTP methods exposed");
  if (headers?.cors && !(headers.cors.allowOrigin === "*" && headers.cors.allowCredentials)) s.push("CORS not wildcard-with-credentials");
  if (disclosure?.ok) {
    if (!disclosure.exposedFiles?.length) s.push("No exposed sensitive files (.git/.env/backups)");
    if (disclosure.securityTxt) s.push("security.txt published");
  }
  if (
    content?.ok &&
    !content.malware?.length &&
    !content.promptInjection?.length &&
    !content.secrets?.length &&
    !content.vulnLibs?.length &&
    !content.mixedContent?.length
  ) {
    s.push("Clean page content (no secrets, malware, vuln libs, mixed content, or prompt-injection)");
  }
  return s;
}

/**
 * Build the machine-readable summary object for structuredContent.
 * @param {string} target
 * @param {object|null} score
 * @param {object} results
 * @returns {object}
 */
function buildStructured(target, score, results) {
  return {
    target,
    score: score?.score ?? null,
    grade: score?.grade ?? null,
    tlsGrade: results.tls?.grade ?? null,
    emailGrade: results.dns?.emailGrade ?? null,
    counts: {
      openPorts: (results.ports?.openPorts || []).length,
      subdomains: results.subdomains?.total ?? 0,
      cveProducts: (results.cve?.findings || []).length,
      findings: (score?.findings || []).length,
    },
    strengths: computeStrengths(results),
    findings: (score?.findings || []).map((f) => ({
      severity: f.severity,
      points: f.points,
      label: f.label,
      fix: f.fix || "",
    })),
  };
}

/**
 * Render a table-formatted Markdown report from a finished scan.
 * @param {string} target
 * @param {object|null} score
 * @param {object} results
 * @returns {string}
 */
function formatReport(target, score, results) {
  const L = [];
  L.push(`# Vantasec scan — ${target}`, "");

  // --- Grades table ---
  L.push("| Scope | Grade |", "|---|---|");
  L.push(`| **Overall** | ${score ? `${score.score}/100 (${score.grade})` : "n/a"} |`);
  if (results.tls?.grade) L.push(`| TLS | ${results.tls.grade} |`);
  if (results.dns?.emailGrade) L.push(`| Email auth | ${results.dns.emailGrade} |`);
  L.push("");

  // --- Snapshot table ---
  L.push("## Snapshot", "", "| Field | Value |", "|---|---|");
  const geo = results.geo;
  if (geo?.ok) {
    const loc = [geo.city, geo.country].filter(Boolean).join(", ");
    L.push(`| IP / network | ${esc([geo.ip, geo.org, loc].filter(Boolean).join(" — ") || "?")} |`);
    if (geo.ptr) L.push(`| Reverse DNS | ${esc(geo.ptr)} |`);
  }
  if (results.tls) {
    L.push(`| HTTPS | ${esc(results.tls.ok ? results.tls.protocol || "TLS" : "no working TLS")} |`);
  }
  if (results.redirect) {
    L.push(`| Forces HTTPS | ${results.redirect.redirects ? "yes" : "NO"} |`);
    if (results.redirect.hsts) L.push(`| HSTS | ${results.redirect.hsts.present ? "yes" : "no"} |`);
  }
  const open = results.ports?.openPorts || [];
  L.push(`| Open ports | ${esc(open.length ? open.map((p) => `${p.port}/${p.service}`).join(", ") : "none")} |`);
  if (results.subdomains) L.push(`| Subdomains (CT) | ${results.subdomains.total ?? 0} |`);
  if (results.tree?.ok) {
    const h = results.tree.hosts ?? 1;
    L.push(`| Site map | ${results.tree.total} file${results.tree.total === 1 ? "" : "s"} · ${h} host${h === 1 ? "" : "s"} |`);
  }
  const cveCount = (results.cve?.findings || []).reduce((n, f) => n + (f.cves?.length || 0), 0);
  if (results.cve) L.push(`| Known CVEs | ${cveCount} across ${(results.cve.findings || []).length} product(s) |`);
  if (results.content?.ok) {
    const c = results.content;
    const issues = [];
    if (c.malware?.length) issues.push(`${c.malware.length} malicious indicator(s)`);
    if (c.promptInjection?.length) issues.push(`${c.promptInjection.length} prompt-injection`);
    if (c.secrets?.length) issues.push(`${c.secrets.length} secret(s)`);
    if (c.vulnLibs?.length) issues.push(`${c.vulnLibs.length} vulnerable lib(s)`);
    if (c.mixedContent?.length) issues.push(`${c.mixedContent.length} mixed-content`);
    if (c.scriptsNoSri?.length) issues.push(`${c.scriptsNoSri.length} script(s) without SRI`);
    L.push(`| Page content | ${esc(issues.length ? issues.join(", ") : "clean")} |`);
  }
  L.push("");

  // --- Strengths ---
  const strengths = computeStrengths(results);
  L.push(`## ✅ What's set up well (${strengths.length})`, "");
  if (strengths.length) for (const x of strengths) L.push(`- ${x}`);
  else L.push("- (nothing notable detected)");
  L.push("");

  // --- Findings table (grouped severity order preserved by score sort) ---
  const findings = score?.findings || [];
  L.push(`## ⚠️ Findings (${findings.length})`, "");
  if (!findings.length) {
    L.push("None — looks well locked down. 🎉");
  } else {
    L.push("| Sev | Pts | Issue | Fix |", "|---|---|---|---|");
    const order = { high: 0, medium: 1, low: 2 };
    for (const f of [...findings].sort((a, b) => (order[a.severity] - order[b.severity]) || b.points - a.points)) {
      L.push(`| ${f.severity} | -${f.points} | ${esc(f.label)} | ${esc(f.fix || "")} |`);
    }
  }
  L.push("");

  // --- Prioritized focus ---
  if (findings.length) {
    L.push("## Suggested focus (highest impact first)", "");
    findings.slice(0, 3).forEach((f, i) => L.push(`${i + 1}. **${esc(f.label)}** — ${esc(f.fix || "remediate")}`));
    L.push("");
  }

  L.push("---");
  L.push("_Assistant: summarize the overall risk, acknowledge the strengths above, and give the user your own prioritized remediation plan in your own words._");
  return L.join("\n");
}

/**
 * Execute the scan tool and shape an MCP tool result (Markdown + structured).
 * @param {object} args - { target, preset }.
 * @returns {Promise<object>} MCP tool result.
 */
async function runScanTool(args) {
  const target = args?.target;
  if (!target || typeof target !== "string") throw new Error("Missing or invalid 'target'");
  let score = null;
  const results = {};
  for await (const ev of runScan(target, { preset: args.preset || "common" })) {
    if (ev.type === "result") results[ev.data.check] = ev.data;
    else if (ev.type === "score") score = ev.data;
    else if (ev.type === "error") throw new Error(ev.data.message);
  }
  return {
    content: [{ type: "text", text: formatReport(target, score, results) }],
    structuredContent: buildStructured(target, score, results),
  };
}

/**
 * Dispatch a single JSON-RPC message.
 * @param {object} msg - Parsed JSON-RPC request/notification.
 */
async function handle(msg) {
  const { id, method, params } = msg;
  const isNotification = id === undefined || id === null;
  try {
    let result;
    switch (method) {
      case "initialize":
        result = {
          protocolVersion: params?.protocolVersion || PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: SERVER_INFO,
        };
        break;
      case "tools/list":
        result = { tools: TOOLS };
        break;
      case "tools/call":
        if (params?.name !== "scan") throw new Error(`Unknown tool: ${params?.name}`);
        result = await runScanTool(params?.arguments);
        break;
      case "ping":
        result = {};
        break;
      default:
        if (isNotification) return;
        send({ jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } });
        return;
    }
    if (!isNotification) send({ jsonrpc: "2.0", id, result });
  } catch (err) {
    if (method === "tools/call" && !isNotification) {
      send({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: `Error: ${err.message}` }], isError: true } });
    } else if (!isNotification) {
      send({ jsonrpc: "2.0", id, error: { code: -32603, message: err.message } });
    } else {
      log("error handling notification:", err.message);
    }
  }
}

let buffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  let nl;
  while ((nl = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, nl).trim();
    buffer = buffer.slice(nl + 1);
    if (!line) continue;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      log("JSON parse error on line:", line);
      continue;
    }
    handle(msg);
  }
});
log("vantasec MCP server ready (stdio)");
