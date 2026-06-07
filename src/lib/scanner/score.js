/**
 * Overall security scoring.
 *
 * Single responsibility: fold the individual check results into one 0-100
 * score, a letter grade, and a list of the findings that cost points (each with
 * a short remediation hint) — so the dashboard can show a single "how locked
 * down am I?" verdict plus how to fix it. Pure function, no I/O. Owns scoring
 * policy only, not the checks.
 */

/**
 * Exposed services that are dangerous to have open to the public internet.
 * Each maps to the deduction applied when found open.
 */
const RISKY_PORTS = {
  21: ["FTP exposed", 8],
  23: ["Telnet exposed (cleartext)", 12],
  135: ["MSRPC exposed", 8],
  139: ["NetBIOS exposed", 8],
  445: ["SMB exposed", 12],
  1433: ["MSSQL exposed", 10],
  2375: ["Docker API exposed (unauthenticated control)", 15],
  3306: ["MySQL exposed", 10],
  3389: ["RDP exposed", 12],
  5432: ["PostgreSQL exposed", 10],
  5900: ["VNC exposed", 12],
  6379: ["Redis exposed (often no auth)", 12],
  9200: ["Elasticsearch exposed", 10],
  11211: ["Memcached exposed", 10],
  27017: ["MongoDB exposed", 12],
};

/**
 * Whether a port is on the risky-exposed-service list (drives both scoring and
 * the UI's risk highlighting, so the two never drift apart).
 *
 * @param {number} port - Port number.
 * @returns {boolean} True if exposing this port to the public is penalized.
 */
export function isRiskyPort(port) {
  return Object.prototype.hasOwnProperty.call(RISKY_PORTS, port);
}

/** Per-header deduction when a graded security header is missing. */
const HEADER_WEIGHTS = {
  "strict-transport-security": 8,
  "content-security-policy": 8,
  "x-frame-options": 4,
  "x-content-type-options": 3,
  "referrer-policy": 2,
  "permissions-policy": 2,
};

/** Exact remediation per missing security header (the literal header to add). */
const HEADER_FIX = {
  "strict-transport-security":
    "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
  "content-security-policy":
    "Add a Content-Security-Policy that restricts script, style, and connect sources.",
  "x-frame-options": "Add: X-Frame-Options: DENY (or use CSP frame-ancestors 'none').",
  "x-content-type-options": "Add: X-Content-Type-Options: nosniff",
  "referrer-policy": "Add: Referrer-Policy: strict-origin-when-cross-origin",
  "permissions-policy":
    "Add a Permissions-Policy disabling unused features, e.g. geolocation=(), camera=().",
};

/**
 * Map a numeric score to a letter grade.
 *
 * @param {number} score - 0-100 score.
 * @returns {string} Letter grade A–F.
 */
function gradeFor(score) {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

/**
 * Compute the overall security score from the collected check results.
 *
 * @param {object} results - Map keyed by check name: { ports, tls, dns, headers,
 *   redirect, disclosure, cve }. Each value is the corresponding result object
 *   (may be missing if a check didn't run).
 * @returns {{ score:number, grade:string, findings:Array<{label:string,points:number,severity:string,fix:(string|undefined)}> }}
 *   score: clamped 0-100. grade: A–F. findings: every deduction with its cost
 *   and a short remediation hint.
 */
export function computeScore(results = {}) {
  let score = 100;
  const findings = [];

  /**
   * Apply a deduction and record why (and how to fix it).
   * @param {string} label - Human-readable reason.
   * @param {number} points - Points to subtract (positive number).
   * @param {string} severity - "high" | "medium" | "low".
   * @param {string} [fix] - Short remediation hint shown in the UI.
   */
  const deduct = (label, points, severity, fix) => {
    score -= points;
    findings.push({ label, points, severity, fix });
  };

  // --- Ports: penalize risky exposed services; web/other ports are mild ---
  const ports = results.ports;
  if (ports?.openPorts) {
    for (const p of ports.openPorts) {
      const risky = RISKY_PORTS[p.port];
      if (risky) {
        deduct(
          `Port ${p.port}: ${risky[0]}`,
          risky[1],
          "high",
          "Close this port or restrict it to trusted IPs with a firewall — don't expose it publicly."
        );
      }
    }
  }

  // --- TLS ---
  const tls = results.tls;
  if (tls) {
    if (!tls.ok) {
      deduct("No working TLS / HTTPS", 25, "high", "Serve the site over HTTPS with a valid certificate (e.g. Let's Encrypt).");
    } else {
      if (tls.daysRemaining != null && tls.daysRemaining < 0) {
        deduct("TLS certificate expired", 25, "high", "Renew the certificate now and automate renewal (certbot/ACME).");
      } else if (tls.daysRemaining != null && tls.daysRemaining < 21) {
        deduct(`TLS certificate expires soon (${tls.daysRemaining}d)`, 8, "medium", "Renew the certificate and enable auto-renewal so it can't lapse.");
      }
      if (tls.authError) deduct(`TLS trust problem: ${tls.authError}`, 10, "medium", "Install the full certificate chain and use a cert matching the hostname.");
      if (tls.protocolWeak) deduct(`Negotiated a deprecated TLS protocol (${tls.protocol})`, 10, "high", "Disable TLS 1.0/1.1 and require TLS 1.2+ (ideally 1.3).");
      if (tls.weakProtocols?.length) {
        deduct(`Accepts deprecated TLS: ${tls.weakProtocols.join(", ")}`, 8, "medium", "Disable deprecated TLS versions in the server configuration.");
      }
      if (tls.keyWeak) deduct(`Weak certificate key (${tls.keyBits}-bit ${tls.keyType})`, 8, "medium", "Reissue the certificate with a 2048-bit+ RSA or an ECDSA key.");
      if (tls.weakCipher) deduct(`Weak cipher negotiated (${tls.cipher})`, 8, "medium", "Disable RC4/3DES/export ciphers; prefer AEAD suites (AES-GCM, ChaCha20).");
    }
  }

  // --- HTTP -> HTTPS redirect + HSTS ---
  const redirect = results.redirect;
  if (redirect?.ok) {
    if (!redirect.redirects) {
      deduct("Plain HTTP is not redirected to HTTPS", 10, "high", "Add a 301 redirect from http:// to https:// at the web server or edge.");
    }
    // Missing HSTS itself is caught by the headers check; flag only a weak max-age here.
    if (redirect.hsts?.present && redirect.hsts.maxAge != null && redirect.hsts.maxAge < 15552000) {
      deduct("HSTS max-age is shorter than 180 days", 3, "low", "Raise Strict-Transport-Security max-age to at least 15552000 (180 days).");
    }
  }

  // --- DNS / email hardening ---
  const dns = results.dns;
  if (dns) {
    if (!dns.spf?.length) deduct("No SPF record (email spoofing risk)", 5, "low", 'Publish an SPF TXT record (use "v=spf1 -all" if the domain sends no mail).');
    if (!dns.dmarc?.length) deduct("No DMARC record (email spoofing risk)", 5, "low", "Publish a DMARC record at _dmarc (start with p=none, then enforce).");
    if (dns.dmarc?.length && dns.dmarcPolicy === "none") {
      deduct("DMARC policy is monitor-only (p=none)", 2, "low", "Move DMARC to p=quarantine, then p=reject once confident.");
    }
    if (dns.spf?.length && (dns.spfQualifier === "+" || dns.spfQualifier === "?")) {
      deduct("SPF is not strict (allows +all/?all)", 2, "low", "Tighten SPF to end with -all (hard fail).");
    }
  }

  // --- HTTP security headers ---
  const headers = results.headers;
  if (headers?.ok && headers.missing) {
    for (const h of headers.missing) {
      const w = HEADER_WEIGHTS[h.name] ?? 2;
      deduct(`Missing header: ${h.name}`, w, w >= 8 ? "medium" : "low", HEADER_FIX[h.name] ?? `Add the ${h.name} response header.`);
    }
    if (headers.fingerprint && Object.keys(headers.fingerprint).length > 0) {
      deduct("Server/tech version leaked in headers", 2, "low", "Remove or mask Server / X-Powered-By version headers.");
    }
  }

  // --- CORS / caching / HTTP methods ---
  if (headers?.ok) {
    if (headers.cors?.allowOrigin === "*" && headers.cors.allowCredentials) {
      deduct("CORS allows any origin with credentials", 10, "high", "Never pair Access-Control-Allow-Origin: * with Allow-Credentials: true; echo a vetted origin instead.");
    }
    if (headers.cacheableWithCookies) {
      deduct("Cookie-setting response is cacheable", 5, "medium", "Add Cache-Control: no-store (or private) to any response that sets cookies.");
    }
  }
  const methods = results.methods;
  if (methods?.ok && methods.dangerous?.length) {
    deduct(`Risky HTTP methods enabled: ${methods.dangerous.join(", ")}`, 5, "medium", "Disable unused methods (especially TRACE/PUT/DELETE) at the server or WAF.");
  }

  // --- Cookie security flags ---
  const cookies = results.headers?.cookies || [];
  for (const c of cookies) {
    if (!c.secure) deduct(`Cookie "${c.name}" missing Secure flag`, 3, "medium", "Add the Secure attribute so the cookie is only sent over HTTPS.");
    if (!c.httpOnly) deduct(`Cookie "${c.name}" missing HttpOnly flag`, 2, "low", "Add the HttpOnly attribute so scripts can't read the cookie.");
    if (!c.sameSite) deduct(`Cookie "${c.name}" missing SameSite`, 1, "low", "Set SameSite=Lax (or Strict) to mitigate CSRF.");
  }

  // --- Disclosure files ---
  const disclosure = results.disclosure;
  if (disclosure?.ok && !disclosure.securityTxt) {
    deduct("No security.txt (no published vuln-reporting contact)", 2, "low", "Publish /.well-known/security.txt with a security contact.");
  }
  // Exposed sensitive files are serious — each is a direct leak.
  if (disclosure?.exposedFiles?.length) {
    for (const f of disclosure.exposedFiles) {
      deduct(`Exposed sensitive file: ${f.path}`, 12, "high", "Remove the file or block public access to this path at the web server.");
    }
  }

  // --- Known CVEs (from version fingerprints) ---
  const cve = results.cve;
  if (cve?.ok && cve.findings?.length) {
    for (const f of cve.findings) {
      // Weight by the most severe CVE found for this product/version.
      const worst = f.cves.reduce((acc, c) => Math.max(acc, c.score ?? 0), 0);
      const points = worst >= 9 ? 15 : worst >= 7 ? 10 : worst >= 4 ? 5 : 2;
      const sev = worst >= 7 ? "high" : worst >= 4 ? "medium" : "low";
      deduct(`${f.cves.length} known CVE(s) for ${f.product} ${f.version}`, points, sev, `Upgrade ${f.product} to a patched release.`);
    }
  }

  // --- Page / JS content hygiene ---
  const content = results.content;
  if (content?.ok) {
    for (const m of content.malware || []) {
      const pts = m.severity === "high" ? 20 : 8;
      deduct(
        `Suspicious code: ${m.type}`,
        pts,
        m.severity,
        "Investigate possible compromise: review/remove this code, rotate exposed credentials, and verify server + build-pipeline integrity."
      );
    }
    for (const p of content.promptInjection || []) {
      const pts = p.severity === "high" ? 12 : p.severity === "medium" ? 6 : 2;
      deduct(
        `LLM/prompt-injection: ${p.type}`,
        pts,
        p.severity,
        "Remove hidden/instructional text aimed at AI crawlers; have any LLM that ingests this site's content treat it as untrusted input."
      );
    }
    for (const s of content.secrets || []) {
      deduct(`Secret leaked in page: ${s.type}`, 15, "high", "Remove the secret from client-side code and rotate it immediately.");
    }
    for (const l of content.vulnLibs || []) {
      deduct(`Vulnerable JS library: ${l.name} ${l.version}`, 6, "medium", `Upgrade ${l.name} to a patched version.`);
    }
    if (content.mixedContent?.length) {
      deduct(`Mixed content: ${content.mixedContent.length} http resource(s) on an https page`, 5, "medium", "Serve all resources over https:// to avoid mixed-content downgrade.");
    }
    if (content.scriptsNoSri?.length) {
      deduct(`${content.scriptsNoSri.length} external script(s) without Subresource Integrity`, 2, "low", "Add an integrity (SRI) hash + crossorigin to third-party <script> tags.");
    }
  }

  // Clamp and grade.
  score = Math.max(0, Math.min(100, Math.round(score)));
  // Show the costliest findings first.
  findings.sort((a, b) => b.points - a.points);
  return { score, grade: gradeFor(score), findings };
}
