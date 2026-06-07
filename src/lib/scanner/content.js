/**
 * Page / JavaScript content audit.
 *
 * Single responsibility: fetch the homepage HTML and statically inspect it for
 * client-side hygiene issues: leaked secrets, mixed (http) content on an https
 * page, third-party scripts missing Subresource Integrity, and known-vulnerable
 * JS library versions. The HTML body is read with a hard size cap; we do NOT
 * fetch external script bodies (bounds work and request fan-out).
 */

import { readCappedText } from "./http.js";

/** Hard cap on the HTML body we will read/parse. */
const MAX_HTML_BYTES = 3_000_000;

/**
 * Low-false-positive secret signatures. Each match is reported with a masked
 * sample so the secret itself never lands in the UI/report verbatim.
 */
const SECRET_PATTERNS = [
  ["AWS access key", /AKIA[0-9A-Z]{16}/g],
  ["Google API key", /AIza[0-9A-Za-z\-_]{35}/g],
  ["Slack token", /xox[baprs]-[0-9A-Za-z-]{10,}/g],
  ["Stripe live key", /sk_live_[0-9A-Za-z]{24,}/g],
  ["GitHub token", /gh[pousr]_[0-9A-Za-z]{36,}/g],
  ["Private key block", /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g],
];

/** Curated known-vulnerable client libraries (versions below `below`). */
const VULN_LIBS = {
  jquery: { below: "3.5.0", note: "jQuery <3.5.0 — XSS via htmlPrefilter (CVE-2020-11022/11023)." },
  angular: { below: "1.8.3", note: "AngularJS 1.x is end-of-life with multiple known issues." },
  bootstrap: { below: "3.4.1", note: "Bootstrap <3.4.1/<4.3.1 — XSS via data-* attributes." },
  lodash: { below: "4.17.21", note: "lodash <4.17.21 — prototype pollution (CVE-2021-23337)." },
};

/** [name, version-capturing regex] applied to script URLs + inline markup. */
const LIB_PATTERNS = [
  ["jquery", /jquery[-.@/](\d+\.\d+\.\d+)/i],
  ["angular", /angular(?:js)?[-.@/](\d+\.\d+\.\d+)/i],
  ["bootstrap", /bootstrap[-.@/](\d+\.\d+\.\d+)/i],
  ["lodash", /lodash[-.@/](\d+\.\d+\.\d+)/i],
];

/** High-confidence crypto-miner signatures (script URLs or in-page globals). */
const MINER_SIGNATURES = [
  /coinhive|coin-hive/i,
  /cryptonight/i,
  /crypto-?loot/i,
  /coinimp/i,
  /jsecoin/i,
  /webminerpool/i,
  /deepminer/i,
  /authedmine|minero\.cc|webmine\.cz/i,
  /CoinHive\.Anonymous|new\s+CoinHive/i,
];

/**
 * Obfuscated dynamic-execution patterns. These are heuristics (legit code can
 * occasionally use them), so they are reported as medium "review" indicators,
 * not confirmed malware.
 */
const OBFUSCATION_PATTERNS = [
  ["eval(atob(…)) — base64-decoded code execution", /eval\s*\(\s*atob\s*\(/i],
  ["eval(unescape(…)) — encoded code execution", /eval\s*\(\s*unescape\s*\(/i],
  ["eval(decodeURIComponent(…))", /eval\s*\(\s*decodeURIComponent\s*\(/i],
  ["Function(atob(…)) — dynamic code from base64", /Function\s*\(\s*atob\s*\(/i],
  ["document.write(unescape(…)) — injected encoded markup", /document\.write\s*\(\s*unescape\s*\(/i],
];

/**
 * Scan page HTML for signs of compromise / malicious code. High-confidence
 * crypto-miner hits are "high"; the obfuscation/injection heuristics are
 * "medium" (worth a human review, not a definitive verdict).
 *
 * @param {string} html - The page HTML.
 * @returns {Array<{type:string, severity:string, detail?:string}>}
 */
function scanMalware(html) {
  const out = [];

  // Crypto miners — report once, with the matched token.
  for (const re of MINER_SIGNATURES) {
    const m = html.match(re);
    if (m) {
      out.push({ type: "Crypto-miner signature", severity: "high", detail: m[0] });
      break;
    }
  }

  // Obfuscated dynamic code execution.
  for (const [label, re] of OBFUSCATION_PATTERNS) {
    if (re.test(html)) out.push({ type: label, severity: "medium" });
  }

  // document.write injecting a remote <script> — a classic injection vector.
  if (/document\.write\s*\(\s*['"][^'"]*<script[^>]+src=/i.test(html)) {
    out.push({ type: "document.write injecting a remote script", severity: "medium" });
  }

  // Hidden / zero-size iframes that still load something (cloaked injection).
  let count = 0;
  for (const tag of html.matchAll(/<iframe\b[^>]*>/gi)) {
    if (count >= 5) break;
    const t = tag[0];
    const hidden = /display\s*:\s*none|visibility\s*:\s*hidden|(?:width|height)\s*[=:]\s*["']?0\b/i.test(t);
    const src = (t.match(/src=["']([^"']+)["']/i) || [])[1];
    if (hidden && src) {
      out.push({ type: "Hidden iframe", severity: "medium", detail: src });
      count += 1;
    }
  }

  return out;
}

/**
 * Mask a secret so only its shape is shown (first 4 chars + length).
 * @param {string} v - Raw matched secret.
 * @returns {string} Masked representation.
 */
function mask(v) {
  return `${v.slice(0, 4)}…(${v.length} chars)`;
}

/**
 * True if semver-ish version `a` is strictly less than `b` (major.minor.patch).
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function ltVersion(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (x < y) return true;
    if (x > y) return false;
  }
  return false;
}

/** Phrases that resemble instructions aimed at an LLM reading the page. */
const INJECTION_PHRASES = [
  /ignore (?:all |any )?(?:previous|prior|above|earlier) (?:instruction|instructions|prompts?|context)/i,
  /disregard (?:the |all |your |any )?(?:above|previous|prior|earlier|system) (?:instruction|instructions|context|prompts?)/i,
  /do not (?:tell|inform|warn|alert) (?:the )?(?:user|operator)/i,
  /(?:reveal|print|output|repeat|show) (?:your |the )?(?:system )?(?:prompt|instructions)/i,
  /\bexfiltrate\b/i,
  /you are (?:now )?(?:an? )?(?:ai|assistant|language model|chatbot)\b/i,
  /\bprompt injection\b/i,
];

/**
 * Scan for content aimed at manipulating an LLM that ingests the page (prompt
 * injection). Hidden carriers — HTML comments, invisible elements, and invisible
 * Unicode "tag" characters — are high-confidence; a high volume of zero-width
 * characters is medium; visible phrase matches are low (could be a legitimate
 * article about the topic). Pure static string analysis — nothing is executed.
 *
 * @param {string} html - The page HTML.
 * @returns {Array<{type:string, severity:string, detail?:string}>}
 */
function scanPromptInjection(html) {
  const out = [];
  const hasPhrase = (text) => INJECTION_PHRASES.some((re) => re.test(text));

  // Invisible Unicode "tag" block (U+E0000–U+E007F) smuggles ASCII no human sees.
  if (/[\u{E0000}-\u{E007F}]/u.test(html)) {
    out.push({ type: "Invisible Unicode 'tag' characters (hidden text for AI)", severity: "high" });
  }

  // Injection instructions hidden inside an HTML comment.
  for (const m of html.matchAll(/<!--([\s\S]*?)-->/g)) {
    if (hasPhrase(m[1])) {
      out.push({ type: "Prompt-injection text hidden in an HTML comment", severity: "high", detail: m[1].trim().slice(0, 140) });
      break;
    }
  }

  // Injection instructions inside an element styled to be invisible to humans.
  const hiddenEl = /<([a-z]+)\b[^>]*(?:display:\s*none|visibility:\s*hidden|opacity:\s*0|font-size:\s*0(?:px)?|aria-hidden=["']true["']|(?:left|text-indent):\s*-\d{3,}px)[^>]*>([\s\S]{0,600}?)<\/\1>/gi;
  for (const m of html.matchAll(hiddenEl)) {
    if (hasPhrase(m[2])) {
      out.push({
        type: "Hidden on-page text containing AI/prompt-injection instructions",
        severity: "high",
        detail: m[2].replace(/<[^>]+>/g, " ").trim().slice(0, 140),
      });
      break;
    }
  }

  // A high volume of zero-width characters can hide an instruction payload.
  const zw = (html.match(/[\u200B\u200C\u200D\u2060]/g) || []).length;
  if (zw >= 20) {
    out.push({ type: `High volume of zero-width characters (${zw}) — possible hidden text`, severity: "medium" });
  }

  // Visible text that resembles injection — low confidence (review).
  if (out.length === 0) {
    for (const re of INJECTION_PHRASES) {
      const m = html.match(re);
      if (m) {
        out.push({ type: "Text resembling prompt-injection instructions (review — may be legitimate)", severity: "low", detail: m[0].slice(0, 140) });
        break;
      }
    }
  }

  return out;
}

/**
 * Audit a page's HTML for client-side content issues.
 *
 * @param {string} url - Full https URL of the homepage.
 * @param {object} [opts]
 * @param {number} [opts.timeout=8000] - Request timeout in ms.
 * @returns {Promise<{ok:boolean, secrets:Array, malware:Array, promptInjection:Array,
 *   mixedContent:string[], scriptsNoSri:string[], vulnLibs:Array, error?:string}>}
 */
export async function auditContent(url, opts = {}) {
  const timeout = opts.timeout ?? 8000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const res = await fetch(url, {
      redirect: "follow",
      signal: controller.signal,
      headers: { "user-agent": "Vantasec-Scanner/0.1 (+security self-audit)" },
    });
    if (!res.ok) return { ok: false, error: `Homepage responded ${res.status}` };
    const ct = res.headers.get("content-type") || "";
    if (!/text\/html/i.test(ct)) return { ok: false, error: "Homepage is not HTML" };

    const html = await readCappedText(res, MAX_HTML_BYTES);

    // --- Leaked secrets (masked) ---
    const secrets = [];
    for (const [type, re] of SECRET_PATTERNS) {
      const m = html.match(re);
      if (m) secrets.push({ type, sample: mask(m[0]), count: m.length });
    }

    // --- Mixed content: http:// resources loaded via src= on an https page ---
    const mixed = new Set();
    for (const m of html.matchAll(/\ssrc=["'](http:\/\/[^"']+)["']/gi)) mixed.add(m[1]);

    // --- External scripts missing Subresource Integrity ---
    const scriptsNoSri = [];
    for (const tag of html.matchAll(/<script\b[^>]*>/gi)) {
      const t = tag[0];
      const src = t.match(/\ssrc=["'](https?:\/\/[^"']+)["']/i);
      if (src && !/\sintegrity=/i.test(t)) scriptsNoSri.push(src[1]);
    }

    // --- Known-vulnerable JS libraries (from URLs / inline markup) ---
    const vulnLibs = [];
    const seen = new Set();
    for (const [name, re] of LIB_PATTERNS) {
      const m = html.match(re);
      if (!m) continue;
      const version = m[1];
      const def = VULN_LIBS[name];
      const key = `${name}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (def && ltVersion(version, def.below)) {
        vulnLibs.push({ name, version, note: def.note });
      }
    }

    const malware = scanMalware(html);
    const promptInjection = scanPromptInjection(html);

    return {
      ok: true,
      secrets,
      malware,
      promptInjection,
      mixedContent: [...mixed].slice(0, 25),
      scriptsNoSri: scriptsNoSri.slice(0, 25),
      vulnLibs,
    };
  } catch (err) {
    const msg = err.name === "AbortError" ? "Homepage fetch timed out" : err.message;
    return { ok: false, error: msg };
  } finally {
    clearTimeout(timer);
  }
}
