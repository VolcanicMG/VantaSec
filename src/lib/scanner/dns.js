/**
 * DNS record + email-security lookups.
 *
 * Single responsibility: resolve common DNS record types for a host and surface
 * its email-hardening posture — SPF, DMARC (with policy strength), DKIM selector
 * discovery, BIMI, MTA-STS, TLS-RPT — plus CAA and a DNSSEC check. Pure Node
 * (dns/promises) except DNSSEC, which uses DoH to read the validated AD flag.
 * Each lookup failure is captured, never thrown.
 */

import { Resolver } from "node:dns/promises";

/** Common DKIM selectors to probe (providers publish keys at <sel>._domainkey). */
const DKIM_SELECTORS = [
  "default", "google", "selector1", "selector2", "k1", "k2",
  "mail", "dkim", "smtp", "s1", "s2", "mandrill", "fm1",
];

/**
 * Resolve a single record type, swallowing "not found" into an empty array.
 *
 * @param {import('node:dns/promises').Resolver} resolver - Configured resolver.
 * @param {string} host - Hostname to query.
 * @param {string} type - Record type ("A", "AAAA", "MX", ...).
 * @returns {Promise<any[]>} Records, or [] if none / lookup failed.
 */
async function safeResolve(resolver, host, type) {
  try {
    return await resolver.resolve(host, type);
  } catch {
    return [];
  }
}

/**
 * Join TXT record chunk-arrays into whole strings.
 * @param {any[]} raw - Raw TXT lookup result.
 * @returns {string[]} One string per record.
 */
function joinTxt(raw) {
  return raw.map((parts) => (Array.isArray(parts) ? parts.join("") : String(parts)));
}

/**
 * Best-effort DNSSEC validation via DNS-over-HTTPS (Cloudflare), reading the
 * AD (Authenticated Data) flag — true only when the resolver validated DNSSEC.
 *
 * @param {string} host - Hostname to check.
 * @returns {Promise<boolean|null>} true/false, or null if the check failed.
 */
async function checkDnssec(host) {
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A&do=1`,
      { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(5000) }
    );
    if (!res.ok) return null;
    const j = await res.json();
    return !!j.AD;
  } catch {
    return null;
  }
}

/**
 * Grade overall email-auth posture from SPF strictness, DMARC enforcement, and
 * DKIM presence.
 *
 * @param {{spf:string[], spfQualifier:(string|null), dmarcPolicy:(string|null), dkim:string[]}} e
 * @returns {string} Grade A–F.
 */
function gradeEmail({ spf, spfQualifier, dmarcPolicy, dkim }) {
  if (!spf.length && !dmarcPolicy) return "F";
  let pts = 0;
  if (spf.length) pts += spfQualifier === "-" ? 2 : 1; // -all is strict
  if (dmarcPolicy === "reject") pts += 3;
  else if (dmarcPolicy === "quarantine") pts += 2;
  else if (dmarcPolicy === "none") pts += 1;
  if (dkim.length) pts += 1;
  if (pts >= 6) return "A";
  if (pts >= 5) return "B";
  if (pts >= 3) return "C";
  if (pts >= 1) return "D";
  return "F";
}

/**
 * Gather DNS records and email-security posture for a host.
 *
 * @param {string} host - Target hostname (IPs are skipped — no records).
 * @returns {Promise<object>} { a, aaaa, mx, ns, txt, cname, spf, dmarc, caa,
 *   mtaSts, tlsRpt, dkim, bimi, dmarcPolicy, spfQualifier, dnssec, emailGrade }.
 */
export async function lookupDns(host) {
  const resolver = new Resolver({ timeout: 5000, tries: 2 });

  const [a, aaaa, mx, ns, txtRaw, cname, dmarcRaw, caaRaw, mtaStsRaw, tlsRptRaw] = await Promise.all([
    safeResolve(resolver, host, "A"),
    safeResolve(resolver, host, "AAAA"),
    safeResolve(resolver, host, "MX"),
    safeResolve(resolver, host, "NS"),
    safeResolve(resolver, host, "TXT"),
    safeResolve(resolver, host, "CNAME"),
    safeResolve(resolver, `_dmarc.${host}`, "TXT"),
    safeResolve(resolver, host, "CAA"),
    safeResolve(resolver, `_mta-sts.${host}`, "TXT"),
    safeResolve(resolver, `_smtp._tls.${host}`, "TXT"),
  ]);

  const txt = joinTxt(txtRaw);
  const dmarcAll = joinTxt(dmarcRaw);
  const spf = txt.filter((r) => /^v=spf1/i.test(r));
  const dmarc = dmarcAll.filter((r) => /^v=DMARC1/i.test(r));

  // CAA gates which CAs may issue certs for this host.
  const caa = caaRaw.map((r) => {
    if (typeof r !== "object" || r === null) return String(r);
    const tag =
      r.issue != null ? `issue=${r.issue}`
      : r.issuewild != null ? `issuewild=${r.issuewild}`
      : r.iodef != null ? `iodef=${r.iodef}`
      : JSON.stringify(r);
    return r.critical ? `(critical) ${tag}` : tag;
  });

  const mtaSts = joinTxt(mtaStsRaw).filter((r) => /^v=STSv1/i.test(r));
  const tlsRpt = joinTxt(tlsRptRaw).filter((r) => /^v=TLSRPTv1/i.test(r));

  // --- Email deep-dive: DKIM selectors, BIMI, DNSSEC, policy strength ---
  const dkimProbe = await Promise.all(
    DKIM_SELECTORS.map((sel) =>
      safeResolve(resolver, `${sel}._domainkey.${host}`, "TXT").then((recs) => {
        const hit = joinTxt(recs).find((r) => /v=DKIM1|(?:^|;)\s*k=|(?:^|;)\s*p=/i.test(r));
        return hit ? { sel, rec: hit } : null;
      })
    )
  );
  const dkimHits = dkimProbe.filter(Boolean);
  // A wildcard/catch-all _domainkey makes EVERY selector "match" the same record;
  // detect that so we don't falsely report a pile of real DKIM selectors.
  const dkimCatchAll = dkimHits.length >= 4 && new Set(dkimHits.map((h) => h.rec)).size <= 1;
  const dkim = dkimCatchAll ? [] : dkimHits.map((h) => h.sel);

  const bimi = joinTxt(await safeResolve(resolver, `default._bimi.${host}`, "TXT")).some((r) => /^v=BIMI1/i.test(r));
  const dnssec = await checkDnssec(host);

  const dmarcPolicy = (dmarc[0]?.match(/p=\s*(none|quarantine|reject)/i)?.[1] || "").toLowerCase() || null;
  const spfQualifier = spf[0]?.match(/([~\-?+])all/)?.[1] || null;
  const emailGrade = gradeEmail({ spf, spfQualifier, dmarcPolicy, dkim });

  return {
    a,
    aaaa,
    mx: mx.map((r) => (typeof r === "object" ? `${r.priority} ${r.exchange}` : r)),
    ns,
    txt,
    cname,
    spf,
    dmarc,
    caa,
    mtaSts,
    tlsRpt,
    dkim,
    dkimCatchAll,
    bimi,
    dmarcPolicy,
    spfQualifier,
    dnssec,
    emailGrade,
  };
}
