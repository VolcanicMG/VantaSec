"use client";

import { isRiskyPort } from "@/lib/scanner/score.js";
import { safeHref } from "@/lib/url.js";

/**
 * Result cards.
 *
 * Single responsibility: render the findings for each check as a card. These
 * are presentational only — all values arrive pre-computed from the scanner.
 * All dynamic values are rendered as text (React auto-escapes), so a hostile
 * banner/header can never inject markup or script into the page.
 */

/**
 * Shared card shell.
 * @param {{title:string, accent?:string, children:React.ReactNode}} props
 * @returns {JSX.Element}
 */
function Card({ title, accent = "slate", children }) {
  const ring = {
    slate: "border-slate-700",
    emerald: "border-emerald-600/50",
    amber: "border-amber-600/50",
    red: "border-red-600/50",
  }[accent];
  return (
    <div className={`rounded-xl border ${ring} bg-slate-900/50 p-5`}>
      <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-300">{title}</h3>
      {children}
    </div>
  );
}

/**
 * Collapsible "more details" disclosure built on the native <details> element.
 *
 * @param {{label?:string, children:React.ReactNode, divider?:boolean}} props -
 *   Optional summary label (defaults to "More details"), the hidden content,
 *   and `divider` (default true) which draws a separating top border. Set
 *   `divider={false}` when the disclosure already sits inside a grouped block
 *   (e.g. a CVE list item) so it stays attached to the content above it.
 * @returns {JSX.Element}
 */
function Details({ label = "More details", children, divider = true }) {
  return (
    <details className={`group ${divider ? "mt-3 border-t border-slate-800 pt-3" : "mt-2"}`}>
      <summary className="cursor-pointer list-none text-xs font-medium text-slate-400 transition hover:text-slate-200">
        <span className="inline-block transition group-open:rotate-90">▸</span> {label}
      </summary>
      <div className="mt-2 space-y-1 text-xs text-slate-400">{children}</div>
    </details>
  );
}

/**
 * Open-ports card.
 * @param {{data:object}} props - The "ports" result event.
 * @returns {JSX.Element}
 */
export function PortsCard({ data }) {
  const open = data.openPorts || [];
  // Only risky exposed services drive the card's alert state, matching how the
  // overall score is computed (isRiskyPort is the shared source of truth).
  const risky = open.filter((p) => isRiskyPort(p.port));
  const accent = risky.length ? "amber" : "emerald";

  return (
    <Card title={`Open Ports (${open.length} of ${data.scanned} scanned)`} accent={accent}>
      {open.length === 0 ? (
        <p className="text-sm text-emerald-400">No open ports found — nothing exposed on the scanned set.</p>
      ) : (
        <>
          <p className={`mb-2 text-xs ${risky.length ? "text-amber-400" : "text-emerald-400"}`}>
            {risky.length
              ? `${risky.length} risky service${risky.length > 1 ? "s" : ""} exposed — these affect your score.`
              : "All open ports are standard web/infrastructure services — none count against your score."}
          </p>
          <ul className="space-y-2 font-mono text-sm">
            {open.map((p) => {
              const bad = isRiskyPort(p.port);
              return (
                <li key={p.port} className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span className={`font-semibold ${bad ? "text-red-400" : "text-emerald-400"}`}>{p.port}</span>
                  <span className="text-slate-300">{p.service}</span>
                  {p.version && <span className="text-slate-500">{p.version}</span>}
                  {bad && <span className="rounded bg-red-500/15 px-1.5 py-0.5 text-xs text-red-400">risky</span>}
                </li>
              );
            })}
          </ul>
        </>
      )}
      {open.length > 0 && (
        <Details label="Raw banners & service detail">
          <ul className="space-y-2 font-mono">
            {open.map((p) => (
              <li key={p.port}>
                <span className="text-slate-300">{p.port}/{p.service}</span>
                {p.version ? ` — ${p.version}` : ""}
                {p.banner && (
                  <pre className="mt-1 max-h-32 overflow-auto whitespace-pre-wrap rounded bg-slate-950/60 p-2 text-slate-500">{p.banner}</pre>
                )}
              </li>
            ))}
          </ul>
        </Details>
      )}
    </Card>
  );
}

/**
 * TLS certificate card.
 * @param {{data:object}} props - The "tls" result event.
 * @returns {JSX.Element}
 */
export function TlsCard({ data }) {
  if (!data.ok) {
    return (
      <Card title="TLS / Certificate" accent="red">
        <p className="text-sm text-red-400">{data.error || "No TLS available"}</p>
      </Card>
    );
  }
  const expSoon = data.daysRemaining != null && data.daysRemaining < 21;
  const weak = data.protocolWeak || data.weakProtocols?.length > 0 || data.keyWeak || data.weakCipher;
  return (
    <Card title={`TLS / Certificate${data.grade ? ` — Grade ${data.grade}` : ""}`} accent={expSoon || weak ? "amber" : "emerald"}>
      <dl className="space-y-1 text-sm">
        <Row k="Protocol" v={data.protocol} />
        <Row k="Issuer" v={data.issuer} />
        <Row k="Subject" v={data.subject} />
        <Row k="Valid to" v={data.validTo} />
        <Row k="Days remaining" v={data.daysRemaining != null ? String(data.daysRemaining) : "—"} warn={expSoon} />
        {data.keyType && (
          <Row
            k="Public key"
            v={`${data.keyType}${data.keyBits ? ` ${data.keyBits}-bit` : ""}${data.curve ? ` (${data.curve})` : ""}`}
            warn={data.keyWeak}
          />
        )}
        {data.ocspStapled != null && <Row k="OCSP stapling" v={data.ocspStapled ? "yes" : "no"} />}
        {data.cipher && <Row k="Cipher" v={data.cipher} warn={data.weakCipher} />}
        {data.http2 != null && <Row k="HTTP/2 (ALPN)" v={data.http2 ? "yes" : "no"} />}
        {data.authError && <Row k="Trust" v={data.authError} warn />}
        {data.weakProtocols?.length > 0 && (
          <Row k="Deprecated TLS accepted" v={data.weakProtocols.join(", ")} warn />
        )}
      </dl>
      <Details>
        <Row k="Valid from" v={data.validFrom || "—"} />
        <Row k="Chain trusted" v={data.authorized ? "yes" : "no"} warn={!data.authorized} />
        <Row k="Negotiated protocol" v={data.protocol || "—"} />
        {data.san?.length > 0 && <Row k="SAN count" v={String(data.san.length)} />}
        {data.ocspUri && <Row k="OCSP responder" v={data.ocspUri} />}
        {data.serialNumber && <Row k="Serial" v={data.serialNumber} />}
        {data.fingerprint256 && <Row k="SHA-256" v={data.fingerprint256} />}
        {data.san?.length > 0 && (
          <div>
            <p className="text-slate-500">Subject Alternative Names:</p>
            <ul className="space-y-1 font-mono">
              {data.san.map((s) => (
                <li key={s} className="break-all">{s}</li>
              ))}
            </ul>
          </div>
        )}
      </Details>
    </Card>
  );
}

/**
 * DNS + email-security card.
 * @param {{data:object}} props - The "dns" result event.
 * @returns {JSX.Element}
 */
export function DnsCard({ data }) {
  const list = (arr) => (arr && arr.length ? arr.join(", ") : "—");
  const hasMx = data.mx?.length > 0;
  return (
    <Card title="DNS & Email Security">
      <dl className="space-y-1 text-sm">
        <Row k="A" v={list(data.a)} />
        <Row k="AAAA" v={list(data.aaaa)} />
        <Row k="MX" v={list(data.mx)} />
        <Row k="NS" v={list(data.ns)} />
        <Row k="SPF" v={data.spf?.length ? "present" : "missing"} warn={!data.spf?.length} />
        <Row k="DMARC" v={data.dmarc?.length ? "present" : "missing"} warn={!data.dmarc?.length} />
        <Row k="CAA" v={data.caa?.length ? `${data.caa.length} record${data.caa.length > 1 ? "s" : ""}` : "none"} />
        <Row k="MTA-STS" v={data.mtaSts?.length ? "present" : "absent"} warn={hasMx && !data.mtaSts?.length} />
        <Row k="TLS-RPT" v={data.tlsRpt?.length ? "present" : "absent"} warn={hasMx && !data.tlsRpt?.length} />
        <Row k="DKIM" v={data.dkimCatchAll ? "wildcard catch-all" : data.dkim?.length ? data.dkim.join(", ") : "none found"} warn={hasMx && !data.dkim?.length && !data.dkimCatchAll} />
        <Row k="DNSSEC" v={data.dnssec == null ? "unknown" : data.dnssec ? "enabled" : "not enabled"} warn={data.dnssec === false} />
        {data.emailGrade && (
          <Row k="Email auth grade" v={data.emailGrade} warn={["D", "F"].includes(data.emailGrade)} />
        )}
      </dl>
      <Details label="Full records">
        {data.spf?.length > 0 && <p className="break-all font-mono">SPF: {data.spf.join(" ")}</p>}
        {data.dmarc?.length > 0 && <p className="break-all font-mono">DMARC: {data.dmarc.join(" ")}</p>}
        {data.mtaSts?.length > 0 && <p className="break-all font-mono">MTA-STS: {data.mtaSts.join(" ")}</p>}
        {data.tlsRpt?.length > 0 && <p className="break-all font-mono">TLS-RPT: {data.tlsRpt.join(" ")}</p>}
        {data.dmarcPolicy && <p className="break-all font-mono">DMARC policy: p={data.dmarcPolicy}</p>}
        {data.spfQualifier && <p className="break-all font-mono">SPF qualifier: {data.spfQualifier}all</p>}
        {data.bimi && <p className="break-all font-mono">BIMI: present</p>}
        {data.cname?.length > 0 && <p className="break-all font-mono">CNAME: {data.cname.join(", ")}</p>}
        {data.caa?.length > 0 && (
          <div>
            <p className="text-slate-500">CAA records:</p>
            <ul className="space-y-1 font-mono">
              {data.caa.map((r, i) => (
                <li key={i} className="break-all">{r}</li>
              ))}
            </ul>
          </div>
        )}
        {data.txt?.length > 0 && (
          <div>
            <p className="text-slate-500">TXT records:</p>
            <ul className="space-y-1 font-mono">
              {data.txt.map((t, i) => (
                <li key={i} className="break-all">{t}</li>
              ))}
            </ul>
          </div>
        )}
        {!data.spf?.length &&
          !data.dmarc?.length &&
          !data.mtaSts?.length &&
          !data.tlsRpt?.length &&
          !data.cname?.length &&
          !data.caa?.length &&
          !data.txt?.length && (
            <p className="text-slate-500">No SPF, DMARC, MTA-STS, TLS-RPT, CAA, or TXT records found.</p>
          )}
      </Details>
    </Card>
  );
}

/**
 * HTTP security-headers card.
 * @param {{data:object}} props - The "headers" result event.
 * @returns {JSX.Element}
 */
export function HeadersCard({ data }) {
  if (!data.ok) {
    return (
      <Card title="HTTP Security Headers" accent="red">
        <p className="text-sm text-red-400">{data.error || "Could not fetch"}</p>
      </Card>
    );
  }
  const missing = data.missing || [];
  return (
    <Card title="HTTP Security Headers" accent={missing.length ? "amber" : "emerald"}>
      <div className="space-y-3 text-sm">
        <div>
          <p className="mb-1 text-xs uppercase text-emerald-500">Present</p>
          {data.present?.length ? (
            <ul className="space-y-1 font-mono text-xs text-slate-300">
              {data.present.map((h) => (
                <li key={h.name}>✓ {h.name}</li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-slate-500">none</p>
          )}
        </div>
        {missing.length > 0 && (
          <div>
            <p className="mb-1 text-xs uppercase text-amber-500">Missing</p>
            <ul className="space-y-1 text-xs text-slate-400">
              {missing.map((h) => (
                <li key={h.name}>
                  <span className="font-mono text-amber-400">✗ {h.name}</span> — {h.why}
                </li>
              ))}
            </ul>
          </div>
        )}
        {data.cspIssues?.length > 0 && (
          <div>
            <p className="mb-1 text-xs uppercase text-amber-500">CSP weaknesses</p>
            <ul className="space-y-1 text-xs text-amber-400">
              {data.cspIssues.map((issue, i) => (
                <li key={i}>⚠ {issue}</li>
              ))}
            </ul>
          </div>
        )}
        {data.cdn?.length > 0 && (
          <div>
            <p className="mb-1 text-xs uppercase text-slate-500">CDN / WAF detected</p>
            <p className="font-mono text-xs text-slate-300">{data.cdn.join(", ")}</p>
          </div>
        )}
        {data.http3 && (
          <div>
            <p className="mb-1 text-xs uppercase text-slate-500">HTTP/3</p>
            <p className="font-mono text-xs text-emerald-400">supported (advertised via Alt-Svc)</p>
          </div>
        )}
        {data.cors && (
          <div>
            <p className="mb-1 text-xs uppercase text-slate-500">CORS</p>
            <p className={`font-mono text-xs ${data.cors.allowOrigin === "*" && data.cors.allowCredentials ? "text-red-400" : "text-slate-300"}`}>
              Allow-Origin: {data.cors.allowOrigin}
              {data.cors.allowCredentials ? " (+credentials)" : ""}
            </p>
          </div>
        )}
        {data.cacheableWithCookies && (
          <div>
            <p className="mb-1 text-xs uppercase text-amber-500">Caching</p>
            <p className="text-xs text-amber-400">A cookie-setting response is cacheable — add Cache-Control: no-store.</p>
          </div>
        )}
        {data.fingerprint && Object.keys(data.fingerprint).length > 0 && (
          <div>
            <p className="mb-1 text-xs uppercase text-slate-500">Tech fingerprint (consider hiding)</p>
            <ul className="space-y-1 font-mono text-xs text-slate-500">
              {Object.entries(data.fingerprint).map(([k, v]) => (
                <li key={k}>{k}: {v}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
      {data.cookies?.length > 0 && (
        <div className="mt-3 border-t border-slate-800 pt-3">
          <p className="mb-1 text-xs uppercase text-slate-500">Cookies</p>
          <ul className="space-y-1 text-xs">
            {data.cookies.map((c) => {
              const flags = [];
              if (!c.secure) flags.push("Secure");
              if (!c.httpOnly) flags.push("HttpOnly");
              if (!c.sameSite) flags.push("SameSite");
              return (
                <li key={c.name} className="flex items-center justify-between gap-3">
                  <span className="font-mono text-slate-300">{c.name}</span>
                  {flags.length === 0 ? (
                    <span className="text-emerald-400">all flags set</span>
                  ) : (
                    <span className="text-amber-400">missing: {flags.join(", ")}</span>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      )}
      {data.present?.length > 0 && (
        <Details label="Present header values">
          <ul className="space-y-1 font-mono">
            {data.present.map((h) => (
              <li key={h.name} className="break-all">
                <span className="text-slate-300">{h.name}:</span> {h.value}
              </li>
            ))}
          </ul>
        </Details>
      )}
    </Card>
  );
}

/**
 * One key/value row used inside the cards.
 * @param {{k:string, v:string, warn?:boolean}} props
 * @returns {JSX.Element}
 */
function Row({ k, v, warn }) {
  return (
    <div className="flex justify-between gap-4">
      <dt className="text-slate-500">{k}</dt>
      <dd className={`text-right font-mono ${warn ? "text-amber-400" : "text-slate-200"}`}>{v}</dd>
    </div>
  );
}

/**
 * HTTP -> HTTPS redirect + HSTS card.
 * @param {{data:object}} props - The "redirect" result event.
 * @returns {JSX.Element}
 */
export function RedirectCard({ data }) {
  if (!data.ok) {
    return (
      <Card title="HTTP → HTTPS Redirect" accent="slate">
        <p className="text-sm text-slate-400">{data.error || "Could not check"}</p>
      </Card>
    );
  }
  const hsts = data.hsts || {};
  return (
    <Card title="HTTP → HTTPS Redirect" accent={data.redirects ? "emerald" : "amber"}>
      <dl className="space-y-1 text-sm">
        <Row
          k="Forces HTTPS"
          v={data.redirects ? "yes" : "no — plain HTTP is served"}
          warn={!data.redirects}
        />
        <Row k="Final URL" v={data.finalUrl || "—"} />
        <Row k="HSTS" v={hsts.present ? "present" : "absent"} warn={!hsts.present} />
        {hsts.present && (
          <>
            <Row k="HSTS max-age" v={hsts.maxAge != null ? `${hsts.maxAge}s` : "—"} />
            <Row k="includeSubDomains" v={hsts.includeSubDomains ? "yes" : "no"} />
            <Row k="preload" v={hsts.preload ? "yes" : "no"} />
          </>
        )}
      </dl>
    </Card>
  );
}

/**
 * Disclosure-files card (security.txt / robots.txt).
 * @param {{data:object}} props - The "disclosure" result event.
 * @returns {JSX.Element}
 */
export function DisclosureCard({ data }) {
  const exposed = data.exposedFiles || [];
  return (
    <Card title="Disclosure Files" accent={exposed.length ? "red" : data.securityTxt ? "emerald" : "slate"}>
      <dl className="space-y-1 text-sm">
        <Row
          k="security.txt"
          v={data.securityTxt ? "present" : "absent"}
          warn={!data.securityTxt}
        />
        <Row k="robots.txt" v={data.robotsTxt ? "present" : "absent"} />
      </dl>
      <div className="mt-3 border-t border-slate-800 pt-3">
        <p className="mb-1 text-xs uppercase text-slate-500">Exposed sensitive files</p>
        {exposed.length > 0 ? (
          <ul className="space-y-1 text-xs">
            {exposed.map((f) => (
              <li key={f.path} className="flex items-center justify-between gap-3">
                <span className="font-mono text-red-400">{f.path}</span>
                <span className="text-slate-500">{f.contentType}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-xs text-emerald-400">None found — no common sensitive files are publicly accessible.</p>
        )}
      </div>
    </Card>
  );
}

/**
 * Known-CVE card — results of the NVD lookup against detected versions.
 * @param {{data:object}} props - The "cve" result event.
 * @returns {JSX.Element}
 */
export function CveCard({ data }) {
  const findings = data.findings || [];
  const sevColor = (sev) => {
    const s = (sev || "").toUpperCase();
    if (s === "CRITICAL") return "text-red-400";
    if (s === "HIGH") return "text-orange-400";
    if (s === "MEDIUM") return "text-amber-400";
    return "text-slate-400";
  };
  // Roll up severity counts across every matched CVE for an at-a-glance summary.
  const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const counts = findings
    .flatMap((f) => f.cves || [])
    .reduce((acc, c) => {
      const s = (c.severity || "").toUpperCase();
      if (s) acc[s] = (acc[s] || 0) + 1;
      return acc;
    }, {});

  return (
    <Card title="Known CVEs" accent={findings.length ? "red" : "emerald"}>
      {findings.length === 0 ? (
        <p className="text-sm text-emerald-400">{data.note || "No known CVEs matched."}</p>
      ) : (
        <div className="space-y-4 text-sm">
          <div className="flex flex-wrap gap-2 text-xs font-medium">
            {SEV_ORDER.filter((s) => counts[s]).map((s) => (
              <span key={s} className={`rounded-full bg-slate-800 px-2 py-0.5 ${sevColor(s)}`}>
                {counts[s]} {s}
              </span>
            ))}
          </div>
          {findings.map((f) => (
            <div key={`${f.product}@${f.version}`}>
              <p className="mb-1 font-mono text-slate-300">
                {f.product} {f.version}{" "}
                <span className="text-xs text-slate-500">({f.source})</span>
              </p>
              <ul className="space-y-3">
                {[...(f.cves || [])]
                  .sort((a, b) => (b.score ?? -1) - (a.score ?? -1))
                  .map((c) => (
                  <li
                    key={c.id}
                    className="border-t border-slate-800/70 pt-3 text-xs first:border-t-0 first:pt-0"
                  >
                    <a
                      href={safeHref(c.url)}
                      target="_blank"
                      rel="noreferrer"
                      className="font-mono text-emerald-400 hover:underline"
                    >
                      {c.id}
                    </a>{" "}
                    <span className={sevColor(c.severity)}>
                      {c.severity}
                      {c.score != null ? ` ${c.score}` : ""}
                    </span>
                    <Details label="More details" divider={false}>
                      {(c.fullDescription || c.summary) && (
                        <p className="text-slate-400">{c.fullDescription || c.summary}</p>
                      )}
                      {c.vector && <Row k="CVSS vector" v={c.vector} />}
                      {c.attackVector && <Row k="Attack vector" v={c.attackVector} />}
                      {c.cwes?.length > 0 && <Row k="Weaknesses" v={c.cwes.join(", ")} />}
                      {c.published && <Row k="Published" v={new Date(c.published).toLocaleDateString()} />}
                      {c.lastModified && <Row k="Last modified" v={new Date(c.lastModified).toLocaleDateString()} />}
                      {c.references?.length > 0 && (
                        <div>
                          <p className="text-slate-500">References:</p>
                          <ul className="space-y-1">
                            {c.references.map((r) => (
                              <li key={r} className="break-all">
                                <a href={safeHref(r)} target="_blank" rel="noreferrer" className="text-emerald-400 hover:underline">
                                  {r}
                                </a>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </Details>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
      {data.note && findings.length > 0 && (
        <p className="mt-3 text-xs text-slate-600">{data.note}</p>
      )}
    </Card>
  );
}

/**
 * Subdomains card — passive Certificate-Transparency discovery (crt.sh).
 * @param {{data:object, onRescan?:(host:string)=>void}} props - The "subdomains"
 *   result event, plus an optional handler to launch a scan of a discovered host.
 * @returns {JSX.Element}
 */
export function SubdomainsCard({ data, onRescan, onScanAll }) {
  if (!data.ok) {
    return (
      <Card title="Subdomains (CT logs)" accent="slate">
        <p className="text-sm text-slate-400">{data.error || "No data"}</p>
      </Card>
    );
  }
  const subs = data.subdomains || [];
  return (
    <Card title={`Subdomains (${data.total} via CT logs)`} accent="slate">
      {subs.length === 0 ? (
        <p className="text-sm text-slate-400">No subdomains found in Certificate Transparency logs.</p>
      ) : (
        <>
          {onScanAll && (
            <button
              type="button"
              onClick={() => onScanAll(subs)}
              className="no-print mb-2 rounded-lg border border-emerald-700/60 px-3 py-1.5 text-xs text-emerald-300 transition hover:bg-emerald-950/40"
            >
              Scan all {subs.length} →
            </button>
          )}
          <p className="mb-2 text-xs text-slate-500">
            From public CT logs — each is a separate host you may want to scan.
            {data.total > subs.length ? ` Showing first ${subs.length}.` : ""}
          </p>
          <ul className="flex flex-wrap gap-2 font-mono text-xs">
            {subs.map((s) => (
              <li key={s}>
                {onRescan ? (
                  <button
                    type="button"
                    onClick={() => onRescan(s)}
                    className="rounded bg-slate-800 px-2 py-1 text-slate-300 transition hover:bg-slate-700 hover:text-emerald-400"
                    title={`Scan ${s}`}
                  >
                    {s}
                  </button>
                ) : (
                  <span className="rounded bg-slate-800 px-2 py-1 text-slate-300">{s}</span>
                )}
              </li>
            ))}
          </ul>
        </>
      )}
    </Card>
  );
}

/**
 * Skeleton placeholder shown while a check's result is still streaming in.
 * @param {{title:string}} props - The card title to display above the shimmer.
 * @returns {JSX.Element}
 */
export function SkeletonCard({ title }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5">
      <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-600">{title}</h3>
      <div className="animate-pulse space-y-2">
        <div className="h-3 w-3/4 rounded bg-slate-800" />
        <div className="h-3 w-1/2 rounded bg-slate-800" />
        <div className="h-3 w-2/3 rounded bg-slate-800" />
      </div>
    </div>
  );
}

/**
 * Recursively render a path tree (folders before files, indented).
 * @param {object} node - Tree node (object of child segments).
 * @param {number} [depth=0]
 * @returns {JSX.Element}
 */
function renderTree(node, depth = 0) {
  const keys = Object.keys(node).sort();
  return (
    <ul className={depth ? "ml-2 border-l border-slate-800 pl-3" : ""}>
      {keys.map((k) => {
        const hasChildren = Object.keys(node[k]).length > 0;
        return (
          <li key={k} className="text-xs">
            <span className="font-mono text-slate-300">
              {hasChildren ? "📁" : "📄"} {k}
            </span>
            {hasChildren && renderTree(node[k], depth + 1)}
          </li>
        );
      })}
    </ul>
  );
}

/**
 * Site map card — a derived path tree from robots.txt + sitemap.xml.
 * @param {{data:object}} props - The "tree" result event.
 * @returns {JSX.Element}
 */
export function TreeCard({ data }) {
  if (!data.ok) {
    return (
      <Card title="Site Map" accent="slate">
        <p className="text-sm text-slate-400">{data.error || "No published paths found"}</p>
      </Card>
    );
  }
  return (
    <Card title={`Site Map (${data.total} files · ${data.hosts ?? 1} host${(data.hosts ?? 1) > 1 ? "s" : ""})`} accent="slate">
      <p className="mb-2 text-xs text-slate-500">
        From {data.sources.join(" + ")} — paths the site publishes plus every resource the page loads, grouped by host (like DevTools “Sources”). Not a real filesystem listing.
      </p>
      {renderTree(data.tree)}
    </Card>
  );
}

/**
 * HTTP methods card — advertised methods + risky ones.
 * @param {{data:object}} props - The "methods" result event.
 * @returns {JSX.Element}
 */
export function MethodsCard({ data }) {
  if (!data.ok) {
    return (
      <Card title="HTTP Methods" accent="slate">
        <p className="text-sm text-slate-400">{data.error || "Could not check"}</p>
      </Card>
    );
  }
  const dangerous = data.dangerous || [];
  return (
    <Card title="HTTP Methods" accent={dangerous.length ? "amber" : "emerald"}>
      <dl className="space-y-1 text-sm">
        <Row k="Allowed" v={data.allow?.length ? data.allow.join(", ") : "— (not advertised)"} />
        <Row k="Risky" v={dangerous.length ? dangerous.join(", ") : "none"} warn={dangerous.length > 0} />
      </dl>
    </Card>
  );
}

/**
 * IP / network enrichment card — GeoIP, ASN/org, reverse DNS.
 * @param {{data:object}} props - The "geo" result event.
 * @returns {JSX.Element}
 */
export function GeoCard({ data }) {
  if (!data.ok) {
    return (
      <Card title="IP / Network" accent="slate">
        <p className="text-sm text-slate-400">{data.error || "No data"}</p>
      </Card>
    );
  }
  const location = [data.city, data.region, data.country].filter(Boolean).join(", ");
  return (
    <Card title="IP / Network" accent="slate">
      <dl className="space-y-1 text-sm">
        <Row k="IP" v={data.ip || "—"} />
        <Row k="Reverse DNS" v={data.ptr || "—"} />
        <Row k="Location" v={location || "—"} />
        <Row k="ASN" v={data.asn || "—"} />
        <Row k="Network" v={data.org || "—"} />
      </dl>
      {data.error && <p className="mt-2 text-xs text-slate-600">{data.error}</p>}
    </Card>
  );
}

/**
 * Page-content audit card — leaked secrets, vulnerable JS libs, mixed content,
 * and scripts missing Subresource Integrity.
 * @param {{data:object}} props - The "content" result event.
 * @returns {JSX.Element}
 */
export function ContentCard({ data }) {
  if (!data.ok) {
    return (
      <Card title="Page Content (JS / secrets)" accent="slate">
        <p className="text-sm text-slate-400">{data.error || "Could not fetch homepage"}</p>
      </Card>
    );
  }
  const malware = data.malware || [];
  const inject = data.promptInjection || [];
  const secrets = data.secrets || [];
  const vuln = data.vulnLibs || [];
  const mixed = data.mixedContent || [];
  const noSri = data.scriptsNoSri || [];
  const accent =
    malware.length || secrets.length || vuln.length || inject.some((p) => p.severity === "high")
      ? "red"
      : mixed.length || noSri.length || inject.length
        ? "amber"
        : "emerald";
  const clean = !malware.length && !inject.length && !secrets.length && !vuln.length && !mixed.length && !noSri.length;
  const injColor = (sev) => (sev === "high" ? "text-red-400" : sev === "medium" ? "text-amber-400" : "text-slate-400");
  return (
    <Card title="Page Content (code / secrets / AI)" accent={accent}>
      {clean && <p className="text-sm text-emerald-400">No client-side content issues found.</p>}
      {malware.length > 0 && (
        <div className="mb-3">
          <p className="mb-1 text-xs uppercase text-red-500">⚠ Possible malicious / compromise indicators ({malware.length})</p>
          <p className="mb-1 text-[11px] text-slate-500">Patterns linked to compromised or injected/obfuscated code — review before trusting the page.</p>
          <ul className="space-y-1 text-xs">
            {malware.map((m, i) => (
              <li key={i}>
                <span className="text-red-400">{m.type}</span>
                {m.detail ? <span className="block break-all font-mono text-slate-500">{m.detail}</span> : null}
              </li>
            ))}
          </ul>
        </div>
      )}
      {inject.length > 0 && (
        <div className="mb-3">
          <p className="mb-1 text-xs uppercase text-red-500">🤖 LLM / prompt-injection indicators ({inject.length})</p>
          <p className="mb-1 text-[11px] text-slate-500">Hidden text aimed at manipulating AI tools that read this page; treat the page as untrusted input to any LLM.</p>
          <ul className="space-y-1 text-xs">
            {inject.map((p, i) => (
              <li key={i}>
                <span className={injColor(p.severity)}>{p.type}</span>
                {p.detail ? <span className="block break-all font-mono text-slate-500">{p.detail}</span> : null}
              </li>
            ))}
          </ul>
        </div>
      )}
      {secrets.length > 0 && (
        <div className="mb-3">
          <p className="mb-1 text-xs uppercase text-red-500">Leaked secrets ({secrets.length})</p>
          <p className="mb-1 text-[11px] text-slate-500">Credentials shipped in client-side code can be read by anyone — rotate them.</p>
          <ul className="space-y-1 text-xs">
            {secrets.map((s, i) => (
              <li key={i}>
                <span className="text-red-400">{s.type}</span>{" "}
                <span className="font-mono text-slate-500">{s.sample}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {vuln.length > 0 && (
        <div className="mb-3">
          <p className="mb-1 text-xs uppercase text-red-500">Vulnerable libraries ({vuln.length})</p>
          <p className="mb-1 text-[11px] text-slate-500">Library versions with publicly known vulnerabilities — upgrade them.</p>
          <ul className="space-y-1 text-xs">
            {vuln.map((l, i) => (
              <li key={i}>
                <span className="font-mono text-red-400">{l.name} {l.version}</span>
                <span className="block text-slate-500">{l.note}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {mixed.length > 0 && (
        <div className="mb-3">
          <p className="mb-1 text-xs uppercase text-amber-500">Mixed content ({mixed.length})</p>
          <p className="mb-1 text-[11px] text-slate-500">http resources on an https page can be tampered with or blocked by browsers.</p>
          <ul className="space-y-1 font-mono text-xs text-amber-400">
            {mixed.slice(0, 8).map((u) => (
              <li key={u} className="break-all">{u}</li>
            ))}
          </ul>
        </div>
      )}
      {noSri.length > 0 && (
        <div className="mb-3">
          <p className="mb-1 text-xs uppercase text-amber-500">Scripts without SRI ({noSri.length})</p>
          <p className="mb-1 text-[11px] text-slate-500">
            Third-party scripts loaded without a Subresource Integrity hash run with full trust — if that host is
            compromised, it can execute arbitrary code on your page. Add an integrity hash + crossorigin to each
            (e.g. integrity=&quot;sha384-…&quot; crossorigin=&quot;anonymous&quot;).
          </p>
          <ul className="space-y-1 text-xs">
            {noSri.map((u) => {
              let host = u;
              try {
                host = new URL(u).host;
              } catch {
                host = u;
              }
              return (
                <li key={u}>
                  <span className="font-mono text-amber-400">{host}</span>
                  <span className="block break-all font-mono text-slate-500">{u}</span>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </Card>
  );
}
