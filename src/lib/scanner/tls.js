/**
 * TLS / certificate inspection.
 *
 * Single responsibility: open a TLS connection to host:443 and report the
 * negotiated protocol plus certificate facts (issuer, subject, validity,
 * days-until-expiry), and probe whether deprecated protocols (TLS 1.0/1.1)
 * are still accepted. Pure Node (tls module).
 */

import tls from "node:tls";

/** Deprecated protocols we actively probe for acceptance. */
const LEGACY_VERSIONS = ["TLSv1", "TLSv1.1"];

/** Cipher families considered weak/legacy if negotiated. */
const WEAK_CIPHER = /RC4|3DES|DES|NULL|EXPORT|MD5|anon/i;

/**
 * Derive an SSL-Labs-style letter grade from the inspected TLS facts.
 *
 * @param {object} p - The TLS result payload.
 * @returns {string} Grade A–F.
 */
function gradeTls(p) {
  if (!p.ok) return "F";
  if (p.daysRemaining != null && p.daysRemaining < 0) return "F"; // expired cert
  const order = ["A", "B", "C", "D", "F"];
  let idx = 0;
  const down = (to) => {
    idx = Math.max(idx, order.indexOf(to));
  };
  if (p.protocolWeak) down("C"); // negotiated TLS < 1.2
  if (p.weakProtocols?.length) down("B"); // still accepts deprecated TLS
  if (p.keyWeak) down("C"); // RSA < 2048
  if (p.weakCipher) down("C"); // RC4/3DES/etc
  if (p.authError) down("C"); // chain/hostname trust problem
  if (p.daysRemaining != null && p.daysRemaining < 21) down("B"); // expiring soon
  return order[idx];
}

/**
 * Probe whether the server will negotiate a specific (legacy) TLS version.
 *
 * @param {string} host - Target hostname (used for SNI).
 * @param {number} port - TLS port.
 * @param {string} version - Pinned version, e.g. "TLSv1.1".
 * @param {number} timeout - Connection timeout in ms.
 * @param {string} connectHost - IP/host to actually connect to (the guard-pinned IP).
 * @returns {Promise<boolean>} True if the server accepted that version.
 */
function probeProtocol(host, port, version, timeout, connectHost) {
  return new Promise((resolve) => {
    let done = false;
    /** @param {boolean} accepted */
    const finish = (accepted) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(accepted);
    };
    let socket;
    try {
      // Connect to the validated IP, but keep SNI = hostname so the right cert
      // is presented and vhost routing still works.
      socket = tls.connect(
        { host: connectHost, port, servername: host, rejectUnauthorized: false, timeout, minVersion: version, maxVersion: version },
        () => finish(true)
      );
    } catch {
      return resolve(false);
    }
    socket.on("error", () => finish(false));
    socket.on("timeout", () => finish(false));
  });
}

/**
 * Inspect the TLS certificate and negotiated protocol for a host, and detect
 * whether deprecated protocol versions are still accepted.
 *
 * @param {string} host - Target hostname (SNI is set to this).
 * @param {object} [opts]
 * @param {number} [opts.port=443] - TLS port.
 * @param {number} [opts.timeout=6000] - Connection timeout in ms.
 * @param {string} [opts.connectIp] - Pre-validated public IP to connect to
 *   instead of re-resolving `host` (prevents DNS-rebinding to an internal IP).
 *   SNI/cert validation still use `host`.
 * @returns {Promise<object>} { ok, protocol, protocolWeak, weakProtocols[],
 *   issuer, subject, validFrom, validTo, daysRemaining, authorized, authError, error }.
 */
export function inspectTls(host, opts = {}) {
  const port = opts.port ?? 443;
  const timeout = opts.timeout ?? 6000;
  // Connect to the guard-validated IP when provided; never re-resolve the name.
  const connectHost = opts.connectIp ?? host;

  return new Promise((resolve) => {
    let settled = false;
    /** Resolve once with a normalized payload. @param {object} payload */
    const finish = (payload) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(payload);
    };

    // requestOCSP asks the server to staple a revocation response; we record
    // whether it actually does (faster, more private revocation for clients).
    let ocspStapled = false;

    const socket = tls.connect(
      { host: connectHost, port, servername: host, rejectUnauthorized: false, timeout, requestOCSP: true, ALPNProtocols: ["h2", "http/1.1"] },
      async () => {
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol();
        if (!cert || Object.keys(cert).length === 0) {
          return finish({ ok: false, error: "No certificate presented" });
        }
        const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
        const daysRemaining = validTo
          ? Math.round((validTo.getTime() - Date.now()) / 86400000)
          : null;

        // Probe deprecated protocols in parallel; any acceptance is a finding.
        const accepted = await Promise.all(
          LEGACY_VERSIONS.map((v) => probeProtocol(host, port, v, timeout, connectHost))
        );
        const weakProtocols = LEGACY_VERSIONS.filter((_, i) => accepted[i]);
        // Negotiated protocol is weak if it's anything below TLS 1.2.
        const protocolWeak = !!protocol && /TLSv1(\.1)?$/.test(protocol);

        // Public-key facts: EC exposes a curve; RSA a modulus. Sub-2048-bit RSA is weak.
        const curve = cert.nistCurve || cert.asn1Curve || null;
        const keyType = curve ? "EC" : cert.modulus ? "RSA" : null;
        const keyBits = cert.bits ?? null;
        const keyWeak = keyType === "RSA" && keyBits != null && keyBits < 2048;

        // Subject Alternative Names arrive as "DNS:a.com, DNS:b.com"; split to a list.
        const san = cert.subjectaltname
          ? cert.subjectaltname.split(",").map((s) => s.trim().replace(/^DNS:/i, ""))
          : [];
        // OCSP responder URL advertised in the cert's Authority Info Access.
        const ocspUri = cert.infoAccess?.["OCSP - URI"]?.[0] || null;

        // Negotiated cipher + ALPN (HTTP/2 support). This is the *negotiated*
        // suite, not a full enumeration of everything the server would accept.
        const cipherInfo = socket.getCipher() || {};
        const cipher = cipherInfo.standardName || cipherInfo.name || null;
        const weakCipher = !!cipher && WEAK_CIPHER.test(cipher);
        const http2 = socket.alpnProtocol === "h2";

        const result = {
          ok: true,
          protocol,
          protocolWeak,
          weakProtocols,
          issuer: cert.issuer?.O || cert.issuer?.CN || "unknown",
          subject: cert.subject?.CN || host,
          validFrom: cert.valid_from || null,
          validTo: cert.valid_to || null,
          daysRemaining,
          authorized: socket.authorized,
          authError: socket.authorizationError ? String(socket.authorizationError) : null,
          keyType,
          keyBits,
          keyWeak,
          curve,
          san,
          serialNumber: cert.serialNumber || null,
          fingerprint256: cert.fingerprint256 || null,
          ocspStapled,
          ocspUri,
          cipher,
          weakCipher,
          http2,
        };
        result.grade = gradeTls(result);
        finish(result);
      }
    );

    // Fires before secureConnect when the server staples an OCSP response.
    socket.on("OCSPResponse", (resp) => {
      ocspStapled = !!(resp && resp.length);
    });

    socket.on("timeout", () => finish({ ok: false, error: "TLS connection timed out" }));
    socket.on("error", (err) => finish({ ok: false, error: err.message }));
  });
}
