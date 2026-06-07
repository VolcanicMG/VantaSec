/**
 * Target parsing/normalization.
 *
 * Single responsibility: turn whatever the user typed (a bare IP, a hostname,
 * or a full URL) into a clean { host, displayName, httpUrl } shape that the
 * rest of the scanner can rely on. No network work happens here.
 */

/**
 * Strip scheme/path/port noise and derive a hostname plus a usable HTTP URL.
 *
 * @param {string} raw - Raw user input (e.g. "example.com", "https://x.io/y", "1.2.3.4").
 * @returns {{ host: string, displayName: string, httpUrl: string }}
 *   host: bare hostname or IP used for socket/DNS/TLS work.
 *   displayName: what we show back to the user.
 *   httpUrl: a normalized https URL used for header/HTTP checks.
 * @throws {Error} If the input is empty or cannot yield a hostname.
 */
export function parseTarget(raw) {
  if (!raw || typeof raw !== "string") {
    throw new Error("Target is required");
  }
  let input = raw.trim();
  if (!input) throw new Error("Target is required");

  // If the user didn't give a scheme, add one so the URL parser works.
  const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(input);
  const urlString = hasScheme ? input : `https://${input}`;

  let url;
  try {
    url = new URL(urlString);
  } catch {
    throw new Error(`Could not parse target: ${raw}`);
  }

  const host = url.hostname;
  if (!host) throw new Error(`No hostname found in: ${raw}`);

  // Always probe HTTP over https on the standard port for the header check;
  // the port scan covers actual open ports separately.
  const httpUrl = `https://${host}`;

  return { host, displayName: host, httpUrl };
}

/**
 * Quick check: does this string look like an IPv4 address?
 *
 * @param {string} host - Hostname or IP.
 * @returns {boolean} True if it parses as dotted-quad IPv4.
 */
export function isIPv4(host) {
  const parts = host.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    if (!/^\d{1,3}$/.test(p)) return false;
    const n = Number(p);
    return n >= 0 && n <= 255;
  });
}
