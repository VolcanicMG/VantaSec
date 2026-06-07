/**
 * HTTP response helpers for the scanner.
 *
 * Single responsibility: read response bodies safely. The scanner only parses
 * bodies from trusted third-party APIs (NVD, CertSpotter), but a cap is cheap
 * defense-in-depth against a runaway/oversized payload exhausting memory.
 */

/**
 * Read a fetch Response body as text, aborting if it exceeds maxBytes.
 *
 * @param {Response} res - A fetch Response.
 * @param {number} maxBytes - Hard cap on the (decoded) body size in bytes.
 * @returns {Promise<string>} The body text.
 * @throws {Error} If the body exceeds maxBytes (the stream is cancelled first).
 */
export async function readCappedText(res, maxBytes) {
  const reader = res.body?.getReader?.();
  if (!reader) return await res.text();
  const decoder = new TextDecoder();
  let out = "";
  let total = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`Response exceeded ${maxBytes}-byte cap`);
    }
    out += decoder.decode(value, { stream: true });
  }
  out += decoder.decode();
  return out;
}
