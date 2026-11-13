// Small HTTP helpers. From perchlight-hooks src/lib/http.js (itself from
// perchlight-status), plus a capped form reader and one HTML page shell for
// the itch.io claim form.

const BASE_HEADERS = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };

export function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...BASE_HEADERS, ...extraHeaders } });
}

/** An API error: { error, message }. */
export function fail(status, error, message = error, extra = {}, headers = {}) {
  return json({ error, message, ...extra }, status, headers);
}

export function text(body, status = 200, extraHeaders = {}) {
  return new Response(body, { status, headers: { "Content-Type": "text/plain; charset=utf-8", ...BASE_HEADERS, ...extraHeaders } });
}

export function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

/** A minimal page. `body` must already be escaped HTML. */
export function page(title, body, status = 200) {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>${escapeHtml(title)}</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem;color:#1d1d1f;background:#fff}input,select,button{font:inherit;padding:.5rem;width:100%;box-sizing:border-box;margin:.25rem 0 1rem}code{font-size:1.1rem;word-break:break-all}@media (prefers-color-scheme:dark){body{color:#eee;background:#151517}}</style></head><body><h1>${escapeHtml(title)}</h1>${body}</body></html>`;
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      ...BASE_HEADERS,
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
      "Referrer-Policy": "no-referrer",
    },
  });
}

/**
 * Reads a stream up to `max` bytes. Stops (and cancels) beyond it.
 * @returns {Promise<{ bytes: Uint8Array, size: number, over: boolean }>}
 */
export async function readCapped(stream, max) {
  if (!stream) return { bytes: new Uint8Array(0), size: 0, over: false };
  const reader = stream.getReader();
  const chunks = [];
  let size = 0;
  let over = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (size + value.byteLength > max) {
      over = true;
      await reader.cancel().catch(() => {});
      break;
    }
    chunks.push(value);
    size += value.byteLength;
  }
  const all = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    all.set(c, at);
    at += c.byteLength;
  }
  return { bytes: all, size, over };
}

/** The raw body as bytes, or null if over maxBytes. */
export async function readBody(request, maxBytes) {
  const len = Number(request.headers.get("Content-Length") ?? "0");
  if (len > maxBytes) return null;
  const r = await readCapped(request.body, maxBytes);
  return r.over ? null : r.bytes;
}

/** Reads a JSON object of at most maxBytes, or null. */
export async function readJson(request, maxBytes = 8 * 1024) {
  const bytes = await readBody(request, maxBytes);
  if (!bytes) return null;
  try {
    const v = JSON.parse(new TextDecoder().decode(bytes) || "{}");
    return v && typeof v === "object" && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

/** A JSON or form-encoded body as a plain object of strings/values, or null. */
export async function readInput(request, maxBytes = 8 * 1024) {
  const type = request.headers.get("Content-Type") ?? "";
  if (type.includes("application/x-www-form-urlencoded")) {
    const bytes = await readBody(request, maxBytes);
    if (!bytes) return null;
    return Object.fromEntries(new URLSearchParams(new TextDecoder().decode(bytes)));
  }
  return readJson(request, maxBytes);
}

export const str = (v, max) => (typeof v === "string" && v.length <= max ? v : null);

const EMAIL_RE = /^[^\s@<>()",;:\\[\]]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+$/;
/** A normalised (trimmed, lower-case) email address, or null. */
export function normEmail(v) {
  if (typeof v !== "string") return null;
  const e = v.trim().toLowerCase();
  return e.length <= 254 && EMAIL_RE.test(e) ? e : null;
}

export function utcDay(ms) {
  return new Date(ms).toISOString().slice(0, 10);
}

export const parseJson = (s, d) => {
  try {
    return s == null ? d : JSON.parse(s);
  } catch {
    return d;
  }
};
