// Licence keys: <PREFIX>- then 26 Crockford base32 characters (128 random bits,
// padded to 130) in groups of 5, then one Crockford check character (the
// 130-bit value mod 37), e.g. MYAPP-7K2QM-ZD0A4-RT8VX-W3NBC-PF9HS-1N.
// The prefix is a hint, isn't secret and isn't part of the key's identity.

const DIGITS = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32
const CHECK = DIGITS + "*~$=U"; // the 37 check symbols

function decodeSymbol(c) {
  const m = { O: "0", I: "1", L: "1" }[c] ?? c;
  return DIGITS.indexOf(m);
}

function checkOf(body) {
  let r = 0;
  for (const c of body) r = (r * 32 + DIGITS.indexOf(c)) % 37;
  return CHECK[r];
}

/** A new random key for a prefix. */
export function generateKey(prefix) {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  // 128 bits -> 26 symbols: two zero bits first, then the bytes, 5 bits at a time.
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  let body = "";
  for (let i = 25; i >= 0; i--) body += DIGITS[Number((acc >> BigInt(i * 5)) & 31n)];
  return formatKey(prefix, body);
}

export function formatKey(prefix, body) {
  const all = body + checkOf(body);
  const groups = all.match(/.{1,5}/g);
  return `${prefix}-${groups.join("-")}`;
}

/**
 * Parses what a buyer typed or pasted. Spaces and dashes are ignored, case
 * doesn't matter, O reads as 0 and I/L as 1, and anything before the last 27
 * symbols is the prefix. Returns { prefix, body } (body = 26 canonical
 * symbols, the key's identity) or null for a malformed key or a bad check
 * character (a typo caught before any database read).
 */
export function parseKey(input) {
  if (typeof input !== "string" || input.length > 80) return null;
  const s = input.toUpperCase().replace(/[\s-]+/g, "");
  if (s.length < 27) return null;
  const tail = s.slice(-27);
  const prefix = s.slice(0, -27);
  if (prefix && !/^[A-Z0-9]{1,12}$/.test(prefix)) return null;
  let body = "";
  for (const c of tail.slice(0, 26)) {
    const v = decodeSymbol(c);
    if (v < 0) return null;
    body += DIGITS[v];
  }
  // The first symbol carries only 3 bits (128 bits in 130).
  if (DIGITS.indexOf(body[0]) > 7) return null;
  const check = tail[26];
  const want = checkOf(body);
  const got = CHECK.includes(check) ? check : DIGITS[decodeSymbol(check)];
  if (got !== want) return null;
  return { prefix, body };
}

export const PREFIX_RE = /^[A-Z0-9]{1,12}$/;
