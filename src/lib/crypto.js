// Hashes, HMAC, constant-time comparison, Ed25519 and AES-GCM.
// hex/base64/sha256/hmacHex/safeEqual/sortableId from perchlight-hooks
// src/lib/crypto.js (itself from perchlight-status); Ed25519 signing and
// AES-GCM key copies are new here. Everything runs in WebCrypto: no dependency.

const enc = new TextEncoder();
export const utf8 = (s) => enc.encode(String(s));

export function hex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Hex string -> bytes, or null if it isn't even-length hex. */
export function fromHex(s) {
  if (typeof s !== "string" || s.length % 2 || !/^[0-9a-fA-F]*$/.test(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function toBase64(bytes) {
  let bin = "";
  const u = new Uint8Array(bytes);
  for (let i = 0; i < u.length; i += 0x8000) bin += String.fromCharCode(...u.subarray(i, i + 0x8000));
  return btoa(bin);
}

export const toBase64Url = (bytes) => toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/** Base64 (standard or URL-safe, padding optional) -> bytes, or null. */
export function fromBase64(s) {
  if (typeof s !== "string") return null;
  let t = s.trim().replace(/-/g, "+").replace(/_/g, "/");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(t)) return null;
  t = t.replace(/=+$/, "");
  if (t.length % 4 === 1) return null;
  t += "=".repeat((4 - (t.length % 4)) % 4);
  try {
    const bin = atob(t);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

export async function sha256Hex(data) {
  return hex(await crypto.subtle.digest("SHA-256", typeof data === "string" ? enc.encode(data) : data));
}

const hmacCache = new Map();
async function hmacSignKey(secret) {
  let k = hmacCache.get(secret);
  if (!k) {
    k = await crypto.subtle.importKey("raw", enc.encode(String(secret)), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    if (hmacCache.size > 32) hmacCache.clear();
    hmacCache.set(secret, k);
  }
  return k;
}

/** HMAC-SHA256(key, message) as lower-case hex. message: string or bytes. */
export async function hmacHex(key, message) {
  const k = await hmacSignKey(key);
  return hex(await crypto.subtle.sign("HMAC", k, typeof message === "string" ? enc.encode(message) : message));
}

/**
 * Constant-time comparison of two strings: hashes both first (so lengths don't
 * leak either), then crypto.subtle.timingSafeEqual. Every secret, HMAC and
 * signature comparison in this Worker goes through `ct.equal`, an object so a
 * test can check that it's used.
 */
async function safeEqual(a, b) {
  const [x, y] = await Promise.all([crypto.subtle.digest("SHA-256", enc.encode(String(a))), crypto.subtle.digest("SHA-256", enc.encode(String(b)))]);
  return crypto.subtle.timingSafeEqual(x, y);
}
export const ct = { equal: safeEqual };

const ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789"; // 32 symbols: no 0/o, 1/l

let lastMs = 0;
let seq = 0;
/** A time-sortable id: 9 base-36 characters of milliseconds, a 3-character
 *  per-isolate sequence, then 10 random characters (50 bits). */
export function sortableId(prefix, now = Date.now()) {
  const ms = Math.floor(now);
  seq = ms === lastMs ? seq + 1 : 0;
  lastMs = ms;
  const bytes = crypto.getRandomValues(new Uint8Array(10));
  let r = "";
  for (const b of bytes) r += ALPHABET[b & 31];
  return `${prefix}${ms.toString(36).padStart(9, "0")}${Math.min(seq, 46655).toString(36).padStart(3, "0")}${r}`;
}

/** 128 random bits, base64url (22 characters). */
export function randomToken() {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(16)));
}

// ---------------------------------------------------------------- Ed25519

const ED = { name: "Ed25519" };
const signerCache = new Map();

/**
 * Imports one SIGNING_KEYS entry: a base64 PKCS#8 Ed25519 private key.
 * Returns { privateKey, publicRaw (32 bytes) }. The public key is read from the
 * JWK export (`x`), so only the private key needs to be configured.
 */
export async function importSigningKey(b64) {
  const cached = signerCache.get(b64);
  if (cached) return cached;
  const der = fromBase64(b64);
  if (!der) throw new Error("not base64");
  const privateKey = await crypto.subtle.importKey("pkcs8", der, ED, true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  const publicRaw = fromBase64(jwk.x);
  if (!publicRaw || publicRaw.length !== 32) throw new Error("no public key in the JWK export");
  const out = { privateKey, publicRaw };
  if (signerCache.size > 16) signerCache.clear();
  signerCache.set(b64, out);
  return out;
}

export async function ed25519Sign(privateKey, bytes) {
  return new Uint8Array(await crypto.subtle.sign(ED, privateKey, bytes));
}

const verifierCache = new Map();
export async function ed25519Verify(publicRaw, signature, bytes) {
  const id = toBase64(publicRaw);
  let key = verifierCache.get(id);
  if (!key) {
    key = await crypto.subtle.importKey("raw", publicRaw, ED, false, ["verify"]);
    if (verifierCache.size > 16) verifierCache.clear();
    verifierCache.set(id, key);
  }
  try {
    return await crypto.subtle.verify(ED, key, signature, bytes);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- AES-GCM

const aesCache = new Map();
async function aesKey(secret) {
  let k = aesCache.get(secret);
  if (!k) {
    const base = await crypto.subtle.importKey("raw", enc.encode(String(secret)), "HKDF", false, ["deriveKey"]);
    k = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode("perchlight-keys/key-enc/v1") },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    if (aesCache.size > 16) aesCache.clear();
    aesCache.set(secret, k);
  }
  return k;
}

/** "<kid>.<iv>.<ciphertext>" (base64url), bound to `aad` (the licence id). */
export async function aesEncrypt(kid, secret, plaintext, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8(aad) }, await aesKey(secret), utf8(plaintext));
  return `${kid}.${toBase64Url(iv)}.${toBase64Url(ctBuf)}`;
}

/** The kid of an encrypted value. */
export const encKid = (value) => String(value).split(".")[0];

/** Decrypts with secrets {kid: secret}; null if the kid is unknown or it fails. */
export async function aesDecrypt(secrets, value, aad) {
  const [kid, ivB, ctB] = String(value).split(".");
  const secret = secrets[kid];
  const iv = fromBase64(ivB);
  const data = fromBase64(ctB);
  if (!secret || !iv || !data) return null;
  try {
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: utf8(aad) }, await aesKey(secret), data);
    return new TextDecoder().decode(pt);
  } catch {
    return null;
  }
}
