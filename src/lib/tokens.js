// Signed tokens (docs/FORMAT.md): licence files, leases, trial leases and the
// revocation list.
//   PLK1.<base64url(payload JSON)>.<base64url(Ed25519 signature)>
//   signature = Ed25519(private[kid], "perchlight-keys/v1\n" || typ || "\n" || payloadBytes)
// The prefix and the typ are domain separation: a revocation list can't pass
// as a licence, and a v1 signature can't be reused by a later format.
import { ed25519Sign, ed25519Verify, fromBase64, importSigningKey, toBase64Url, utf8 } from "./crypto.js";

export const TYPES = ["lic", "lease", "trial", "revs"];
const MAX_TOKEN = 8192;

function signedBytes(typ, payloadBytes) {
  const head = utf8(`perchlight-keys/v1\n${typ}\n`);
  const all = new Uint8Array(head.length + payloadBytes.length);
  all.set(head, 0);
  all.set(payloadBytes, head.length);
  return all;
}

/**
 * Parses SIGNING_KEYS / ACTIVE_KID. Returns { active, keys: {kid: b64} } or
 * throws with a message naming what's wrong (never the key itself).
 */
export function signingConfig(env) {
  let keys;
  try {
    keys = JSON.parse(env.SIGNING_KEYS || "");
  } catch {
    throw new Error("SIGNING_KEYS isn't set or isn't JSON");
  }
  if (!keys || typeof keys !== "object" || Array.isArray(keys) || !Object.keys(keys).length) throw new Error("SIGNING_KEYS has no keys");
  for (const kid of Object.keys(keys)) if (!/^[A-Za-z0-9_-]{1,32}$/.test(kid)) throw new Error("SIGNING_KEYS: a kid must be 1-32 letters, digits, _ or -");
  const active = env.ACTIVE_KID || "";
  if (!keys[active]) throw new Error("ACTIVE_KID isn't one of the SIGNING_KEYS kids");
  return { active, keys };
}

/** Signs a payload with the active key; sets payload.kid. */
export async function signToken(env, payload) {
  const cfg = signingConfig(env);
  if (!TYPES.includes(payload.typ)) throw new Error("bad typ");
  const { privateKey } = await importSigningKey(cfg.keys[cfg.active]);
  const body = { ...payload, kid: cfg.active };
  const payloadBytes = utf8(JSON.stringify(body));
  const sig = await ed25519Sign(privateKey, signedBytes(body.typ, payloadBytes));
  return `PLK1.${toBase64Url(payloadBytes)}.${toBase64Url(sig)}`;
}

/** Public keys {kid: base64url raw 32 bytes} for every configured kid. */
export async function publicKeys(env) {
  const cfg = signingConfig(env);
  const out = {};
  for (const [kid, b64] of Object.entries(cfg.keys)) out[kid] = toBase64Url((await importSigningKey(b64)).publicRaw);
  return { active: cfg.active, keys: out };
}

/**
 * Verifies a token against public keys {kid: raw bytes | base64}. Checks only
 * the format and the signature, and that typ is the expected one; returns the
 * payload or null. Time and device checks are the caller's.
 */
export async function verifyToken(token, pubKeys, expectTyp) {
  if (typeof token !== "string" || token.length > MAX_TOKEN) return null;
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== "PLK1") return null;
  const payloadBytes = fromBase64(parts[1]);
  const sig = fromBase64(parts[2]);
  if (!payloadBytes || !sig || sig.length !== 64) return null;
  let payload;
  try {
    payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payloadBytes));
  } catch {
    return null;
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  if (!TYPES.includes(payload.typ) || (expectTyp && payload.typ !== expectTyp)) return null;
  let pub = pubKeys[payload.kid];
  if (!Object.hasOwn(pubKeys, payload.kid) || !pub) return null;
  if (typeof pub === "string") pub = fromBase64(pub);
  if (!pub || pub.length !== 32) return null;
  return (await ed25519Verify(pub, sig, signedBytes(payload.typ, payloadBytes))) ? payload : null;
}

/** Public keys of this deployment as raw bytes (for verifying its own leases on renew). */
export async function ownPublicKeys(env) {
  const cfg = signingConfig(env);
  const out = {};
  for (const [kid, b64] of Object.entries(cfg.keys)) out[kid] = (await importSigningKey(b64)).publicRaw;
  return out;
}
