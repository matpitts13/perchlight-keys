// Buyer-facing routes: "resend my keys" and the itch.io claim page.
import { aesDecrypt, hmacHex, sortableId } from "../lib/crypto.js";
import { escapeHtml, json, normEmail, page, readInput } from "../lib/http.js";
import { deliveryStmt, encSecrets, issue } from "../lib/licenses.js";
import { sendDelivery } from "../lib/deliveries.js";
import { d1Hits, ipHash } from "../lib/rate.js";
import { itchDownloadKey, TransientError } from "../lib/providers.js";

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

// ------------------------------------------------------------ resend my keys

/**
 * POST /v1/resend {email}: always 202 {"ok":true}, the same body and headers
 * for every address and every throttle. The lookup, the limits and the send
 * all run in waitUntil, after the answer, so timing says nothing either.
 */
export async function handleResend(request, app) {
  const input = await readInput(request, 4096).catch(() => null);
  const email = normEmail(input?.email);
  app.waitUntil(resendWork(app, request, email));
  return json({ ok: true }, 202);
}

async function emailBucket(app, email) {
  const salt = app.env.IP_SALT || app.env.KEY_LOOKUP_SECRET || "perchlight-keys";
  return (await hmacHex(salt, `email/${email}`)).slice(0, 32);
}

export async function resendWork(app, request, email) {
  const ip = await ipHash(app, request);
  const buckets = [{ bucket: `rs:ip:${ip}`, windowMs: HOUR, limit: 10 }];
  if (email) {
    const e = await emailBucket(app, email);
    buckets.push({ bucket: `rs:e15:${e}`, windowMs: 15 * MIN, limit: 1 }, { bucket: `rs:eday:${e}`, windowMs: DAY, limit: 5 });
  }
  if (!(await d1Hits(app, buckets)) || !email) return "limited";
  const has = await app.db.prepare("SELECT 1 AS x FROM licenses WHERE email = ? AND status != 'revoked' LIMIT 1").bind(email).first();
  if (!has) return "none";
  const cap = Math.max(1, Number.parseInt(app.env.RESEND_DAILY_CAP ?? "200", 10) || 200);
  if (!(await d1Hits(app, [{ bucket: "rs:global", windowMs: DAY, limit: cap }]))) return "cap";
  const id = sortableId("dlv_", app.now);
  await deliveryStmt(app, { id, licenseId: null, kind: "resend", email }).run();
  await sendDelivery(app, id);
  return "sent";
}

// ------------------------------------------------------------ itch.io claim

function itchProducts(app) {
  return Object.values(app.cfg.products).filter((p) => p.map?.itch && Object.keys(p.map.itch).length);
}

function claimForm(app, message = "") {
  const prods = itchProducts(app);
  if (!prods.length || !app.env.ITCH_API_KEY) return page("Claim a licence key", "<p>itch.io claims aren't set up here.</p>", 404);
  const select =
    prods.length > 1
      ? `<label>Product<select name="product">${prods.map((p) => `<option value="${escapeHtml(p.id)}">${escapeHtml(p.name)}</option>`).join("")}</select></label>`
      : `<input type="hidden" name="product" value="${escapeHtml(prods[0].id)}">`;
  return page(
    "Claim a licence key",
    `${message ? `<p><strong>${escapeHtml(message)}</strong></p>` : ""}<p>Bought on itch.io? Paste your download key (or the download page's address) and the email address to send the licence key to.</p>
<form method="post" action="/claim/itch">${select}<label>Download key or download URL<input name="download_key" required maxlength="300" autocomplete="off"></label>
<label>Email<input name="email" type="email" required maxlength="254" autocomplete="email"></label><button type="submit">Claim</button></form>`,
  );
}

/** The download key from a pasted key or download URL, or null. */
export function extractDownloadKey(input) {
  if (typeof input !== "string" || input.length > 300) return null;
  const s = input.trim();
  const m = /\/download\/([A-Za-z0-9_-]{10,80})(?:[/?#]|$)/.exec(s);
  if (m) return m[1];
  return /^[A-Za-z0-9_-]{10,80}$/.test(s) ? s : null;
}

const GENERIC = "That download key couldn't be used. Check it and try again, or contact the seller.";

export async function handleClaim(request, app) {
  if (request.method === "GET") return claimForm(app);
  if (request.method !== "POST") return page("Claim a licence key", "<p>Not allowed.</p>", 405);
  const prods = itchProducts(app);
  if (!prods.length || !app.env.ITCH_API_KEY) return claimForm(app);
  const input = await readInput(request, 4096);
  const prod = prods.find((p) => p.id === input?.product) ?? (prods.length === 1 ? prods[0] : null);
  const dk = extractDownloadKey(input?.download_key);
  const email = normEmail(input?.email);
  if (!prod || !dk || !email) return claimForm(app, "Enter a download key and a valid email address.");
  const ip = await ipHash(app, request);
  const dkHash = (await hmacHex(app.env.IP_SALT || app.env.KEY_LOOKUP_SECRET || "perchlight-keys", `dk/${dk}`)).slice(0, 32);
  const ok = await d1Hits(app, [
    { bucket: `cl:ip:${ip}`, windowMs: HOUR, limit: 10 },
    { bucket: `cl:dk:${dkHash}`, windowMs: DAY, limit: 5 },
  ]);
  if (!ok) return claimForm(app, "Too many attempts. Try again later.");
  let found = null;
  let edition = null;
  try {
    for (const [gameId, v] of Object.entries(prod.map.itch).slice(0, 3)) {
      found = await itchDownloadKey(app, gameId, dk);
      if (found) {
        edition = typeof v === "string" ? v : v.edition;
        break;
      }
    }
  } catch (err) {
    if (!(err instanceof TransientError)) throw err;
    return claimForm(app, "itch.io didn't answer. Try again in a few minutes.");
  }
  if (!found) return claimForm(app, GENERIC);
  const ref = String(found.id);
  const r = await issue(app, { product: prod, edition, email, source: "itch", sourceRef: ref, refs: [{ source: "itch", ref }], sendEmail: true });
  let key = r.key;
  let deliveryId = r.deliveryId;
  if (r.status !== "issued") {
    // Claimed before: show the same key again and re-send it to the address on file.
    key = await aesDecrypt(encSecrets(app.env).secrets, r.license.key_enc, r.license.id);
    deliveryId = sortableId("dlv_", app.now);
    await deliveryStmt(app, { id: deliveryId, licenseId: r.license.id, kind: "key_issued", email: r.license.email }).run();
  }
  if (deliveryId) app.waitUntil(sendDelivery(app, deliveryId));
  const where = r.status === "issued" ? "We've emailed it to you too." : "It was claimed before; we've emailed it again to the address it was first sent to.";
  return page(
    "Your licence key",
    `<p>${escapeHtml(prod.name)}:</p><p><code>${escapeHtml(key ?? "(couldn't be shown; contact the seller)")}</code></p><p>${escapeHtml(where)}</p>`,
  );
}
