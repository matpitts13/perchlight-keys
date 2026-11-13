// Emails: claim-then-send, as perchlight-forms src/lib/deliveries.js. A row is
// claimed (status 'sending', attempts + 1) by a conditional UPDATE before
// anything is sent, so two requests can't send the same row. Failures are
// retried after 1 / 5 / 30 min, 2 h and 12 h by the lazy sweep; an unclear
// outcome ('unknown') is never retried automatically. The message is built at
// send time from the licence (keys decrypted then), so no key is ever stored
// in a delivery row.

import { getSender } from "./mail/index.js";
import { redactAddresses } from "./mail/common.js";
import { escapeHtml } from "./http.js";
import { left, spend } from "./budget.js";
import { bump } from "./footprint.js";
import { encSecrets, lookupSecrets, keyHmac } from "./licenses.js";
import { aesDecrypt, aesEncrypt } from "./crypto.js";
import { generateKey, parseKey } from "./keyfmt.js";

export const RETRY_MINUTES = [1, 5, 30, 120, 720];
const MAX_ATTEMPTS = RETRY_MINUTES.length + 1;
const STALE_SENDING_MS = 10 * 60_000;

/** Decrypts a licence's key; with RESEND_REISSUE=1 a key that can't be decrypted (lost KEY_ENC_SECRET) is replaced. */
async function keyFor(app, lic) {
  const encs = encSecrets(app.env);
  const key = await aesDecrypt(encs.secrets, lic.key_enc, lic.id);
  if (key || app.env.RESEND_REISSUE !== "1") return key;
  const product = app.cfg.products[lic.product_id];
  if (!product) return null;
  const fresh = generateKey(product.prefix);
  const look = lookupSecrets(app.env);
  const hmac = await keyHmac(look.active, look.secrets[look.active], parseKey(fresh).body);
  const enc = await aesEncrypt(encs.active, encs.secrets[encs.active], fresh, lic.id);
  const r = await app.db.prepare("UPDATE licenses SET key_hmac = ?, key_enc = ?, updated_at = ? WHERE id = ? AND key_enc = ?").bind(hmac, enc, app.now, lic.id, lic.key_enc).run();
  return r.meta.changes ? fresh : null;
}

const productName = (app, id) => app.cfg.products[id]?.name ?? id;

function wrap(title, lines, htmlParts) {
  const text = lines.join("\n");
  const html = `<!doctype html><html><body style="font-family:system-ui,sans-serif;line-height:1.5"><h2>${escapeHtml(title)}</h2>${htmlParts.join("")}</body></html>`;
  return { text, html };
}

/** Builds a delivery's message, or null when there's nothing to send. */
export async function buildMessage(app, d) {
  if (d.kind === "resend") {
    const lics = (await app.db.prepare("SELECT * FROM licenses WHERE email = ? AND status != 'revoked' ORDER BY created_at LIMIT 20").bind(d.email).all()).results;
    if (!lics.length) return null;
    const lines = ["You (or someone using your address) asked for your licence keys.", ""];
    const html = ["<p>You (or someone using your address) asked for your licence keys.</p><ul>"];
    for (const l of lics) {
      const key = await keyFor(app, l);
      const label = `${productName(app, l.product_id)} (${l.edition})${l.status === "expired" ? " - expired" : ""}`;
      lines.push(`${label}: ${key ?? "(couldn't be recovered; reply to the seller)"}`);
      html.push(`<li>${escapeHtml(label)}: <code>${escapeHtml(key ?? "(couldn't be recovered; reply to the seller)")}</code></li>`);
    }
    lines.push("", "If you didn't ask for this, you can ignore this email.");
    html.push("</ul><p>If you didn't ask for this, you can ignore this email.</p>");
    return { to: d.email, subject: "Your keys (requested)", ...wrap("Your keys", lines, html) };
  }
  const lic = await app.db.prepare("SELECT * FROM licenses WHERE id = ?").bind(d.license_id).first();
  if (!lic) return null;
  const name = productName(app, lic.product_id);
  if (d.kind === "refund_notice") {
    const lines = [`Your licence for ${name} has been ended after a refund or chargeback.`, "", "If you think this is a mistake, reply to the seller."];
    return { to: d.email, subject: `Licence refunded: ${name}`, ...wrap("Licence refunded", lines, [`<p>${escapeHtml(lines[0])}</p><p>${escapeHtml(lines[2])}</p>`]) };
  }
  if (lic.status === "revoked") return null;
  const key = await keyFor(app, lic);
  if (!key) return null;
  const lines = [`Thanks for buying ${name} (${lic.edition}).`, "", "Your licence key:", "", key, "", "Paste it into the app to activate it. Keep this email; you can also ask for it again from the seller's site."];
  return {
    to: d.email,
    subject: `Your licence key for ${name}`,
    ...wrap(`Your licence key for ${name}`, lines, [
      `<p>${escapeHtml(lines[0])}</p><p>Your licence key:</p><p><code style="font-size:1.2em">${escapeHtml(key)}</code></p><p>${escapeHtml(lines[6])}</p>`,
    ]),
  };
}

/**
 * Claims and sends one delivery. Returns the new status, or null if it wasn't
 * claimable (already sent, being sent, not due) or nothing could be done.
 */
export async function sendDelivery(app, id) {
  const sender = getSender(app.env);
  if (!sender) return null; // email isn't set up: the row waits as it is
  // claim (1) + build (1-2 reads, +1 per re-issued key) + send (1) + record (1)
  if (left(app.budget) < 5) return null;
  const claim = await app.db
    .prepare(
      "UPDATE deliveries SET status = 'sending', attempts = attempts + 1, claimed_at = ? WHERE id = ? AND ((status IN ('pending', 'retry') AND next_at <= ?) OR status = 'retry_requested')",
    )
    .bind(app.now, id, app.now)
    .run();
  if (!claim.meta.changes) return null;
  const d = await app.db.prepare("SELECT * FROM deliveries WHERE id = ?").bind(id).first();
  let msg;
  try {
    msg = await buildMessage(app, d);
  } catch (err) {
    return record(app, d, { status: "retry", error: `build: ${err instanceof Error ? err.message : String(err)}` });
  }
  if (!msg) return record(app, d, { status: "skipped" });
  if (!spend(app.budget, 1)) return record(app, d, { status: "retry", error: "budget", noCount: true });
  const result = await sender.send(msg, { idempotencyKey: `lic-${d.license_id ?? "resend"}-${d.kind}-${d.id}` });
  return record(app, d, result);
}

async function record(app, d, result) {
  let status;
  let nextAt = d.next_at;
  let error = result.error ? redactAddresses(result.error).slice(0, 300) : null;
  switch (result.status) {
    case "sent":
      status = "sent";
      bump("emails_sent", 1, app.now);
      break;
    case "skipped":
      status = "failed";
      error = "nothing to send (licence revoked, missing, or no key)";
      break;
    case "unknown":
    case "conflict":
      status = "unknown";
      break;
    case "rejected":
      status = "failed";
      break;
    default: {
      // retry | throttled | config | budget: try again later, up to 5 retries
      const attempts = d.attempts; // already counts this one
      if (attempts >= MAX_ATTEMPTS) status = "failed";
      else {
        status = "retry";
        nextAt = app.now + RETRY_MINUTES[Math.min(attempts - 1, RETRY_MINUTES.length - 1)] * 60_000;
      }
    }
  }
  await app.db
    .prepare("UPDATE deliveries SET status = ?, next_at = ?, last_error = ?, sent_at = ? WHERE id = ? AND status = 'sending'")
    .bind(status, nextAt, error, status === "sent" ? app.now : null, d.id)
    .run();
  return status;
}

/** Sends up to `limit` due retries (the lazy sweep). Rows stuck in 'sending' become 'unknown'. */
export async function sendDue(app, limit = 5) {
  if (!getSender(app.env)) return 0;
  await app.db
    .prepare("UPDATE deliveries SET status = 'unknown', last_error = 'interrupted while sending' WHERE status = 'sending' AND claimed_at < ?")
    .bind(app.now - STALE_SENDING_MS)
    .run();
  const due = (
    await app.db
      .prepare("SELECT id FROM deliveries WHERE (status IN ('pending', 'retry') AND next_at <= ?) OR status = 'retry_requested' ORDER BY next_at LIMIT ?")
      .bind(app.now, limit)
      .all()
  ).results;
  let n = 0;
  for (const { id } of due) {
    if (left(app.budget) < 5) break;
    if (await sendDelivery(app, id)) n++;
  }
  return n;
}
