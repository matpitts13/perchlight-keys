// The admin API: Authorization: Bearer <ADMIN_TOKEN> (constant-time compare,
// 16+ characters; /api/* answers 503 until it's set). Keys are never in a
// list; POST /api/licenses/:id/reveal decrypts one.
import { aesDecrypt, aesEncrypt, ct, encKid } from "../lib/crypto.js";
import { fail, json, normEmail, parseJson, readJson, str } from "../lib/http.js";
import { encSecrets, issue, keyHmac, lookupSecrets, claimExisting, runIntent, newEvent, parseIntent, releaseClaim, reprocessClaimed } from "../lib/licenses.js";
import { licenseAction } from "../lib/actions.js";
import { sendDelivery, sendDue } from "../lib/deliveries.js";
import { PROVIDERS } from "../lib/config.js";
import { lemonOrders, TransientError } from "../lib/providers.js";
import { gumroadSync, lemonIntent, SALE_ID_RE } from "./webhooks.js";
import { claimSweep, runSweep } from "../lib/sweep.js";
import { flushFootprint } from "../lib/footprint.js";
import { signingConfig } from "../lib/tokens.js";
import { parseKey } from "../lib/keyfmt.js";
import { left } from "../lib/budget.js";
import { randomToken } from "../lib/crypto.js";
import { getSender } from "../lib/mail/index.js";

const DAY = 86_400_000;
const PUBLIC_COLS =
  "id, product_id, edition, email, name, source, source_ref, status, revoked_reason, revoked_at, expires_at, device_limit, flags, churn, created_at, updated_at, notes";

export async function authorized(request, env) {
  const token = env.ADMIN_TOKEN;
  if (!token || token.length < 16) return "unset";
  const h = request.headers.get("Authorization") ?? "";
  const m = /^Bearer (.+)$/.exec(h);
  return m && m[1].length <= 512 && (await ct.equal(m[1], token)) ? "ok" : "no";
}

const lim = (v, d, max) => Math.max(1, Math.min(Number.parseInt(v ?? "", 10) || d, max));

function configReport(app) {
  const problems = [...app.cfg.errors];
  const check = (fn) => {
    try {
      fn();
    } catch (err) {
      problems.push(err.message);
    }
  };
  check(() => signingConfig(app.env));
  check(() => lookupSecrets(app.env));
  check(() => encSecrets(app.env));
  return {
    problems,
    products: Object.keys(app.cfg.products),
    email: !!getSender(app.env),
    providers: {
      stripe: !!app.env.STRIPE_WEBHOOK_SECRET,
      lemonsqueezy: !!app.env.LEMONSQUEEZY_WEBHOOK_SECRET,
      gumroad: !!(app.env.GUMROAD_PING_TOKEN && app.env.GUMROAD_ACCESS_TOKEN),
      itch: !!app.env.ITCH_API_KEY,
    },
  };
}

async function createLicense(app, body) {
  const prod = typeof body.product === "string" && Object.hasOwn(app.cfg.products, body.product) ? app.cfg.products[body.product] : null;
  if (!prod) return fail(400, "unknown_product", "Unknown product.");
  const edition = body.edition ?? prod.defaultEdition;
  if (typeof edition !== "string" || !Object.hasOwn(prod.editions, edition)) return fail(400, "bad_edition", "Unknown edition.");
  const email = normEmail(body.email);
  if (!email) return fail(400, "bad_email", "A valid email is needed.");
  const source = body.source ?? "manual";
  if (!["manual", "import", ...PROVIDERS].includes(source)) return fail(400, "bad_source", "source: manual, import, stripe, lemonsqueezy, gumroad or itch.");
  const sourceRef = body.source_ref === undefined ? `m_${randomToken()}` : str(String(body.source_ref), 200);
  if (!sourceRef) return fail(400, "bad_source_ref", "source_ref: up to 200 characters.");
  let expiresAt = prod.duration === "perpetual" ? null : app.now + prod.duration * DAY;
  if (body.expires_days !== undefined) {
    if (!Number.isInteger(body.expires_days) || body.expires_days < 1 || body.expires_days > 36500) return fail(400, "bad_expiry", "expires_days: 1-36500.");
    expiresAt = app.now + body.expires_days * DAY;
  }
  if (body.perpetual === true) expiresAt = null;
  if (body.device_limit !== undefined && body.device_limit !== null && !(Number.isInteger(body.device_limit) && body.device_limit >= 1 && body.device_limit <= 1000))
    return fail(400, "bad_device_limit", "device_limit: 1-1000.");
  const r = await issue(app, {
    product: prod,
    edition,
    email,
    name: str(body.name, 100),
    source,
    sourceRef,
    refs: source === "manual" ? [] : [{ source, ref: sourceRef }],
    expiresAt,
    deviceLimit: body.device_limit ?? null,
    notes: str(body.notes, 500),
    sendEmail: body.send_email !== false,
  });
  const pub = publicView(r.license);
  if (r.status !== "issued") return json({ existing: true, license: pub });
  if (r.deliveryId) app.waitUntil(sendDelivery(app, r.deliveryId));
  return json({ existing: false, license: pub, key: r.key }, 201);
}

function publicView(l) {
  if (!l) return null;
  const { key_hmac, key_enc, action_requested, churn_month, ...rest } = l;
  void key_hmac, key_enc, action_requested, churn_month;
  return rest;
}

/** Lemon Squeezy re-sync: issues anything missing from the last N days of orders (idempotent). */
async function resyncLemon(app, body) {
  if (!app.env.LEMONSQUEEZY_API_KEY) return fail(400, "not_configured", "Set LEMONSQUEEZY_API_KEY (and LEMONSQUEEZY_STORE_ID).");
  const days = Number.isInteger(body.days) && body.days >= 1 && body.days <= 30 ? body.days : 7;
  const cutoff = app.now - days * DAY;
  const out = { checked: 0, issued: 0, existing: 0, unmapped: 0, other: 0, more: false };
  for (let page = 1; page <= 10; page++) {
    if (left(app.budget) < 6) {
      out.more = true;
      break;
    }
    const { orders, hasNext } = await lemonOrders(app, page);
    const recent = orders.filter((o) => Date.parse(o?.attributes?.created_at ?? "") >= cutoff && o?.attributes?.status === "paid" && o.id != null);
    out.checked += recent.length;
    if (recent.length) {
      const ids = recent.map((o) => String(o.id));
      const have = new Set(
        (await app.db.prepare(`SELECT source_ref FROM licenses WHERE source = 'lemonsqueezy' AND source_ref IN (${ids.map(() => "?").join(",")})`).bind(...ids).all()).results.map(
          (r) => r.source_ref,
        ),
      );
      for (const o of recent) {
        if (have.has(String(o.id))) {
          out.existing++;
          continue;
        }
        if (left(app.budget) < 4) {
          out.more = true;
          break;
        }
        const intent = lemonIntent(app, { meta: { event_name: "order_created" }, data: o });
        const r = await runIntent(app, newEvent("lemonsqueezy", `order_created:${o.id}:resync`, "resync"), intent);
        if (r.result === "issued") out.issued++;
        else if (r.result === "unmapped") out.unmapped++;
        else out.other++;
      }
    }
    const oldest = Math.min(...orders.map((o) => Date.parse(o?.attributes?.created_at ?? "") || 0));
    if (out.more || !hasNext || !orders.length || oldest < cutoff) break;
  }
  // The new licences' emails go out with the lazy sweep (5 per sweep) or POST /api/housekeeping.
  return json(out);
}

/** Re-encrypts and re-HMACs licences not on the active KEY_ENC / KEY_LOOKUP kids, in bounded batches. */
async function rekey(app, body) {
  const look = lookupSecrets(app.env);
  const encs = encSecrets(app.env);
  const limit = Number.isInteger(body.limit) && body.limit > 0 && body.limit <= 25 ? body.limit : 25;
  const rows = (
    await app.db
      .prepare("SELECT id, key_hmac, key_enc FROM licenses WHERE substr(key_hmac, 1, length(?) + 1) != ? OR substr(key_enc, 1, length(?) + 1) != ? LIMIT ?")
      .bind(look.active, `${look.active}:`, encs.active, `${encs.active}.`, limit)
      .all()
  ).results;
  const stmts = [];
  let failed = 0;
  for (const r of rows) {
    const key = await aesDecrypt(encs.secrets, r.key_enc, r.id);
    const parsed = key && parseKey(key);
    if (!parsed) {
      failed++;
      continue;
    }
    const hmac = await keyHmac(look.active, look.secrets[look.active], parsed.body);
    const enc = encKid(r.key_enc) === encs.active ? r.key_enc : await aesEncrypt(encs.active, encs.secrets[encs.active], key, r.id);
    stmts.push(app.db.prepare("UPDATE licenses SET key_hmac = ?, key_enc = ? WHERE id = ? AND key_enc = ?").bind(hmac, enc, r.id, r.key_enc));
  }
  if (stmts.length) await app.db.batch(stmts);
  return json({ updated: stmts.length, failed, more: rows.length === limit });
}

async function footprint(app) {
  await flushFootprint(app.env.DB, app.now, true);
  const since = new Date(app.now - 7 * DAY).toISOString().slice(0, 10);
  const rows = (await app.db.prepare("SELECT day, data FROM footprint WHERE day >= ? ORDER BY day DESC").bind(since).all()).results;
  const days = {};
  for (const r of rows) days[r.day] = parseJson(r.data, {});
  return json({
    days,
    limits: { worker_requests_per_day: 100_000, d1_rows_written_per_day: 100_000, d1_rows_read_per_day: 5_000_000, subrequests_per_invocation: 50 },
  });
}

export async function handleAdmin(request, app, path) {
  const auth = await authorized(request, app.env);
  if (auth === "unset") return fail(503, "admin_disabled", "Set ADMIN_TOKEN (16+ characters) to use the admin API.");
  if (auth !== "ok") return fail(401, "unauthorized", "Bearer token required.", {}, { "WWW-Authenticate": "Bearer" });
  const m = request.method;
  const body = m === "POST" || m === "PATCH" ? await readJson(request, 64 * 1024) : {};
  if (body === null) return fail(400, "bad_request", "Send a JSON object of at most 64 KB.");
  const url = new URL(request.url);
  const q = url.searchParams;
  let g;
  try {
    if (m === "GET" && path === "config") return json(configReport(app));
    if (m === "GET" && path === "footprint") return footprint(app);
    if (m === "POST" && path === "housekeeping") {
      await claimSweep(app, true);
      return json(await runSweep(app));
    }
    if (m === "GET" && path === "licenses") {
      const where = [];
      const args = [];
      const email = q.get("email");
      if (email) where.push("email = ?") && args.push(email.toLowerCase());
      if (q.get("product")) where.push("product_id = ?") && args.push(q.get("product"));
      if (q.get("status")) where.push("status = ?") && args.push(q.get("status"));
      if (q.get("before")) where.push("id < ?") && args.push(q.get("before"));
      const sql = `SELECT ${PUBLIC_COLS} FROM licenses ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY id DESC LIMIT ?`;
      const rows = (await app.db.prepare(sql).bind(...args, lim(q.get("limit"), 50, 200)).all()).results;
      return json({ licenses: rows });
    }
    if (m === "POST" && path === "licenses") return await createLicense(app, body);
    if ((g = /^licenses\/(lic_[a-z0-9]{1,40})$/.exec(path)) && m === "GET") {
      const lic = await app.db.prepare(`SELECT ${PUBLIC_COLS} FROM licenses WHERE id = ?`).bind(g[1]).first();
      if (!lic) return fail(404, "not_found", "No such licence.");
      const acts = (
        await app.db.prepare("SELECT id, label, first_at, last_seen_at, deactivated_at FROM activations WHERE license_id = ? ORDER BY first_at DESC LIMIT 100").bind(g[1]).all()
      ).results;
      return json({ license: lic, activations: acts });
    }
    if ((g = /^licenses\/(lic_[a-z0-9]{1,40})\/reveal$/.exec(path)) && m === "POST") {
      const lic = await app.db.prepare("SELECT id, key_enc FROM licenses WHERE id = ?").bind(g[1]).first();
      if (!lic) return fail(404, "not_found", "No such licence.");
      const key = await aesDecrypt(encSecrets(app.env).secrets, lic.key_enc, lic.id);
      return key ? json({ key }) : fail(409, "undecryptable", "The key can't be decrypted with the current KEY_ENC_SECRET.");
    }
    if ((g = /^licenses\/(lic_[a-z0-9]{1,40})\/(revoke|unrevoke|extend|edition|resend|free-all)$/.exec(path)) && m === "POST") {
      const op = g[2] === "free-all" ? "free_all" : g[2];
      let email;
      if (op === "resend" && body.email !== undefined) {
        email = normEmail(body.email);
        if (!email) return fail(400, "bad_email", "Not a valid email.");
      }
      const r = await licenseAction(app, g[1], op, {
        reason: body.reason,
        days: body.days,
        expiresAt: body.expires_at,
        perpetual: body.perpetual,
        edition: body.edition,
        email,
      });
      if (!r.ok) return fail(r.error === "not_found" ? 404 : 400, r.error, r.error);
      if (r.deliveryId) app.waitUntil(sendDelivery(app, r.deliveryId));
      return json(r);
    }
    if ((g = /^activations\/(act_[a-z0-9]{1,40})\/free$/.exec(path)) && m === "POST") {
      const r = await app.db.prepare("UPDATE activations SET deactivated_at = ? WHERE id = ? AND kind = 'full' AND deactivated_at IS NULL").bind(app.now, g[1]).run();
      return json({ ok: true, freed: r.meta.changes > 0 });
    }
    if (m === "GET" && path === "events") {
      const rows = q.get("result")
        ? (await app.db.prepare("SELECT provider, event_id, type, received_at, result, license_id, target_ref, error FROM webhook_events WHERE result = ? ORDER BY received_at DESC LIMIT ?").bind(q.get("result"), lim(q.get("limit"), 50, 200)).all()).results
        : (await app.db.prepare("SELECT provider, event_id, type, received_at, result, license_id, target_ref, error FROM webhook_events ORDER BY received_at DESC LIMIT ?").bind(lim(q.get("limit"), 50, 200)).all()).results;
      return json({ events: rows });
    }
    if ((g = /^events\/(stripe|lemonsqueezy|gumroad)\/(.{1,200})\/reprocess$/.exec(path)) && m === "POST") {
      const ev = await claimExisting(app, g[1], decodeURIComponent(g[2]), ["unmapped", "error", "reprocess_requested", "dropped"]);
      if (!ev) return fail(409, "not_reprocessable", "Only unmapped, error and dropped events can be re-processed.");
      if (!parseIntent(ev.action)) {
        await releaseClaim(app, ev, "error", "nothing stored to re-process");
        return fail(409, "not_reprocessable", "Nothing stored to re-process.");
      }
      const r = await reprocessClaimed(app, ev); // on a throw the event is back to 'error'
      if (r.deliveryId) app.waitUntil(sendDelivery(app, r.deliveryId));
      return json(r);
    }
    if (m === "GET" && path === "deliveries") {
      const st = q.get("status");
      const rows = (
        await app.db
          .prepare(`SELECT id, license_id, kind, status, attempts, next_at, last_error, created_at, sent_at FROM deliveries ${st ? "WHERE status = ?" : ""} ORDER BY created_at DESC LIMIT ?`)
          .bind(...(st ? [st] : []), lim(q.get("limit"), 50, 200))
          .all()
      ).results;
      return json({ deliveries: rows });
    }
    if ((g = /^deliveries\/(dlv_[a-z0-9]{1,40})\/retry$/.exec(path)) && m === "POST") {
      const r = await app.db.prepare("UPDATE deliveries SET status = 'retry_requested' WHERE id = ? AND status IN ('failed', 'unknown', 'retry')").bind(g[1]).run();
      if (!r.meta.changes) return fail(409, "not_retryable", "Only failed, unknown or waiting deliveries can be retried.");
      return json({ ok: true, status: await sendDelivery(app, g[1]) });
    }
    if (m === "POST" && path === "emails/send-due") return json({ sent: await sendDue(app, 5) });
    if (m === "POST" && path === "resync/lemonsqueezy") return await resyncLemon(app, body);
    if (m === "POST" && path === "resync/gumroad") {
      if (!app.env.GUMROAD_ACCESS_TOKEN) return fail(400, "not_configured", "Set GUMROAD_ACCESS_TOKEN.");
      const sale = str(body.sale_id, 80);
      if (!sale || !SALE_ID_RE.test(sale)) return fail(400, "bad_request", "sale_id required.");
      return json(await gumroadSync(app, sale));
    }
    if (m === "POST" && path === "rekey") return await rekey(app, body);
    return fail(404, "not_found", "No such admin route.");
  } catch (err) {
    if (err instanceof TransientError) return fail(503, "upstream_unavailable", err.message);
    throw err;
  }
}
