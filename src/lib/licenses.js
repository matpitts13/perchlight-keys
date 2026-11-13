// Licences: key storage, lookup, issuing and the event actions (revoke,
// expire, ...). Every write that must happen once is one D1 batch (a
// transaction) that claims first and acts only on its own claim:
//   webhook_events (provider, event_id) unique  -> one action per event
//   licenses (source, source_ref) unique         -> one licence per order
import { aesEncrypt, ct, hmacHex, randomToken, sortableId } from "./crypto.js";
import { generateKey, parseKey } from "./keyfmt.js";
import { secretSet } from "./appctx.js";
import { findMapping } from "./config.js";
import { stripeLineIds, TransientError } from "./providers.js";

export const lookupSecrets = (env) => secretSet(env, "KEY_LOOKUP_SECRET", "KEY_LOOKUP_ACTIVE");
export const encSecrets = (env) => secretSet(env, "KEY_ENC_SECRET", "KEY_ENC_ACTIVE");

/** The stored HMAC for a key body under one lookup kid. */
export async function keyHmac(kid, secret, body) {
  return `${kid}:${await hmacHex(secret, `perchlight-keys/lookup/v1\n${body}`)}`;
}

/**
 * Finds the licence for what a buyer typed. Returns the row or null; a
 * malformed key, a bad check character and an unknown key all give null.
 * One indexed read (all lookup kids at once), then a constant-time re-compare.
 */
export async function findByKey(app, input) {
  const parsed = parseKey(input);
  if (!parsed) return null;
  const { active, secrets } = lookupSecrets(app.env);
  const kids = [active, ...Object.keys(secrets).filter((k) => k !== active)].slice(0, 4);
  const cands = await Promise.all(kids.map((k) => keyHmac(k, secrets[k], parsed.body)));
  const row = await app.db
    .prepare(`SELECT * FROM licenses WHERE key_hmac IN (${cands.map(() => "?").join(",")}) LIMIT 1`)
    .bind(...cands)
    .first();
  if (!row) return null;
  for (const c of cands) if (await ct.equal(c, row.key_hmac)) return row;
  return null;
}

/** A new licence row and its plaintext key (the key goes only to the buyer). */
export async function newLicense(app, spec) {
  const { product } = spec;
  const id = sortableId("lic_", app.now);
  const key = generateKey(product.prefix);
  const body = parseKey(key).body;
  const look = lookupSecrets(app.env);
  const encs = encSecrets(app.env);
  const row = {
    id,
    product_id: product.id,
    edition: spec.edition,
    key_hmac: await keyHmac(look.active, look.secrets[look.active], body),
    key_enc: await aesEncrypt(encs.active, encs.secrets[encs.active], key, id),
    email: spec.email,
    name: spec.name ?? null,
    source: spec.source,
    source_ref: spec.sourceRef,
    expires_at: spec.expiresAt ?? null,
    device_limit: spec.deviceLimit ?? null,
    notes: spec.notes ?? null,
  };
  return { row, key };
}

const claimed = "EXISTS (SELECT 1 FROM webhook_events WHERE provider = ? AND event_id = ? AND claim = ?)";

function eventInsert(app, ev, action) {
  return app.db
    .prepare(
      "INSERT INTO webhook_events (provider, event_id, type, received_at, result, claim, body_sha256, action) VALUES (?, ?, ?, ?, 'processing', ?, ?, ?) ON CONFLICT DO NOTHING",
    )
    .bind(ev.provider, ev.eventId, ev.type, app.now, ev.claim, ev.bodyHash ?? null, action ? JSON.stringify(action) : null);
}

export function deliveryStmt(app, { id, licenseId, kind, email, condSql = "1", condArgs = [] }) {
  return app.db
    .prepare(
      `INSERT INTO deliveries (id, license_id, kind, email, status, attempts, next_at, created_at) SELECT ?, ?, ?, ?, 'pending', 0, ?, ? WHERE ${condSql}`,
    )
    .bind(id, licenseId, kind, email, app.now, app.now, ...condArgs);
}

/** An event with a fresh claim nonce. */
export function newEvent(provider, eventId, type, bodyHash) {
  return { provider, eventId: String(eventId).slice(0, 200), type: String(type).slice(0, 80), bodyHash, claim: randomToken() };
}

/**
 * Takes over an existing event row for re-processing (admin, desktop app or a
 * pending target that arrived). Returns the event or null if not claimable.
 */
export async function claimExisting(app, provider, eventId, allowed) {
  const claim = randomToken();
  const r = await app.db
    .prepare(`UPDATE webhook_events SET claim = ?, result = 'processing' WHERE provider = ? AND event_id = ? AND result IN (${allowed.map(() => "?").join(",")})`)
    .bind(claim, provider, eventId, ...allowed)
    .run();
  if (!r.meta.changes) return null;
  const row = await app.db.prepare("SELECT * FROM webhook_events WHERE provider = ? AND event_id = ?").bind(provider, eventId).first();
  return row ? { provider, eventId, type: row.type, bodyHash: row.body_sha256, claim, action: row.action } : null;
}

/**
 * Issues a licence, once. spec: { product, edition, email, name, source,
 * sourceRef, refs: [{source, ref}], expiresAt, deviceLimit, notes, sendEmail }.
 * ev (optional): the webhook event that asks for it, claimed in the same batch.
 * Returns { status: "issued" | "existing" | "duplicate_event", license, key?, deliveryId? }.
 */
export async function issue(app, spec, ev = null, action = null) {
  const { row, key } = await newLicense(app, spec);
  const deliveryId = spec.sendEmail === false ? null : sortableId("dlv_", app.now);
  const cond = ev ? claimed : "1";
  const condArgs = ev ? [ev.provider, ev.eventId, ev.claim] : [];
  const stmts = [];
  if (ev) stmts.push(eventInsert(app, ev, action));
  stmts.push(
    app.db
      .prepare(
        `INSERT INTO licenses (id, product_id, edition, key_hmac, key_enc, email, name, source, source_ref, status, expires_at, device_limit, notes, created_at, updated_at)
         SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ? WHERE ${cond} ON CONFLICT DO NOTHING`,
      )
      .bind(row.id, row.product_id, row.edition, row.key_hmac, row.key_enc, row.email, row.name, row.source, row.source_ref, row.expires_at, row.device_limit, row.notes, app.now, app.now, ...condArgs),
  );
  const mine = "EXISTS (SELECT 1 FROM licenses WHERE id = ?)";
  for (const r of spec.refs ?? []) {
    stmts.push(
      app.db.prepare(`INSERT INTO license_refs (source, ref, license_id) SELECT ?, ?, ? WHERE ${mine} ON CONFLICT DO NOTHING`).bind(r.source, String(r.ref).slice(0, 200), row.id, row.id),
    );
  }
  if (deliveryId) stmts.push(deliveryStmt(app, { id: deliveryId, licenseId: row.id, kind: "key_issued", email: row.email, condSql: mine, condArgs: [row.id] }));
  let updIdx = -1;
  if (ev) {
    updIdx = stmts.length;
    stmts.push(
      app.db
        .prepare(
          `UPDATE webhook_events SET result = CASE WHEN ${mine} THEN 'issued' ELSE 'duplicate' END,
             license_id = (SELECT id FROM licenses WHERE source = ? AND source_ref = ?), claim = NULL, error = NULL
           WHERE provider = ? AND event_id = ? AND claim = ?`,
        )
        .bind(row.id, row.source, row.source_ref, ev.provider, ev.eventId, ev.claim),
    );
  }
  const selIdx = stmts.length;
  stmts.push(app.db.prepare("SELECT * FROM licenses WHERE source = ? AND source_ref = ?").bind(row.source, row.source_ref));
  const res = await app.db.batch(stmts);
  const license = res[selIdx].results[0] ?? null;
  if (license?.id === row.id) return { status: "issued", license, key, deliveryId };
  if (ev && !res[updIdx].meta.changes) return { status: "duplicate_event", license };
  return { status: "existing", license };
}

/** Records an event that needs no licence change. Returns false for a duplicate. */
export async function recordEvent(app, ev, result, { error = null, action = null, licenseId = null } = {}) {
  const r = await app.db
    .prepare(
      `INSERT INTO webhook_events (provider, event_id, type, received_at, result, license_id, action, error, body_sha256)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`,
    )
    .bind(ev.provider, ev.eventId, ev.type, app.now, result, licenseId, action ? JSON.stringify(action) : null, error, ev.bodyHash ?? null)
    .run();
  if (r.meta.changes) return true;
  // A re-processed event: the row exists and carries our claim.
  const u = await app.db
    .prepare("UPDATE webhook_events SET result = ?, license_id = ?, error = ?, claim = NULL WHERE provider = ? AND event_id = ? AND claim = ?")
    .bind(result, licenseId, error, ev.provider, ev.eventId, ev.claim ?? "")
    .run();
  return u.meta.changes > 0;
}

/** SET clause, its arguments and an extra WHERE for each action (each changes a row only when it changes something). */
export function opSql(op, { reason = null, flag = null, expiresAt = null }, now) {
  switch (op) {
    case "revoke":
      return { set: "status = 'revoked', revoked_reason = ?, revoked_at = ?, updated_at = ?", args: [reason, now, now], where: "status != 'revoked'" };
    case "unrevoke":
      return { set: "status = 'active', revoked_reason = NULL, revoked_at = NULL, updated_at = ?", args: [now], where: "status = 'revoked'" };
    case "expire":
      return { set: "status = 'expired', updated_at = ?", args: [now], where: "status = 'active'" };
    case "reactivate":
      return { set: "status = 'active', expires_at = ?, updated_at = ?", args: [expiresAt, now], where: "status IN ('active', 'expired')" };
    case "set_expiry":
      return { set: "expires_at = ?, updated_at = ?", args: [expiresAt, now], where: "status != 'revoked'" };
    case "flag":
      return {
        set: "flags = CASE WHEN flags IS NULL OR flags = '' THEN ? WHEN instr(',' || flags || ',', ',' || ? || ',') > 0 THEN flags ELSE flags || ',' || ? END, updated_at = ?",
        args: [flag, flag, flag, now],
        where: "1",
      };
    default:
      throw new Error(`unknown op ${op}`);
  }
}

/**
 * Applies an action to the licence a provider id points at, once per event.
 * act: { refSource, ref, op: revoke|expire|reactivate|set_expiry|flag, reason, expiresAt, notify }.
 * If no licence has that id yet, the event waits as pending_target (applied
 * when the order arrives, dropped after 7 days).
 * Returns { status: "applied" | "pending_target" | "duplicate_event", licenseId }.
 */
export async function actOnLicense(app, ev, act, action) {
  const target = "(SELECT license_id FROM license_refs WHERE source = ? AND ref = ?)";
  const ref = String(act.ref).slice(0, 200);
  const q = opSql(act.op, act, app.now);
  const stmts = [
    eventInsert(app, ev, action),
    app.db
      .prepare(`UPDATE licenses SET ${q.set} WHERE id = ${target} AND ${claimed} AND (${q.where})`)
      .bind(...q.args, act.refSource, ref, ev.provider, ev.eventId, ev.claim),
  ];
  const deliveryId = act.op === "revoke" && act.notify ? sortableId("dlv_", app.now) : null;
  if (deliveryId) {
    stmts.push(
      app.db
        .prepare(
          `INSERT INTO deliveries (id, license_id, kind, email, status, attempts, next_at, created_at)
           SELECT ?, id, 'refund_notice', email, 'pending', 0, ?, ? FROM licenses WHERE id = ${target} AND revoked_at = ? AND ${claimed}`,
        )
        .bind(deliveryId, app.now, app.now, act.refSource, ref, app.now, ev.provider, ev.eventId, ev.claim),
    );
  }
  const updIdx = stmts.length;
  stmts.push(
    app.db
      .prepare(
        `UPDATE webhook_events SET result = CASE WHEN ${target} IS NOT NULL THEN 'applied' ELSE 'pending_target' END,
           license_id = ${target}, target_ref = ?, claim = NULL, error = NULL
         WHERE provider = ? AND event_id = ? AND claim = ?`,
      )
      .bind(act.refSource, ref, act.refSource, ref, ref, ev.provider, ev.eventId, ev.claim),
  );
  stmts.push(app.db.prepare("SELECT result, license_id FROM webhook_events WHERE provider = ? AND event_id = ?").bind(ev.provider, ev.eventId));
  const res = await app.db.batch(stmts);
  if (!res[updIdx].meta.changes) return { status: "duplicate_event", licenseId: null };
  const row = res[updIdx + 1].results[0];
  return { status: row.result, licenseId: row.license_id, deliveryId: deliveryId && res[2].meta.changes ? deliveryId : null };
}

/**
 * Runs an event's intent (also used to re-process it). intent:
 *   { kind: "issue", provider, ids, email, name, sourceRef, refs, expiresAt }
 *   { kind: "act", refSource, ref, op, reason, flag, expiresAt, notify }
 *   { kind: "ignore", why }
 * Returns { result, license?, deliveryId? } with result one of the
 * webhook_events results, or "duplicate_event".
 */
export async function runIntent(app, ev, intent) {
  if (intent.kind === "ignore") {
    const fresh = await recordEvent(app, ev, "ignored", { error: intent.why?.slice(0, 200) ?? null });
    return { result: fresh ? "ignored" : "duplicate_event" };
  }
  if (intent.kind === "act") {
    const r = await actOnLicense(app, ev, intent, intent);
    return { result: r.status, licenseId: r.licenseId, deliveryId: r.deliveryId };
  }
  if (!intent.email) {
    const fresh = await recordEvent(app, ev, "error", { action: intent, error: "no buyer email in the event" });
    return { result: fresh ? "error" : "duplicate_event" };
  }
  let ids = intent.ids;
  if (intent.provider === "stripe" && intent.session) {
    try {
      ids = [...(await stripeLineIds(app, intent.session)), ...ids];
    } catch (err) {
      if (err instanceof TransientError) throw err;
      const fresh = await recordEvent(app, ev, "error", { action: intent, error: String(err.message).slice(0, 200) });
      return { result: fresh ? "error" : "duplicate_event" };
    }
  }
  const m = findMapping(app.cfg, intent.provider, ids);
  if (!m) {
    const fresh = await recordEvent(app, ev, "unmapped", { action: intent, error: `no product maps ${ids.filter(Boolean).join(" / ").slice(0, 150)}` });
    return { result: fresh ? "unmapped" : "duplicate_event" };
  }
  if (m.upgrade) {
    const existing = await app.db
      .prepare("SELECT id FROM licenses WHERE product_id = ? AND email = ? AND status = 'active' ORDER BY created_at LIMIT 1")
      .bind(m.product.id, intent.email)
      .first();
    if (existing) {
      const res = await app.db.batch([
        eventInsert(app, ev, intent),
        app.db.prepare(`UPDATE licenses SET edition = ?, updated_at = ? WHERE id = ? AND ${claimed}`).bind(m.edition, app.now, existing.id, ev.provider, ev.eventId, ev.claim),
        app.db
          .prepare("UPDATE webhook_events SET result = 'applied', license_id = ?, claim = NULL WHERE provider = ? AND event_id = ? AND claim = ?")
          .bind(existing.id, ev.provider, ev.eventId, ev.claim),
      ]);
      return { result: res[2].meta.changes ? "applied" : "duplicate_event", licenseId: existing.id };
    }
  }
  const spec = {
    product: m.product,
    edition: m.edition,
    email: intent.email,
    name: intent.name,
    source: intent.provider,
    sourceRef: intent.sourceRef,
    refs: [{ source: intent.provider, ref: intent.sourceRef }, ...(intent.refs ?? []).map((ref) => ({ source: intent.provider, ref }))],
    expiresAt: intent.expiresAt ?? (m.product.duration === "perpetual" ? null : app.now + m.product.duration * 86_400_000),
  };
  const r = await issue(app, spec, ev, intent);
  if (r.status === "issued") await applyPending(app, intent.provider, [intent.sourceRef, ...(intent.refs ?? [])]);
  return { result: r.status === "issued" ? "issued" : r.status === "existing" ? "duplicate" : "duplicate_event", license: r.license, deliveryId: r.deliveryId };
}

/** Applies events that arrived before their order (at most 5 per issue). */
export async function applyPending(app, provider, refs) {
  const list = [...new Set(refs.filter(Boolean).map(String))].slice(0, 10);
  if (!list.length) return 0;
  const rows = (
    await app.db
      .prepare(`SELECT event_id FROM webhook_events WHERE provider = ? AND result = 'pending_target' AND target_ref IN (${list.map(() => "?").join(",")}) ORDER BY received_at LIMIT 5`)
      .bind(provider, ...list)
      .all()
  ).results;
  let n = 0;
  for (const { event_id } of rows) {
    const ev = await claimExisting(app, provider, event_id, ["pending_target"]);
    if (!ev) continue;
    const intent = JSON.parse(ev.action ?? "null");
    if (intent?.kind === "act") {
      await actOnLicense(app, ev, intent, intent);
      n++;
    }
  }
  return n;
}
