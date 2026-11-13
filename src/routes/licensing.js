// The public licensing API the app calls: activate, renew, deactivate,
// license (offline-only products), trial, revocations, keys.
// Errors are JSON { error, message }. invalid_key covers a malformed key, a
// bad check character, an unknown key and a key for another product alike.
import { fail, json, readJson, str } from "../lib/http.js";
import { findByKey } from "../lib/licenses.js";
import { memoryHit, ipHash } from "../lib/rate.js";
import { ownPublicKeys, publicKeys, signToken, verifyToken } from "../lib/tokens.js";
import { sortableId } from "../lib/crypto.js";
import { parseKey } from "../lib/keyfmt.js";

const DAY = 86_400_000;
const PER_MINUTE = 20;
const DEVICE_RE = /^[A-Za-z0-9_-]{16,128}$/;
const sec = (ms) => Math.floor(ms / 1000);

const invalidKey = () => fail(404, "invalid_key", "That licence key isn't valid for this product.");
const tooMany = () => fail(429, "rate_limited", "Too many requests. Try again in a minute.", { retry_after: 60 }, { "Retry-After": "60" });

function cleanLabel(v) {
  if (typeof v !== "string") return null;
  const s = v.replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, 64);
  return s || null;
}

function product(app, id) {
  return typeof id === "string" && Object.hasOwn(app.cfg.products, id) ? app.cfg.products[id] : null;
}

/** "revoked" | "expired" | null */
export function licenseBlock(lic, now) {
  if (lic.status === "revoked") return "revoked";
  if (lic.status === "expired" || (lic.expires_at != null && lic.expires_at <= now)) return "expired";
  return null;
}

function blocked(why) {
  return why === "revoked" ? fail(403, "revoked", "This licence has been revoked.") : fail(403, "expired", "This licence has expired.");
}

const features = (prod, edition) => prod.editions[edition]?.features ?? [];

/** A device-bound lease for a licence. */
export async function makeLease(app, prod, lic, device) {
  const now = app.now;
  const leaseEnd = now + prod.leaseDays * DAY;
  const exp = lic.expires_at != null ? Math.min(lic.expires_at, leaseEnd) : leaseEnd;
  const payload = {
    typ: "lease",
    lid: lic.id,
    prod: prod.id,
    ed: lic.edition,
    feat: features(prod, lic.edition),
    iat: sec(now),
    nbf: sec(now),
    exp: sec(exp),
    dev: device,
    renew: sec(now + prod.renewAfterDays * DAY),
    grace: prod.graceDays * 86_400,
  };
  return { lease: await signToken(app.env, payload), server_time: sec(now), renew_after: payload.renew, expires: payload.exp };
}

/** The offline licence file (typ "lic"). */
export async function makeLicenseFile(app, prod, lic) {
  const payload = {
    typ: "lic",
    lid: lic.id,
    prod: prod.id,
    ed: lic.edition,
    feat: features(prod, lic.edition),
    iat: sec(app.now),
    nbf: sec(lic.created_at),
    exp: lic.expires_at != null ? sec(lic.expires_at) : null,
    grace: prod.graceDays * 86_400,
  };
  return signToken(app.env, payload);
}

async function limited(app, request, extraKey) {
  const ip = await ipHash(app, request);
  const okIp = memoryHit(`ip:${ip}`, PER_MINUTE, app.now);
  const okKey = extraKey ? memoryHit(`k:${extraKey}`, PER_MINUTE, app.now) : true;
  return !(okIp && okKey);
}

async function touch(app, act) {
  if (app.now - act.last_seen_at < DAY) return;
  await app.db.prepare("UPDATE activations SET last_seen_at = ? WHERE id = ?").bind(app.now, act.id).run();
}

async function activate(app, request) {
  const input = await readJson(request);
  if (!input) return fail(400, "bad_request", "Send a JSON body of at most 8 KB.");
  const prod = product(app, input.product);
  const key = str(input.key, 80);
  const device = str(input.device, 128);
  if (!prod) return fail(400, "unknown_product", "Unknown product.");
  if (!key) return invalidKey();
  if (!device || !DEVICE_RE.test(device)) return fail(400, "bad_device", "device must be 16-128 characters of A-Z, a-z, 0-9, _ or -.");
  if (await limited(app, request, parseKey(key)?.body ?? "bad")) return tooMany();
  const lic = await findByKey(app, key);
  if (!lic || lic.product_id !== prod.id) return invalidKey();
  const why = licenseBlock(lic, app.now);
  if (why) return blocked(why);
  if (prod.activation === "none") return fail(400, "offline_only", "This product uses licence files only: call /v1/license.");

  const findActive = () =>
    app.db.prepare("SELECT id, last_seen_at FROM activations WHERE license_id = ? AND device_hash = ? AND deactivated_at IS NULL AND kind = 'full'").bind(lic.id, device).first();
  const existing = await findActive();
  if (existing) {
    await touch(app, existing);
    return json(await makeLease(app, prod, lic, device));
  }
  const limit = lic.device_limit ?? prod.deviceLimit;
  // Atomic: the count and the insert are one statement, so two devices racing
  // for the last slot can't both get it.
  const ins = await app.db
    .prepare(
      `INSERT INTO activations (id, license_id, product_id, device_hash, label, kind, first_at, last_seen_at)
       SELECT ?, ?, ?, ?, ?, 'full', ?, ? WHERE (SELECT COUNT(*) FROM activations WHERE license_id = ? AND deactivated_at IS NULL AND kind = 'full') < ?
       ON CONFLICT DO NOTHING`,
    )
    .bind(sortableId("act_", app.now), lic.id, prod.id, device, cleanLabel(input.label), app.now, app.now, lic.id, limit)
    .run();
  if (!ins.meta.changes) {
    if (await findActive()) return json(await makeLease(app, prod, lic, device)); // the same device, concurrently
    const devices = (
      await app.db
        .prepare("SELECT id, label, last_seen_at FROM activations WHERE license_id = ? AND deactivated_at IS NULL AND kind = 'full' ORDER BY first_at")
        .bind(lic.id)
        .all()
    ).results.map((d) => ({ id: d.id, label: d.label, last_seen: new Date(d.last_seen_at).toISOString() }));
    return fail(409, "device_limit", `This key is already active on ${limit} device(s). Free one to use it here.`, { limit, devices });
  }
  return json(await makeLease(app, prod, lic, device));
}

async function renew(app, request) {
  const input = await readJson(request);
  if (!input) return fail(400, "bad_request", "Send a JSON body of at most 8 KB.");
  let lic;
  let device;
  if (typeof input.lease === "string") {
    const p = await verifyToken(input.lease, await ownPublicKeys(app.env), "lease");
    if (!p || typeof p.lid !== "string" || typeof p.dev !== "string") return fail(401, "invalid_lease", "That lease isn't valid.");
    if (await limited(app, request, p.lid)) return tooMany();
    lic = await app.db.prepare("SELECT * FROM licenses WHERE id = ?").bind(p.lid).first();
    if (!lic || lic.product_id !== p.prod) return fail(401, "invalid_lease", "That lease isn't valid.");
    device = p.dev;
  } else {
    const key = str(input.key, 80);
    device = str(input.device, 128);
    if (!key) return invalidKey();
    if (!device || !DEVICE_RE.test(device)) return fail(400, "bad_device", "device must be 16-128 characters of A-Z, a-z, 0-9, _ or -.");
    if (await limited(app, request, parseKey(key)?.body ?? "bad")) return tooMany();
    lic = await findByKey(app, key);
    if (!lic) return invalidKey();
  }
  const prod = product(app, lic.product_id);
  if (!prod) return invalidKey();
  const why = licenseBlock(lic, app.now);
  if (why) return blocked(why);
  const act = await app.db
    .prepare("SELECT id, last_seen_at FROM activations WHERE license_id = ? AND device_hash = ? AND deactivated_at IS NULL AND kind = 'full'")
    .bind(lic.id, device)
    .first();
  if (!act) return fail(403, "not_activated", "This device isn't activated (it may have been freed). Activate it again.");
  await touch(app, act);
  return json(await makeLease(app, prod, lic, device));
}

async function deactivate(app, request) {
  const input = await readJson(request);
  if (!input) return fail(400, "bad_request", "Send a JSON body of at most 8 KB.");
  const key = str(input.key, 80);
  const device = str(input.device, 128);
  const activation = str(input.activation, 64);
  if (!key) return invalidKey();
  if (!device && !activation) return fail(400, "bad_request", "Send device (this device's id) or activation (an id from the device list).");
  if (await limited(app, request, parseKey(key)?.body ?? "bad")) return tooMany();
  const lic = await findByKey(app, key);
  if (!lic) return invalidKey();
  const r = await app.db
    .prepare("UPDATE activations SET deactivated_at = ? WHERE license_id = ? AND kind = 'full' AND deactivated_at IS NULL AND (device_hash = ? OR id = ?)")
    .bind(app.now, lic.id, device ?? "", activation ?? "")
    .run();
  if (r.meta.changes) await countChurn(app, lic.id);
  return json({ ok: true, freed: r.meta.changes > 0 });
}

/** Deactivate churn: more than 10 in a calendar month flags the licence (no automatic action). */
export async function countChurn(app, licenseId) {
  const month = new Date(app.now).toISOString().slice(0, 7);
  await app.db
    .prepare(
      `UPDATE licenses SET
         churn = CASE WHEN churn_month = ?1 THEN churn + 1 ELSE 1 END,
         churn_month = ?1,
         flags = CASE WHEN (CASE WHEN churn_month = ?1 THEN churn + 1 ELSE 1 END) > 10 AND instr(',' || COALESCE(flags, '') || ',', ',churn,') = 0
                      THEN CASE WHEN flags IS NULL OR flags = '' THEN 'churn' ELSE flags || ',churn' END ELSE flags END
       WHERE id = ?2`,
    )
    .bind(month, licenseId)
    .run();
}

async function licenseFile(app, request) {
  const input = await readJson(request);
  if (!input) return fail(400, "bad_request", "Send a JSON body of at most 8 KB.");
  const key = str(input.key, 80);
  if (!key) return invalidKey();
  if (await limited(app, request, parseKey(key)?.body ?? "bad")) return tooMany();
  const lic = await findByKey(app, key);
  const prod = lic && product(app, lic.product_id);
  if (!lic || !prod || (input.product !== undefined && input.product !== prod.id)) return invalidKey();
  const why = licenseBlock(lic, app.now);
  if (why) return blocked(why);
  if (prod.activation !== "none") return fail(400, "activation_required", "This product uses device activation: call /v1/activate.");
  return json({ license: await makeLicenseFile(app, prod, lic), server_time: sec(app.now) });
}

async function trial(app, request) {
  const input = await readJson(request);
  if (!input) return fail(400, "bad_request", "Send a JSON body of at most 8 KB.");
  const prod = product(app, input.product);
  const device = str(input.device, 128);
  if (!prod) return fail(400, "unknown_product", "Unknown product.");
  if (!prod.trialDays) return fail(404, "no_trial", "This product has no trial.");
  if (!device || !DEVICE_RE.test(device)) return fail(400, "bad_device", "device must be 16-128 characters of A-Z, a-z, 0-9, _ or -.");
  if (await limited(app, request, `trial:${prod.id}:${device}`)) return tooMany();
  const [, sel] = await app.db.batch([
    app.db
      .prepare(
        `INSERT INTO activations (id, license_id, product_id, device_hash, label, kind, first_at, last_seen_at, expires_at)
         VALUES (?, NULL, ?, ?, NULL, 'trial', ?, ?, ?) ON CONFLICT DO NOTHING`,
      )
      .bind(sortableId("trl_", app.now), prod.id, device, app.now, app.now, app.now + prod.trialDays * DAY),
    app.db.prepare("SELECT first_at, expires_at FROM activations WHERE product_id = ? AND device_hash = ? AND kind = 'trial'").bind(prod.id, device),
  ]);
  const t = sel.results[0];
  if (!t || t.expires_at <= app.now) return fail(403, "trial_used", "The trial on this device has ended.");
  const payload = {
    typ: "trial",
    lid: null,
    prod: prod.id,
    ed: prod.trialEdition,
    feat: features(prod, prod.trialEdition),
    iat: sec(app.now),
    nbf: sec(t.first_at),
    exp: sec(t.expires_at),
    dev: device,
    renew: null,
    grace: 0,
  };
  return json({ lease: await signToken(app.env, payload), server_time: sec(app.now), expires: payload.exp });
}

export function revokedKids(env) {
  try {
    const v = JSON.parse(env.REVOKED_KIDS || "[]");
    return Array.isArray(v) ? v.filter((k) => typeof k === "string").slice(0, 50) : [];
  } catch {
    return [];
  }
}

const REVS_LIMIT = 1000;
async function revocations(app, request, url) {
  const prod = product(app, url.searchParams.get("product"));
  if (!prod) return fail(400, "unknown_product", "Unknown product.");
  const since = Math.max(0, Math.min(Number.parseInt(url.searchParams.get("since") ?? "0", 10) || 0, 1e11));
  if (await limited(app, request)) return tooMany();
  const rows = (
    await app.db
      .prepare("SELECT id, revoked_at FROM licenses WHERE product_id = ? AND status = 'revoked' AND revoked_at >= ? ORDER BY revoked_at, id LIMIT ?")
      .bind(prod.id, since * 1000, REVS_LIMIT + 1)
      .all()
  ).results;
  const more = rows.length > REVS_LIMIT;
  const list = rows.slice(0, REVS_LIMIT);
  const payload = {
    typ: "revs",
    prod: prod.id,
    iat: sec(app.now),
    since,
    lids: list.map((r) => r.id),
    kids_revoked: revokedKids(app.env),
    more,
    next_since: more ? sec(list[list.length - 1].revoked_at) : null,
  };
  return json({ revocations: await signToken(app.env, payload) }, 200, { "Cache-Control": "public, max-age=3600" });
}

async function keys(app) {
  const pk = await publicKeys(app.env);
  return json({ active: pk.active, keys: pk.keys, kids_revoked: revokedKids(app.env) }, 200, { "Cache-Control": "public, max-age=300" });
}

export async function handleLicensing(request, app, path, url) {
  const route = `${request.method} ${path}`;
  switch (route) {
    case "POST /v1/activate":
      return activate(app, request);
    case "POST /v1/renew":
      return renew(app, request);
    case "POST /v1/deactivate":
      return deactivate(app, request);
    case "POST /v1/license":
      return licenseFile(app, request);
    case "POST /v1/trial":
      return trial(app, request);
    case "GET /v1/revocations":
      return revocations(app, request, url);
    case "GET /v1/keys":
      return keys(app);
    default:
      return null;
  }
}
