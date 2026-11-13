// Payment webhooks: Stripe, Lemon Squeezy, Gumroad (docs/SDD.md, "Payment
// providers"). Order of work: verify (constant time) -> one D1 batch that
// claims the event and issues or acts -> answer 200 -> email in waitUntil.
// A duplicate answers 200 with no new rows; a D1 or upstream failure answers
// 503 so the store retries.
import { ct, hmacHex, sha256Hex, utf8 } from "../lib/crypto.js";
import { fail, json, readBody } from "../lib/http.js";
import { newEvent, runIntent } from "../lib/licenses.js";
import { sendDelivery } from "../lib/deliveries.js";
import { gumroadSale, TransientError } from "../lib/providers.js";

const MAX_BODY = 512 * 1024;
export const STRIPE_TOLERANCE_S = 300;

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** Stripe-Signature: t=<unix>,v1=<hex>[,v1=...]; HMAC-SHA256 over "<t>.<raw body>". */
export async function verifyStripe(secret, header, body, nowMs) {
  if (!header || header.length > 2048) return { ok: false, why: "header missing" };
  let t = null;
  const v1 = [];
  for (const part of header.split(",")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k === "t") t = v;
    else if (k === "v1") v1.push(v.toLowerCase());
  }
  if (!t || !/^\d{1,12}$/.test(t) || !v1.length) return { ok: false, why: "header malformed" };
  if (Math.abs(nowMs / 1000 - Number(t)) > STRIPE_TOLERANCE_S) return { ok: false, why: "timestamp outside tolerance" };
  const expected = await hmacHex(secret, concat(utf8(`${t}.`), body));
  let ok = false;
  for (const sig of v1.slice(0, 8)) if (await ct.equal(expected, sig)) ok = true;
  return ok ? { ok: true } : { ok: false, why: "signature mismatch" };
}

/** Lemon Squeezy X-Signature: hex HMAC-SHA256 of the raw body. */
export async function verifyLemon(secret, header, body) {
  if (!header || header.length > 256) return false;
  return ct.equal(await hmacHex(secret, body), header.trim().toLowerCase());
}

const asStr = (v) => (typeof v === "string" ? v : typeof v === "number" ? String(v) : null);
const ms = (iso) => {
  const t = Date.parse(iso ?? "");
  return Number.isFinite(t) ? t : null;
};

/** A refund under a provider's policy: revoke, or just flag. */
function refundAct(app, provider, ref, full) {
  const policy = app.cfg.refunds[provider] ?? "full-only";
  const revoke = policy === "any" || (policy === "full-only" && full);
  return revoke
    ? { kind: "act", refSource: provider, ref, op: "revoke", reason: full ? "refund" : "partial_refund", notify: true }
    : { kind: "act", refSource: provider, ref, op: "flag", flag: full ? "refund" : "partial_refund" };
}

/** The intent of a Stripe event. */
export function stripeIntent(app, event) {
  const o = event?.data?.object ?? {};
  switch (event.type) {
    case "checkout.session.completed":
    case "checkout.session.async_payment_succeeded": {
      if (event.type === "checkout.session.completed" && o.payment_status !== "paid" && o.payment_status !== "no_payment_required")
        return { kind: "ignore", why: `payment_status ${o.payment_status}: waiting for async_payment_succeeded` };
      if (!asStr(o.id)) return { kind: "ignore", why: "no session id" };
      return {
        kind: "issue",
        provider: "stripe",
        session: o.id,
        ids: [asStr(o.payment_link), asStr(o.metadata?.perchlight)].filter(Boolean),
        email: (o.customer_details?.email ?? o.customer_email ?? "").toLowerCase().slice(0, 254) || null,
        name: asStr(o.customer_details?.name)?.slice(0, 100) ?? null,
        sourceRef: o.id,
        refs: [asStr(o.payment_intent), asStr(o.subscription)].filter(Boolean),
      };
    }
    case "charge.refunded": {
      const pi = asStr(o.payment_intent);
      if (!pi) return { kind: "ignore", why: "charge has no payment_intent" };
      const full = o.refunded === true || (Number.isFinite(o.amount) && o.amount_refunded >= o.amount);
      return refundAct(app, "stripe", pi, full);
    }
    case "charge.dispute.created": {
      const pi = asStr(o.payment_intent);
      if (!pi) return { kind: "ignore", why: "dispute has no payment_intent" };
      return app.cfg.disputes === "revoke"
        ? { kind: "act", refSource: "stripe", ref: pi, op: "revoke", reason: "dispute", notify: false }
        : { kind: "act", refSource: "stripe", ref: pi, op: "flag", flag: "dispute" };
    }
    case "customer.subscription.deleted":
      return asStr(o.id) ? { kind: "act", refSource: "stripe", ref: o.id, op: "expire" } : { kind: "ignore", why: "no id" };
    case "customer.subscription.updated": {
      if (!asStr(o.id)) return { kind: "ignore", why: "no id" };
      const end = o.current_period_end ?? o.items?.data?.[0]?.current_period_end;
      if (["active", "trialing", "past_due"].includes(o.status))
        return { kind: "act", refSource: "stripe", ref: o.id, op: "reactivate", expiresAt: Number.isFinite(end) ? end * 1000 : null };
      if (["canceled", "unpaid", "incomplete_expired"].includes(o.status)) return { kind: "act", refSource: "stripe", ref: o.id, op: "expire" };
      return { kind: "ignore", why: `subscription status ${o.status}` };
    }
    default:
      return { kind: "ignore", why: "event type not used" };
  }
}

/** The intent of a Lemon Squeezy event. */
export function lemonIntent(app, body) {
  const name = body?.meta?.event_name;
  const d = body?.data ?? {};
  const a = d.attributes ?? {};
  const id = asStr(d.id);
  if (!id) return { kind: "ignore", why: "no data.id" };
  switch (name) {
    case "order_created": {
      if (a.status !== "paid") return { kind: "ignore", why: `order status ${a.status}` };
      const item = a.first_order_item ?? {};
      return {
        kind: "issue",
        provider: "lemonsqueezy",
        ids: [asStr(item.variant_id), asStr(item.product_id)].filter(Boolean),
        email: (asStr(a.user_email) ?? "").toLowerCase().slice(0, 254) || null,
        name: asStr(a.user_name)?.slice(0, 100) ?? null,
        sourceRef: id,
        refs: [],
      };
    }
    case "order_refunded":
      if (a.status !== "refunded" && a.status !== "partial_refund" && !a.refunded) return { kind: "ignore", why: `order status ${a.status}` };
      return refundAct(app, "lemonsqueezy", id, a.status === "refunded" || (a.refunded === true && a.status !== "partial_refund"));
    case "subscription_expired":
      return asStr(a.order_id) ? { kind: "act", refSource: "lemonsqueezy", ref: asStr(a.order_id), op: "expire" } : { kind: "ignore", why: "no order_id" };
    case "subscription_cancelled":
      return asStr(a.order_id)
        ? { kind: "act", refSource: "lemonsqueezy", ref: asStr(a.order_id), op: "set_expiry", expiresAt: ms(a.ends_at) ?? app.now }
        : { kind: "ignore", why: "no order_id" };
    case "subscription_resumed":
      return asStr(a.order_id) ? { kind: "act", refSource: "lemonsqueezy", ref: asStr(a.order_id), op: "reactivate", expiresAt: null } : { kind: "ignore", why: "no order_id" };
    default:
      return { kind: "ignore", why: "event type not used" };
  }
}

/** The intent of a Gumroad sale as the API reports it, and the state used in the event id. */
export function gumroadIntent(app, sale) {
  const id = asStr(sale.id);
  if (sale.chargebacked || sale.disputed) {
    return {
      state: "chargeback",
      intent:
        app.cfg.disputes === "revoke"
          ? { kind: "act", refSource: "gumroad", ref: id, op: "revoke", reason: "dispute", notify: false }
          : { kind: "act", refSource: "gumroad", ref: id, op: "flag", flag: "dispute" },
    };
  }
  if (sale.refunded) return { state: "refund", intent: refundAct(app, "gumroad", id, true) };
  if (sale.partially_refunded) return { state: "partial", intent: refundAct(app, "gumroad", id, false) };
  return {
    state: "sale",
    intent: {
      kind: "issue",
      provider: "gumroad",
      ids: [asStr(sale.product_id), asStr(sale.product_permalink)].filter(Boolean),
      email: (asStr(sale.email) ?? asStr(sale.purchase_email) ?? "").toLowerCase().slice(0, 254) || null,
      name: asStr(sale.full_name)?.slice(0, 100) ?? null,
      sourceRef: id,
      refs: [],
    },
  };
}

/** Runs an intent and answers; emails go out after the answer. */
export async function settle(app, ev, intent) {
  const r = await runIntent(app, ev, intent);
  if (r.deliveryId) app.waitUntil(sendDelivery(app, r.deliveryId));
  return r;
}

async function stripe(app, request) {
  const secret = app.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) return fail(404, "not_configured", "Stripe isn't set up.");
  const body = await readBody(request, MAX_BODY);
  if (!body) return fail(413, "too_large", "Body too large.");
  const v = await verifyStripe(secret, request.headers.get("Stripe-Signature"), body, app.now);
  if (!v.ok) return fail(400, "bad_signature", v.why);
  let event;
  try {
    event = JSON.parse(new TextDecoder().decode(body));
  } catch {
    return fail(400, "bad_json", "Body isn't JSON.");
  }
  if (!asStr(event?.id) || !asStr(event?.type)) return fail(400, "bad_event", "No event id or type.");
  const ev = newEvent("stripe", event.id, event.type, await sha256Hex(body));
  const r = await settle(app, ev, stripeIntent(app, event));
  return json({ ok: true, result: r.result });
}

async function lemonsqueezy(app, request) {
  const secret = app.env.LEMONSQUEEZY_WEBHOOK_SECRET;
  if (!secret) return fail(404, "not_configured", "Lemon Squeezy isn't set up.");
  const body = await readBody(request, MAX_BODY);
  if (!body) return fail(413, "too_large", "Body too large.");
  if (!(await verifyLemon(secret, request.headers.get("X-Signature"), body))) return fail(400, "bad_signature", "signature mismatch");
  let data;
  try {
    data = JSON.parse(new TextDecoder().decode(body));
  } catch {
    return fail(400, "bad_json", "Body isn't JSON.");
  }
  const name = asStr(data?.meta?.event_name) ?? asStr(request.headers.get("X-Event-Name"));
  if (!name || !asStr(data?.data?.id)) return fail(400, "bad_event", "No event name or data.id.");
  data.meta.event_name = name;
  // No delivery id or timestamp is documented: the event id is the event name,
  // the object id and its updated_at, so a replayed body is a duplicate and a
  // later change to the same object (a second refund) is a new event.
  const ev = newEvent("lemonsqueezy", `${name}:${data.data.id}:${asStr(data.data.attributes?.updated_at) ?? ""}`, name, await sha256Hex(body));
  const r = await settle(app, ev, lemonIntent(app, data));
  return json({ ok: true, result: r.result });
}

/** Looks a Gumroad sale up and acts on what the API says (also the admin re-sync). */
export async function gumroadSync(app, saleId, bodyHash = null) {
  const sale = await gumroadSale(app, saleId);
  if (!sale || String(sale.id) !== saleId) return { result: "unknown_sale" };
  if (app.env.GUMROAD_SELLER_ID && String(sale.seller_id ?? "") !== app.env.GUMROAD_SELLER_ID) return { result: "other_seller" };
  const { state, intent } = gumroadIntent(app, sale);
  const ev = newEvent("gumroad", `${saleId}:${state}`, state, bodyHash);
  return settle(app, ev, intent);
}

export const SALE_ID_RE = /^[A-Za-z0-9_=+/-]{1,80}$/;

async function gumroad(app, request, token) {
  const want = app.env.GUMROAD_PING_TOKEN;
  if (!want || want.length < 22 || !app.env.GUMROAD_ACCESS_TOKEN) return fail(404, "not_configured", "Gumroad isn't set up.");
  if (!(await ct.equal(token, want))) return fail(404, "not_found", "Not found.");
  const body = await readBody(request, 64 * 1024);
  if (!body) return fail(413, "too_large", "Body too large.");
  const text = new TextDecoder().decode(body);
  let saleId = null;
  if ((request.headers.get("Content-Type") ?? "").includes("json")) {
    try {
      saleId = asStr(JSON.parse(text)?.sale_id);
    } catch {
      saleId = null;
    }
  } else saleId = new URLSearchParams(text).get("sale_id");
  if (!saleId || !SALE_ID_RE.test(saleId)) return fail(400, "bad_ping", "No sale_id.");
  // The ping body is used only for the sale id: the API lookup is the truth,
  // so a forged or replayed ping can't issue anything.
  const r = await gumroadSync(app, saleId, await sha256Hex(body));
  return json({ ok: true, result: r.result });
}

export async function handleWebhook(request, app, path) {
  if (request.method !== "POST") return fail(405, "method_not_allowed", "POST only.");
  try {
    if (path === "/v1/webhooks/stripe") return await stripe(app, request);
    if (path === "/v1/webhooks/lemonsqueezy") return await lemonsqueezy(app, request);
    const g = /^\/v1\/webhooks\/gumroad\/([A-Za-z0-9_-]{1,128})$/.exec(path);
    if (g) return await gumroad(app, request, g[1]);
    return fail(404, "not_found", "Not found.");
  } catch (err) {
    console.error(`webhook ${path.replace(/gumroad\/.*/, "gumroad/<token>")}: ${err instanceof Error ? err.message : String(err)}`);
    return fail(503, err instanceof TransientError ? "upstream_unavailable" : "unavailable", "Try again later.", {}, { "Retry-After": "60" });
  }
}
