import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { makeWorker } from "../src/app.js";
import { clock } from "../src/lib/appctx.js";
import { net } from "../src/lib/net.js";
import { resetRate } from "../src/lib/rate.js";
import { resetFootprint } from "../src/lib/footprint.js";
import { resetSweepMemory } from "../src/lib/sweep.js";
import { hmacHex } from "../src/lib/crypto.js";
import { TEST_CONFIG } from "./config.js";

export const ORIGIN = "https://keys.test";
export const TOKEN = "test-admin-token-0123456789";
export const MIN = 60_000;
export const HOUR = 3_600_000;
export const DAY = 86_400_000;
// Monday 2 March 2026, 08:00:00 UTC.
export const NOW = Date.UTC(2026, 2, 2, 8, 0);

export const worker = makeWorker(TEST_CONFIG);
const realFetch = net.fetch;

export function setNow(ms) {
  clock.now = () => ms;
}

/**
 * Fake network. routes: url prefix -> { status, body, headers } | "down" | (url, init) => same | Response.
 * The longest matching prefix wins. Every call is recorded. Resend answers 200 by default.
 */
export function fakeNet(routes = {}) {
  const calls = [];
  const defaults = { "https://api.resend.com/": { status: 200, body: '{"id":"em_test"}' } };
  const pick = (table, url) => Object.keys(table).filter((k) => url.startsWith(k)).sort((a, b) => b.length - a.length)[0];
  net.fetch = async (input, init = {}) => {
    const url = typeof input === "string" ? input : input.url;
    const headers = new Headers(init.headers ?? {});
    const body = typeof init.body === "string" ? init.body : null;
    calls.push({ url, method: init.method ?? "GET", headers, body, json: body ? JSON.parse(body) : null });
    const own = pick(routes, url);
    const def = own === undefined ? pick(defaults, url) : undefined;
    let r = own !== undefined ? routes[own] : def !== undefined ? defaults[def] : undefined;
    if (typeof r === "function") r = await r(url, init, calls.length);
    if (r === undefined) throw new Error(`unexpected fetch in test: ${url}`);
    if (r instanceof Response) return r;
    if (r === "down") throw new TypeError("Network connection lost.");
    return new Response(r.status === 204 ? null : typeof r.body === "object" ? JSON.stringify(r.body) : (r.body ?? ""), { status: r.status ?? 200, headers: r.headers ?? {} });
  };
  return calls;
}

export function restoreNet() {
  net.fetch = realFetch;
}

export const emails = (calls) => calls.filter((c) => c.url === "https://api.resend.com/emails");

export async function call(path, init = {}, envOverrides = {}, ip = "203.0.113.7") {
  const ctx = createExecutionContext();
  const e = { ...env, ...envOverrides };
  const headers = new Headers(init.headers ?? {});
  if (!headers.has("CF-Connecting-IP")) headers.set("CF-Connecting-IP", ip);
  const res = await worker.fetch(new Request(`${ORIGIN}${path}`, { ...init, headers }), e, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

async function parse(res) {
  const t = await res.text();
  try {
    return JSON.parse(t);
  } catch {
    return t;
  }
}

/** POST JSON to a public route. */
export async function post(path, body, envOverrides = {}, ip) {
  const res = await call(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }, envOverrides, ip);
  return { status: res.status, data: await parse(res), res };
}

export async function get(path, envOverrides = {}) {
  const res = await call(path, {}, envOverrides);
  return { status: res.status, data: await parse(res), res };
}

export async function api(method, path, body, envOverrides = {}, token = TOKEN) {
  const headers = { Authorization: `Bearer ${token}` };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await call(`/api/${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }, envOverrides);
  return { status: res.status, data: await parse(res), res };
}

export async function rows(sql, ...params) {
  return (await env.DB.prepare(sql).bind(...params).all()).results;
}

const TABLES = ["products", "licenses", "license_refs", "activations", "webhook_events", "deliveries", "rate", "footprint"];
export async function resetAll() {
  restoreNet();
  resetRate();
  resetFootprint();
  resetSweepMemory();
  setNow(NOW);
  await env.DB.batch([
    ...TABLES.map((t) => env.DB.prepare(`DELETE FROM ${t}`)),
    // No sweep until a test moves the clock 5 minutes on.
    env.DB.prepare("UPDATE state SET value = ? WHERE key = 'sweep_at'").bind(String(NOW)),
  ]);
}

/** Issues a licence through the admin API; returns { key, license }. */
export async function issueKey(opts = {}) {
  const r = await api("POST", "licenses", { product: "app", email: "buyer@example.com", send_email: false, ...opts });
  if (r.status !== 201) throw new Error(`issue failed: ${r.status} ${JSON.stringify(r.data)}`);
  return r.data;
}

export const dev = (n) => `device-${String(n).padStart(4, "0")}-abcdefghijklmnop`;

// ---------------------------------------------------------------- webhook senders

export async function stripeSig(body, t = Math.floor(clock.now() / 1000), secret = env.STRIPE_WEBHOOK_SECRET) {
  return `t=${t},v1=${await hmacHex(secret, `${t}.${body}`)}`;
}

export async function stripeSend(event, { t, sig, raw } = {}, envOverrides = {}) {
  const body = raw ?? JSON.stringify(event);
  const res = await call("/v1/webhooks/stripe", { method: "POST", headers: { "Content-Type": "application/json", "Stripe-Signature": sig ?? (await stripeSig(body, t)) }, body }, envOverrides);
  return { status: res.status, data: await parse(res) };
}

export async function lemonSend(payload, { sig, raw } = {}) {
  const body = raw ?? JSON.stringify(payload);
  const res = await call("/v1/webhooks/lemonsqueezy", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Event-Name": payload?.meta?.event_name ?? "", "X-Signature": sig ?? (await hmacHex(env.LEMONSQUEEZY_WEBHOOK_SECRET, body)) },
    body,
  });
  return { status: res.status, data: await parse(res) };
}

export function checkoutEvent(id, { session = "cs_test_1", status = "paid", email = "buyer@example.com", link = null, meta = null, pi = "pi_1", sub = null, type = "checkout.session.completed" } = {}) {
  return {
    id,
    type,
    data: {
      object: {
        id: session,
        object: "checkout.session",
        payment_status: status,
        payment_link: link,
        metadata: meta ? { perchlight: meta } : {},
        customer_details: { email, name: "Buyer Person" },
        payment_intent: pi,
        subscription: sub,
      },
    },
  };
}

export function lemonOrder(id, { event = "order_created", status = "paid", variant = 111, email = "buyer@example.com", updated = "2026-03-02T08:00:00.000000Z", refunded = false } = {}) {
  return {
    meta: { event_name: event, test_mode: true },
    data: {
      type: "orders",
      id: String(id),
      attributes: { status, user_email: email, user_name: "Buyer", refunded, updated_at: updated, created_at: "2026-03-02T07:00:00.000000Z", first_order_item: { variant_id: variant, product_id: 5 } },
    },
  };
}
