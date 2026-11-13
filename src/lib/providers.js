// Outbound calls to the stores' APIs (each one subrequest, through net.fetch
// so tests can stub them). A network error or a 5xx is "try later"
// (TransientError: webhooks answer 503 so the store retries); a 4xx is a
// definite answer and is never retried in a loop.
import { net } from "./net.js";
import { must } from "./budget.js";

const TIMEOUT_MS = 10_000;

export class TransientError extends Error {
  constructor(message) {
    super(message);
    this.name = "TransientError";
  }
}

async function getJson(app, url, headers) {
  must(app.budget);
  let res;
  try {
    res = await net.fetch(url, { headers: { Accept: "application/json", ...headers }, signal: AbortSignal.timeout(TIMEOUT_MS) });
  } catch (err) {
    throw new TransientError(`${new URL(url).host} unreachable: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (res.status >= 500 || res.status === 429) throw new TransientError(`${new URL(url).host} ${res.status}`);
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  return { status: res.status, ok: res.ok, data };
}

/**
 * Stripe: the price and product ids of a Checkout Session's line items
 * (needs STRIPE_SECRET_KEY; a restricted key with Checkout Sessions read is
 * enough). Returns [] without a key.
 */
export async function stripeLineIds(app, sessionId) {
  if (!app.env.STRIPE_SECRET_KEY || !/^cs_[A-Za-z0-9_]{1,200}$/.test(sessionId)) return [];
  const r = await getJson(app, `https://api.stripe.com/v1/checkout/sessions/${sessionId}/line_items?limit=10`, { Authorization: `Bearer ${app.env.STRIPE_SECRET_KEY}` });
  if (!r.ok) throw new Error(`Stripe line items lookup: ${r.status}`);
  const ids = [];
  for (const li of r.data?.data ?? []) {
    if (li?.price?.id) ids.push(li.price.id);
    const prod = typeof li?.price?.product === "string" ? li.price.product : li?.price?.product?.id;
    if (prod) ids.push(prod);
  }
  return ids;
}

/** Gumroad: GET /v2/sales/:id. Returns the sale or null (unknown sale, or not this seller's). */
export async function gumroadSale(app, saleId) {
  const r = await getJson(app, `https://api.gumroad.com/v2/sales/${encodeURIComponent(saleId)}`, { Authorization: `Bearer ${app.env.GUMROAD_ACCESS_TOKEN}` });
  if (!r.ok || !r.data?.success || !r.data.sale) return null;
  return r.data.sale;
}

/**
 * itch.io: looks up a download key for one game (server-side API, scope
 * game:view:purchases). Returns { id, game_id, ... } or null.
 */
export async function itchDownloadKey(app, gameId, downloadKey) {
  const r = await getJson(app, `https://api.itch.io/games/${encodeURIComponent(gameId)}/download_keys?download_key=${encodeURIComponent(downloadKey)}`, {
    Authorization: `Bearer ${app.env.ITCH_API_KEY}`,
  });
  const k = r.ok ? r.data?.download_key : null;
  return k && k.id != null && String(k.game_id) === String(gameId) ? k : null;
}

/** Lemon Squeezy: one page of orders, newest first. */
export async function lemonOrders(app, page) {
  const store = app.env.LEMONSQUEEZY_STORE_ID ? `&filter[store_id]=${encodeURIComponent(app.env.LEMONSQUEEZY_STORE_ID)}` : "";
  const r = await getJson(app, `https://api.lemonsqueezy.com/v1/orders?page[number]=${page}&page[size]=50${store}`, {
    Accept: "application/vnd.api+json",
    Authorization: `Bearer ${app.env.LEMONSQUEEZY_API_KEY}`,
  });
  if (!r.ok) throw new Error(`Lemon Squeezy orders: ${r.status}`);
  return { orders: r.data?.data ?? [], hasNext: !!r.data?.links?.next };
}
