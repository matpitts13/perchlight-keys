// Regressions for the v0.1 review's MEDIUM findings (and two LOWs).
import { env } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import { resetAll, rows, fakeNet, api, call, post, issueKey, dev, setNow, stripeSend, lemonSend, lemonOrder, checkoutEvent, NOW, MIN, DAY } from "./helpers.js";
import { hmacHex } from "../src/lib/crypto.js";

beforeEach(resetAll);

describe("M1: a re-process that fails never strands the event in 'processing'", () => {
  it("admin re-process hitting an upstream 5xx: 503, and the event is back to 'error' (re-processable)", async () => {
    fakeNet({ "https://api.stripe.com/": { status: 502 } });
    await stripeSend(checkoutEvent("evt_m1", { session: "cs_m1" })); // no secret key: unmapped
    expect((await rows("SELECT result FROM webhook_events"))[0].result).toBe("unmapped");
    const r = await api("POST", "events/stripe/evt_m1/reprocess", {}, { STRIPE_SECRET_KEY: "rk_test" });
    expect(r.status).toBe(503);
    const ev = (await rows("SELECT result, claim FROM webhook_events"))[0];
    expect(ev).toEqual({ result: "error", claim: null });
    fakeNet({ "https://api.stripe.com/": { body: { data: [{ price: { id: "price_std", product: "p" } }] } } });
    expect((await api("POST", "events/stripe/evt_m1/reprocess", {}, { STRIPE_SECRET_KEY: "rk_test" })).data.result).toBe("issued");
  });

  it("the sweep releases a claim left in 'processing' by an evicted isolate after 10 minutes", async () => {
    await env.DB.prepare(
      "INSERT INTO webhook_events (provider, event_id, type, received_at, result, claim, claimed_at) VALUES ('stripe', 'evt_stuck', 't', ?, 'processing', 'x', ?)",
    )
      .bind(NOW, NOW)
      .run();
    setNow(NOW + 11 * MIN);
    await call("/");
    expect((await rows("SELECT result, claim FROM webhook_events"))[0]).toEqual({ result: "error", claim: null });
  });

  it("a broken pending event doesn't fail the order's webhook; it goes back to pending_target", async () => {
    fakeNet();
    await stripeSend({ id: "evt_pend", type: "charge.refunded", data: { object: { payment_intent: "pi_x", amount: 1, amount_refunded: 1, refunded: true } } });
    await env.DB.prepare("UPDATE webhook_events SET action = '{not json'").run();
    const r = await stripeSend(checkoutEvent("evt_order", { meta: "price_std", pi: "pi_x", session: "cs_x" }));
    expect(r).toEqual({ status: 200, data: { ok: true, result: "issued" } });
    expect((await rows("SELECT result FROM webhook_events WHERE event_id = 'evt_pend'"))[0].result).toBe("pending_target");
  });
});

describe("M2: extending a perpetual licence by days leaves it perpetual", () => {
  it("API and desktop Extend 30", async () => {
    const { license } = await issueKey();
    const r = await api("POST", `licenses/${license.id}/extend`, { days: 30 });
    expect(r.data).toMatchObject({ ok: true, changed: false, expires_at: null });
    await env.DB.prepare("UPDATE licenses SET action_requested = 'extend_30'").run();
    setNow(NOW + 6 * MIN);
    await call("/");
    expect((await rows("SELECT expires_at FROM licenses"))[0].expires_at).toBeNull();
  });
});

describe("M3: a reactivation without a new end date never makes a subscription perpetual", () => {
  it("Stripe subscription.updated with no period end keeps the expiry", async () => {
    fakeNet();
    await stripeSend(checkoutEvent("evt_s", { meta: "price_sub", session: "cs_s", pi: null, sub: "sub_9" }));
    const before = (await rows("SELECT expires_at FROM licenses"))[0].expires_at;
    expect(before).toBe(NOW + 35 * DAY);
    await stripeSend({ id: "evt_u", type: "customer.subscription.updated", data: { object: { id: "sub_9", status: "active" } } });
    expect((await rows("SELECT expires_at FROM licenses"))[0].expires_at).toBe(before);
  });

  it("Lemon Squeezy subscription_updated (a renewal) moves the expiry to renews_at; resume without a date keeps it", async () => {
    fakeNet();
    await lemonSend(lemonOrder(4001, { variant: 333 }));
    const sub = (name, attrs) => ({ meta: { event_name: name }, data: { type: "subscriptions", id: "s9", attributes: { order_id: 4001, ...attrs } } });
    await lemonSend(sub("subscription_updated", { status: "active", renews_at: "2026-04-15T00:00:00Z", updated_at: "1" }));
    expect((await rows("SELECT expires_at FROM licenses"))[0].expires_at).toBe(Date.parse("2026-04-15T00:00:00Z"));
    await lemonSend(sub("subscription_resumed", { updated_at: "2" }));
    expect((await rows("SELECT expires_at FROM licenses"))[0].expires_at).toBe(Date.parse("2026-04-15T00:00:00Z"));
  });
});

describe("M4: metric names can't be grown from request paths", () => {
  it("random paths count as 'other'", async () => {
    for (let i = 0; i < 60; i++) await call(`/v1/rnd${i}abc`);
    await call("/v1/webhooks/zzz", { method: "POST" });
    const fp = await api("GET", "footprint");
    const day = Object.values(fp.data.days)[0];
    expect(Object.keys(day).filter((k) => k.startsWith("req_")).sort()).toEqual(["req_admin", "req_other"]);
    expect(day.req_other).toBe(61);
  });
});

describe("M5: public routes can't spend the D1 write quota", () => {
  it("resend: a flood of random addresses from one IP writes rate rows for 10 requests only", async () => {
    fakeNet();
    for (let i = 0; i < 40; i++) await post("/v1/resend", { email: `r${i}@example.com` }, {}, "198.51.100.77");
    const n = (await rows("SELECT COUNT(*) AS n FROM rate"))[0].n;
    expect(n).toBeLessThanOrEqual(10 * 3);
  });

  it("trial: at most 10 new trials an hour per IP", async () => {
    let last;
    for (let i = 0; i < 11; i++) last = await post("/v1/trial", { product: "app", device: dev(500 + i) }, {}, "198.51.100.88");
    expect(last.status).toBe(429);
    expect((await rows("SELECT COUNT(*) AS n FROM activations WHERE kind = 'trial'"))[0].n).toBe(10);
  });
});

describe("M6: sweep queries use indexes", () => {
  it("free-requested, old events and stuck claims are index lookups, not table scans", async () => {
    const plan = async (sql, ...b) => JSON.stringify(await rows(`EXPLAIN QUERY PLAN ${sql}`, ...b));
    expect(await plan("SELECT id FROM activations WHERE free_requested = 1")).toContain("activations_free");
    expect(await plan("SELECT rowid FROM webhook_events WHERE received_at < ? AND result != 'pending_target' LIMIT 200", 1)).toContain("webhook_events_received");
    expect(await plan("SELECT rowid FROM webhook_events WHERE result = 'processing' AND claimed_at < ?", 1)).toMatch(/webhook_events_processing|webhook_events_result/);
  });
});

describe("LOW fixes", () => {
  it("Lemon Squeezy with the event name only in the header doesn't throw", async () => {
    fakeNet();
    const body = JSON.stringify({ data: { id: "1", attributes: {} } });
    const res = await call("/v1/webhooks/lemonsqueezy", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Event-Name": "license_key_created", "X-Signature": await hmacHex(env.LEMONSQUEEZY_WEBHOOK_SECRET, body) },
      body,
    });
    expect(res.status).toBe(200);
  });
});
