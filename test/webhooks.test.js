import { env } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import { resetAll, rows, fakeNet, emails, stripeSend, stripeSig, lemonSend, checkoutEvent, lemonOrder, call, api, setNow, NOW, DAY, MIN } from "./helpers.js";
import { hmacHex } from "../src/lib/crypto.js";

beforeEach(resetAll);

const brokenDb = () => {
  const boom = async () => {
    throw new Error("D1_ERROR: unavailable");
  };
  const stmt = { bind: () => stmt, first: boom, run: boom, all: boom, raw: boom };
  return { prepare: () => stmt, batch: boom, exec: boom };
};

describe("Stripe", () => {
  it("checkout.session.completed creates exactly one licence and one email; the same event again: 200, no new rows", async () => {
    const calls = fakeNet();
    const ev = checkoutEvent("evt_1", { meta: "price_std" });
    const r = await stripeSend(ev);
    expect(r).toEqual({ status: 200, data: { ok: true, result: "issued" } });
    const lics = await rows("SELECT * FROM licenses");
    expect(lics).toHaveLength(1);
    expect(lics[0]).toMatchObject({ product_id: "app", edition: "standard", email: "buyer@example.com", source: "stripe", source_ref: "cs_test_1", status: "active" });
    const sent = emails(calls);
    expect(sent).toHaveLength(1);
    expect(sent[0].json.to).toEqual(["buyer@example.com"]);
    expect(sent[0].json.subject).toBe("Your licence key for Test App");
    expect(sent[0].json.text).toMatch(/TAPP-[0-9A-Z]{5}-/);
    expect(sent[0].headers.get("Idempotency-Key")).toMatch(/^lic-lic_.*-key_issued-dlv_/);
    const again = await stripeSend(ev);
    expect(again.data.result).toBe("duplicate_event");
    expect(await rows("SELECT * FROM licenses")).toHaveLength(1);
    expect(await rows("SELECT * FROM deliveries")).toHaveLength(1);
    expect(emails(calls)).toHaveLength(1);
    const evRow = (await rows("SELECT * FROM webhook_events"))[0];
    expect(evRow).toMatchObject({ provider: "stripe", event_id: "evt_1", result: "issued", license_id: lics[0].id, claim: null });
    expect(evRow.body_sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("the same event delivered 5 times at once still gives one licence and one email", async () => {
    const calls = fakeNet();
    const ev = checkoutEvent("evt_c", { meta: "price_std" });
    const results = await Promise.all([1, 2, 3, 4, 5].map(() => stripeSend(ev)));
    expect(results.every((r) => r.status === 200)).toBe(true);
    expect(results.filter((r) => r.data.result === "issued")).toHaveLength(1);
    expect(await rows("SELECT * FROM licenses")).toHaveLength(1);
    expect(emails(calls)).toHaveLength(1);
  });

  it("a different event for the same session (async_payment_succeeded after completed) issues nothing new", async () => {
    fakeNet();
    await stripeSend(checkoutEvent("evt_a", { meta: "price_std" }));
    const r = await stripeSend(checkoutEvent("evt_b", { meta: "price_std", type: "checkout.session.async_payment_succeeded" }));
    expect(r.data.result).toBe("duplicate");
    expect(await rows("SELECT * FROM licenses")).toHaveLength(1);
    expect((await rows("SELECT result FROM webhook_events WHERE event_id = 'evt_b'"))[0].result).toBe("duplicate");
  });

  it("one byte changed: 400, nothing stored; a valid signature 6 minutes old: refused", async () => {
    fakeNet();
    const body = JSON.stringify(checkoutEvent("evt_x", { meta: "price_std" }));
    const sig = await stripeSig(body);
    const tampered = body.replace("buyer@", "buyar@");
    expect((await stripeSend(null, { raw: tampered, sig })).status).toBe(400);
    const old = Math.floor(NOW / 1000) - 6 * 60;
    const r = await stripeSend(null, { raw: body, sig: await stripeSig(body, old) });
    expect(r.status).toBe(400);
    expect(r.data.message).toBe("timestamp outside tolerance");
    expect(await rows("SELECT * FROM webhook_events")).toHaveLength(0);
    expect(await rows("SELECT * FROM licenses")).toHaveLength(0);
  });

  it("accepts any matching v1 among several and ignores other schemes", async () => {
    fakeNet();
    const body = JSON.stringify(checkoutEvent("evt_m", { meta: "price_std" }));
    const good = await stripeSig(body);
    const t = good.split(",")[0];
    const sig = `${t},v0=abc,v1=${"0".repeat(64)},${good.split(",")[1]}`;
    expect((await stripeSend(null, { raw: body, sig })).status).toBe(200);
  });

  it("unpaid (async) sessions issue nothing until async_payment_succeeded", async () => {
    fakeNet();
    expect((await stripeSend(checkoutEvent("evt_u", { meta: "price_std", status: "unpaid" }))).data.result).toBe("ignored");
    expect(await rows("SELECT * FROM licenses")).toHaveLength(0);
    const r = await stripeSend(checkoutEvent("evt_s", { meta: "price_std", status: "unpaid", type: "checkout.session.async_payment_succeeded" }));
    expect(r.data.result).toBe("issued");
  });

  it("maps by line-item price with STRIPE_SECRET_KEY (one lookup), or by payment link", async () => {
    const calls = fakeNet({ "https://api.stripe.com/v1/checkout/sessions/cs_li/line_items": { body: { data: [{ price: { id: "price_pro", product: "prod_x" } }] } } });
    const r = await stripeSend(checkoutEvent("evt_li", { session: "cs_li" }), {}, { STRIPE_SECRET_KEY: "rk_test" });
    expect(r.data.result).toBe("issued");
    expect(calls[0].headers.get("Authorization")).toBe("Bearer rk_test");
    expect((await rows("SELECT edition FROM licenses"))[0].edition).toBe("pro");
    const r2 = await stripeSend(checkoutEvent("evt_pl", { session: "cs_pl", link: "plink_std", pi: "pi_2" }));
    expect(r2.data.result).toBe("issued");
  });

  it("a line-item lookup 5xx answers 503 (Stripe retries) and stores nothing", async () => {
    fakeNet({ "https://api.stripe.com/": { status: 502 } });
    const r = await stripeSend(checkoutEvent("evt_5", { session: "cs_5" }), {}, { STRIPE_SECRET_KEY: "rk_test" });
    expect(r.status).toBe(503);
    expect(await rows("SELECT * FROM webhook_events")).toHaveLength(0);
  });

  it("unknown mapping: stored as unmapped (no licence), then re-processed after the mapping is fixed", async () => {
    fakeNet();
    const r = await stripeSend(checkoutEvent("evt_un", { meta: "price_unknown" }));
    expect(r.data.result).toBe("unmapped");
    expect(await rows("SELECT * FROM licenses")).toHaveLength(0);
    const ev = (await rows("SELECT * FROM webhook_events"))[0];
    expect(ev.result).toBe("unmapped");
    expect(JSON.parse(ev.action).email).toBe("buyer@example.com");
    // Fix the stored intent the way a corrected mapping would resolve it: re-process maps again with the current config.
    await env.DB.prepare("UPDATE webhook_events SET action = json_set(action, '$.ids', json_array('price_std'))").run();
    const re = await api("POST", "events/stripe/evt_un/reprocess", {});
    expect(re.data.result).toBe("issued");
    expect(await rows("SELECT * FROM licenses")).toHaveLength(1);
    expect((await api("POST", "events/stripe/evt_un/reprocess", {})).status).toBe(409);
  });

  it("full refund revokes and emails a refund notice; partial refund only flags", async () => {
    const calls = fakeNet();
    await stripeSend(checkoutEvent("evt_1", { meta: "price_std", pi: "pi_full" }));
    await stripeSend(checkoutEvent("evt_2", { meta: "price_std", pi: "pi_part", session: "cs_2" }));
    const partial = await stripeSend({ id: "evt_r1", type: "charge.refunded", data: { object: { id: "ch_1", payment_intent: "pi_part", amount: 1000, amount_refunded: 300, refunded: false } } });
    expect(partial.data.result).toBe("applied");
    const full = await stripeSend({ id: "evt_r2", type: "charge.refunded", data: { object: { id: "ch_2", payment_intent: "pi_full", amount: 1000, amount_refunded: 1000, refunded: true } } });
    expect(full.data.result).toBe("applied");
    const lics = await rows("SELECT source_ref, status, revoked_reason, flags FROM licenses ORDER BY source_ref");
    expect(lics[0]).toMatchObject({ source_ref: "cs_2", status: "active", flags: "partial_refund" });
    expect(lics[1]).toMatchObject({ source_ref: "cs_test_1", status: "revoked", revoked_reason: "refund" });
    const notice = emails(calls).filter((c) => c.json.subject.startsWith("Licence refunded"));
    expect(notice).toHaveLength(1);
    expect(notice[0].json.text).not.toMatch(/TAPP-/);
  });

  it("a dispute revokes; subscription deleted expires; updated renews the expiry", async () => {
    fakeNet();
    await stripeSend(checkoutEvent("evt_s1", { meta: "price_sub", session: "cs_sub", pi: null, sub: "sub_1" }));
    const end = Math.floor(NOW / 1000) + 40 * 86400;
    await stripeSend({ id: "evt_s2", type: "customer.subscription.updated", data: { object: { id: "sub_1", status: "active", items: { data: [{ current_period_end: end }] } } } });
    expect((await rows("SELECT expires_at FROM licenses"))[0].expires_at).toBe(end * 1000);
    await stripeSend({ id: "evt_s3", type: "customer.subscription.deleted", data: { object: { id: "sub_1", status: "canceled" } } });
    expect((await rows("SELECT status FROM licenses"))[0].status).toBe("expired");
    await stripeSend({ id: "evt_s4", type: "customer.subscription.updated", data: { object: { id: "sub_1", status: "active", current_period_end: end + 100 } } });
    expect((await rows("SELECT status FROM licenses"))[0].status).toBe("active");
    await stripeSend(checkoutEvent("evt_d0", { meta: "price_std", session: "cs_d", pi: "pi_d" }));
    await stripeSend({ id: "evt_d1", type: "charge.dispute.created", data: { object: { id: "dp_1", payment_intent: "pi_d" } } });
    expect((await rows("SELECT status, revoked_reason FROM licenses WHERE source_ref = 'cs_d'"))[0]).toEqual({ status: "revoked", revoked_reason: "dispute" });
  });

  it("a refund that arrives before its order waits as pending_target and is applied when the order arrives", async () => {
    fakeNet();
    const r = await stripeSend({ id: "evt_early", type: "charge.refunded", data: { object: { payment_intent: "pi_late", amount: 500, amount_refunded: 500, refunded: true } } });
    expect(r.data.result).toBe("pending_target");
    await stripeSend(checkoutEvent("evt_late", { meta: "price_std", pi: "pi_late", session: "cs_late" }));
    expect((await rows("SELECT status FROM licenses"))[0].status).toBe("revoked");
    expect((await rows("SELECT result FROM webhook_events WHERE event_id = 'evt_early'"))[0].result).toBe("applied");
  });

  it("an upgrade purchase changes the existing licence's edition instead of issuing a new one", async () => {
    fakeNet();
    await stripeSend(checkoutEvent("evt_1", { meta: "price_std" }));
    const r = await stripeSend(checkoutEvent("evt_up", { meta: "price_up", session: "cs_up", pi: "pi_up" }));
    expect(r.data.result).toBe("applied");
    const lics = await rows("SELECT edition FROM licenses");
    expect(lics).toEqual([{ edition: "pro" }]);
  });

  it("D1 unavailable: 503 so Stripe retries", async () => {
    fakeNet();
    const r = await stripeSend(checkoutEvent("evt_d", { meta: "price_std" }), {}, { DB: brokenDb() });
    expect(r.status).toBe(503);
  });

  it("not configured: 404; oversized body: 413", async () => {
    expect((await stripeSend(checkoutEvent("e", {}), {}, { STRIPE_WEBHOOK_SECRET: "" })).status).toBe(404);
    const res = await call("/v1/webhooks/stripe", { method: "POST", body: "x".repeat(600 * 1024) });
    expect(res.status).toBe(413);
  });
});

describe("Lemon Squeezy", () => {
  it("order_created issues one licence; a replayed delivery creates nothing new; a wrong X-Signature is refused", async () => {
    const calls = fakeNet();
    const order = lemonOrder(5001);
    expect((await lemonSend(order)).data.result).toBe("issued");
    expect((await lemonSend(order)).data.result).toBe("duplicate_event");
    expect(await rows("SELECT * FROM licenses")).toHaveLength(1);
    expect(emails(calls)).toHaveLength(1);
    const bad = await lemonSend(lemonOrder(5002), { sig: "0".repeat(64) });
    expect(bad.status).toBe(400);
    expect(await rows("SELECT * FROM licenses")).toHaveLength(1);
    const lic = (await rows("SELECT * FROM licenses"))[0];
    expect(lic).toMatchObject({ source: "lemonsqueezy", source_ref: "5001", edition: "standard" });
  });

  it("license_key_created is ignored; refunds revoke (full) or flag (partial); subscription events expire / set expiry / resume", async () => {
    fakeNet();
    await lemonSend(lemonOrder(6001));
    await lemonSend(lemonOrder(6002, { variant: 222 }));
    expect((await lemonSend({ meta: { event_name: "license_key_created" }, data: { id: "77", attributes: { order_id: 6001 } } })).data.result).toBe("ignored");
    expect((await lemonSend(lemonOrder(6002, { event: "order_refunded", status: "partial_refund", updated: "2026-03-03T00:00:00Z" }))).data.result).toBe("applied");
    expect((await lemonSend(lemonOrder(6001, { event: "order_refunded", status: "refunded", refunded: true, updated: "2026-03-03T00:00:00Z" }))).data.result).toBe("applied");
    const l = await rows("SELECT source_ref, status, flags FROM licenses ORDER BY source_ref");
    expect(l).toEqual([
      { source_ref: "6001", status: "revoked", flags: null },
      { source_ref: "6002", status: "active", flags: "partial_refund" },
    ]);
    await lemonSend(lemonOrder(7001, { variant: 333 }));
    const sub = (name, attrs) => ({ meta: { event_name: name }, data: { type: "subscriptions", id: "s1", attributes: { order_id: 7001, ...attrs } } });
    await lemonSend(sub("subscription_cancelled", { ends_at: "2026-04-01T00:00:00Z", updated_at: "a" }));
    expect((await rows("SELECT expires_at FROM licenses WHERE source_ref = '7001'"))[0].expires_at).toBe(Date.parse("2026-04-01T00:00:00Z"));
    await lemonSend(sub("subscription_resumed", { status: "active", renews_at: "2026-05-01T00:00:00Z", updated_at: "b" }));
    expect((await rows("SELECT expires_at, status FROM licenses WHERE source_ref = '7001'"))[0]).toEqual({ expires_at: Date.parse("2026-05-01T00:00:00Z"), status: "active" });
    await lemonSend(sub("subscription_expired", { updated_at: "c" }));
    expect((await rows("SELECT status FROM licenses WHERE source_ref = '7001'"))[0].status).toBe("expired");
  });

  it("an unpaid order issues nothing", async () => {
    fakeNet();
    expect((await lemonSend(lemonOrder(8001, { status: "pending" }))).data.result).toBe("ignored");
    expect(await rows("SELECT * FROM licenses")).toHaveLength(0);
  });

  it("admin re-sync of the last 7 days issues missing orders once, idempotently", async () => {
    const calls = fakeNet({
      "https://api.lemonsqueezy.com/v1/orders": {
        body: {
          data: [lemonOrder(9001).data, lemonOrder(9002).data, { ...lemonOrder(9003).data, attributes: { ...lemonOrder(9003).data.attributes, created_at: "2026-01-01T00:00:00Z" } }],
          links: { next: null },
        },
      },
    });
    await lemonSend(lemonOrder(9001));
    const r = await api("POST", "resync/lemonsqueezy", { days: 7 });
    expect(r.data).toMatchObject({ checked: 2, issued: 1, existing: 1 });
    expect(calls.find((c) => c.url.includes("lemonsqueezy")).headers.get("Authorization")).toBe("Bearer ls-api-key");
    const again = await api("POST", "resync/lemonsqueezy", { days: 7 });
    expect(again.data).toMatchObject({ issued: 0, existing: 2 });
    expect(await rows("SELECT * FROM licenses")).toHaveLength(2);
  });
});

describe("Gumroad", () => {
  const ping = (saleId, token = env.GUMROAD_PING_TOKEN) =>
    call(`/v1/webhooks/gumroad/${token}`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: `sale_id=${encodeURIComponent(saleId)}&email=forged%40evil.test&product_id=gprod1` });
  const sale = (over = {}) => ({ success: true, sale: { id: "S1==", seller_id: "seller-1", product_id: "gprod1", email: "real@example.com", full_name: "Real Buyer", refunded: false, ...over } });

  it("looks the sale up and issues from the API's answer, not the ping body; a repeat ping issues nothing", async () => {
    const calls = fakeNet({ "https://api.gumroad.com/v2/sales/": { body: sale() } });
    const r = await ping("S1==");
    expect(r.status).toBe(200);
    expect(calls[0].url).toBe("https://api.gumroad.com/v2/sales/S1%3D%3D");
    expect(calls[0].headers.get("Authorization")).toBe("Bearer gumroad-access-token");
    expect((await rows("SELECT email, source_ref FROM licenses"))[0]).toEqual({ email: "real@example.com", source_ref: "S1==" });
    await ping("S1==");
    expect(await rows("SELECT * FROM licenses")).toHaveLength(1);
    expect(emails(calls)).toHaveLength(1);
  });

  it("a wrong token is 404 with no lookup; another seller's sale or an unknown sale is ignored", async () => {
    const calls = fakeNet({ "https://api.gumroad.com/v2/sales/S2": { body: sale({ id: "S2", seller_id: "someone-else" }) }, "https://api.gumroad.com/v2/sales/S3": { status: 404, body: { success: false } } });
    expect((await ping("S1==", "wrong-token-wrong-token-wrong")).status).toBe(404);
    expect(calls).toHaveLength(0);
    expect(await (await ping("S2")).json()).toEqual({ ok: true, result: "other_seller" });
    expect(await (await ping("S3")).json()).toEqual({ ok: true, result: "unknown_sale" });
    expect(await rows("SELECT * FROM licenses")).toHaveLength(0);
  });

  it("a refund seen on a later ping revokes (policy 'any' here); admin re-sync works the same way", async () => {
    let state = sale();
    fakeNet({ "https://api.gumroad.com/v2/sales/": () => ({ body: state }) });
    await ping("S1==");
    state = sale({ refunded: true });
    const r = await api("POST", "resync/gumroad", { sale_id: "S1==" });
    expect(r.data.result).toBe("applied");
    expect((await rows("SELECT status FROM licenses"))[0].status).toBe("revoked");
  });

  it("not enabled without GUMROAD_ACCESS_TOKEN", async () => {
    fakeNet();
    const res = await call(`/v1/webhooks/gumroad/${env.GUMROAD_PING_TOKEN}`, { method: "POST", body: "sale_id=1" }, { GUMROAD_ACCESS_TOKEN: "" });
    expect(res.status).toBe(404);
  });

  it("a lookup outage answers 503 (no hot loop: nothing is retried by the Worker itself)", async () => {
    const calls = fakeNet({ "https://api.gumroad.com/": "down" });
    expect((await ping("S1==")).status).toBe(503);
    expect(calls).toHaveLength(1);
  });
});

describe("housekeeping of events", () => {
  it("drops pending_target events after 7 days and deletes events after 90", async () => {
    fakeNet();
    await stripeSend({ id: "evt_p", type: "charge.refunded", data: { object: { payment_intent: "pi_never", amount: 1, amount_refunded: 1, refunded: true } } });
    await stripeSend(checkoutEvent("evt_old", { meta: "price_std" }));
    setNow(NOW + 8 * DAY);
    await api("POST", "housekeeping", {});
    expect((await rows("SELECT result FROM webhook_events WHERE event_id = 'evt_p'"))[0].result).toBe("dropped");
    setNow(NOW + 91 * DAY);
    await api("POST", "housekeeping", {});
    expect(await rows("SELECT * FROM webhook_events")).toHaveLength(0);
    void MIN;
    void hmacHex;
  });
});
