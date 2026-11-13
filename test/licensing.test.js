import { env } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import { resetAll, post, get, api, rows, issueKey, dev, setNow, NOW, DAY, MIN } from "./helpers.js";
import { verifyToken, publicKeys } from "../src/lib/tokens.js";

beforeEach(resetAll);

async function pubs() {
  return (await publicKeys(env)).keys;
}

describe("activate", () => {
  it("returns a device-bound lease: 30 days, renew from day 23, 7 days' grace, features of the edition", async () => {
    const { key, license } = await issueKey({ edition: "pro" });
    const r = await post("/v1/activate", { key, product: "app", device: dev(1), label: "Laptop" });
    expect(r.status).toBe(200);
    const p = await verifyToken(r.data.lease, await pubs(), "lease");
    const s = NOW / 1000;
    expect(p).toMatchObject({ typ: "lease", kid: "k1", lid: license.id, prod: "app", ed: "pro", feat: ["core", "export"], dev: dev(1), iat: s, nbf: s, exp: s + 30 * 86400, renew: s + 23 * 86400, grace: 7 * 86400 });
    expect(p).not.toHaveProperty("email");
    expect(r.data.server_time).toBe(s);
  });

  it("device limit 2: a third device gets 409 with the 2 devices (labels and last-seen only); freeing one lets it in; re-activating uses no slot", async () => {
    const { key } = await issueKey();
    expect((await post("/v1/activate", { key, product: "app", device: dev(1), label: "A" })).status).toBe(200);
    expect((await post("/v1/activate", { key, product: "app", device: dev(2), label: "B" })).status).toBe(200);
    expect((await post("/v1/activate", { key, product: "app", device: dev(1) })).status).toBe(200); // re-activation
    const third = await post("/v1/activate", { key, product: "app", device: dev(3) });
    expect(third.status).toBe(409);
    expect(third.data.error).toBe("device_limit");
    expect(third.data.devices.map((d) => d.label)).toEqual(["A", "B"]);
    expect(Object.keys(third.data.devices[0]).sort()).toEqual(["id", "label", "last_seen"]);
    expect(JSON.stringify(third.data)).not.toContain(dev(1));
    const d = await post("/v1/deactivate", { key, device: dev(1) });
    expect(d.data).toEqual({ ok: true, freed: true });
    expect((await post("/v1/activate", { key, product: "app", device: dev(3) })).status).toBe(200);
    expect((await rows("SELECT COUNT(*) AS n FROM activations WHERE deactivated_at IS NULL AND kind = 'full'"))[0].n).toBe(2);
  });

  it("a buyer can free another device by the activation id from the 409 list", async () => {
    const { key } = await issueKey();
    await post("/v1/activate", { key, product: "app", device: dev(1) });
    await post("/v1/activate", { key, product: "app", device: dev(2) });
    const third = await post("/v1/activate", { key, product: "app", device: dev(3) });
    const r = await post("/v1/deactivate", { key, activation: third.data.devices[0].id });
    expect(r.data.freed).toBe(true);
    expect((await post("/v1/activate", { key, product: "app", device: dev(3) })).status).toBe(200);
  });

  it("concurrent activations of different devices can't exceed the limit", async () => {
    const { key } = await issueKey();
    const results = await Promise.all([1, 2, 3, 4, 5].map((n) => post("/v1/activate", { key, product: "app", device: dev(n) })));
    expect(results.filter((r) => r.status === 200).length).toBe(2);
    expect(results.filter((r) => r.status === 409).length).toBe(3);
  });

  it("invalid_key for a bad check symbol, an unknown key and another product's key, all the same answer", async () => {
    const { key } = await issueKey();
    const typo = key.slice(0, -2) + (key.at(-2) === "A" ? "B" : "A") + key.at(-1);
    const unknown = (await issueKey({ product: "sub" })).key;
    const a = await post("/v1/activate", { key: typo, product: "app", device: dev(1) });
    const b = await post("/v1/activate", { key: unknown, product: "app", device: dev(1) });
    expect(a.status).toBe(404);
    expect(b.status).toBe(404);
    expect(a.data).toEqual(b.data);
  });

  it("revoked -> 403 revoked; expired -> 403 expired; bad device and unknown product -> 400", async () => {
    const { key, license } = await issueKey();
    await api("POST", `licenses/${license.id}/revoke`, { reason: "test" });
    expect((await post("/v1/activate", { key, product: "app", device: dev(1) })).data.error).toBe("revoked");
    const e = await issueKey({ expires_days: 1 });
    setNow(NOW + 2 * DAY);
    expect((await post("/v1/activate", { key: e.key, product: "app", device: dev(1) })).data.error).toBe("expired");
    expect((await post("/v1/activate", { key: e.key, product: "app", device: "short" })).status).toBe(400);
    expect((await post("/v1/activate", { key: e.key, product: "nope", device: dev(1) })).data.error).toBe("unknown_product");
  });

  it("a lease never outlives the licence's own expiry", async () => {
    const { key } = await issueKey({ expires_days: 10 });
    const r = await post("/v1/activate", { key, product: "app", device: dev(1) });
    const p = await verifyToken(r.data.lease, await pubs(), "lease");
    expect(p.exp).toBe(NOW / 1000 + 10 * 86400);
  });

  it("rate-limits one IP to 20 calls a minute (429)", async () => {
    const { key } = await issueKey();
    let last;
    for (let i = 0; i < 21; i++) last = await post("/v1/activate", { key, product: "app", device: dev(1) });
    expect(last.status).toBe(429);
    expect(last.res.headers.get("Retry-After")).toBe("60");
    setNow(NOW + MIN);
    expect((await post("/v1/activate", { key, product: "app", device: dev(1) })).status).toBe(200);
  });

  it("refuses oversized bodies", async () => {
    const r = await post("/v1/activate", { key: "x", product: "app", device: dev(1), pad: "x".repeat(9000) });
    expect(r.status).toBe(400);
  });
});

describe("renew", () => {
  it("renews by lease or by key+device; last-seen is written at most once a day", async () => {
    const { key, license } = await issueKey();
    const a = await post("/v1/activate", { key, product: "app", device: dev(1) });
    setNow(NOW + 23 * DAY);
    const r = await post("/v1/renew", { lease: a.data.lease });
    expect(r.status).toBe(200);
    const p = await verifyToken(r.data.lease, await pubs(), "lease");
    expect(p.iat).toBe((NOW + 23 * DAY) / 1000);
    const seen1 = (await rows("SELECT last_seen_at FROM activations WHERE license_id = ?", license.id))[0].last_seen_at;
    expect(seen1).toBe(NOW + 23 * DAY);
    setNow(NOW + 23 * DAY + 3_600_000);
    expect((await post("/v1/renew", { key, device: dev(1) })).status).toBe(200);
    expect((await rows("SELECT last_seen_at FROM activations WHERE license_id = ?", license.id))[0].last_seen_at).toBe(seen1);
  });

  it("an expired lease still renews (the licence is the authority); a forged or freed one doesn't", async () => {
    const { key } = await issueKey();
    const a = await post("/v1/activate", { key, product: "app", device: dev(1) });
    setNow(NOW + 60 * DAY);
    expect((await post("/v1/renew", { lease: a.data.lease })).status).toBe(200);
    const forged = a.data.lease.slice(0, -4) + (a.data.lease.endsWith("AAAA") ? "BBBB" : "AAAA");
    expect((await post("/v1/renew", { lease: forged })).data.error).toBe("invalid_lease");
    await post("/v1/deactivate", { key, device: dev(1) });
    expect((await post("/v1/renew", { lease: a.data.lease })).data.error).toBe("not_activated");
  });

  it("after a revoke, renew fails with 403 revoked and the id is in a correctly signed /v1/revocations", async () => {
    const { key, license } = await issueKey();
    const a = await post("/v1/activate", { key, product: "app", device: dev(1) });
    await api("POST", `licenses/${license.id}/revoke`, { reason: "refund" });
    expect((await post("/v1/renew", { lease: a.data.lease })).data.error).toBe("revoked");
    const rv = await get("/v1/revocations?product=app&since=0");
    expect(rv.res.headers.get("Cache-Control")).toBe("public, max-age=3600");
    const p = await verifyToken(rv.data.revocations, await pubs(), "revs");
    expect(p.lids).toEqual([license.id]);
    expect(p.prod).toBe("app");
    expect(p.kids_revoked).toEqual([]);
    const later = await get(`/v1/revocations?product=app&since=${NOW / 1000 + 1}`);
    expect((await verifyToken(later.data.revocations, await pubs(), "revs")).lids).toEqual([]);
  });

  it("a renewed lease picks up an edition change at once", async () => {
    const { key, license } = await issueKey();
    const a = await post("/v1/activate", { key, product: "app", device: dev(1) });
    await api("POST", `licenses/${license.id}/edition`, { edition: "pro" });
    const p = await verifyToken((await post("/v1/renew", { lease: a.data.lease })).data.lease, await pubs(), "lease");
    expect(p.ed).toBe("pro");
    expect(p.feat).toContain("export");
  });

  it("rotation: renew accepts a lease signed by the old kid and returns one signed by the new", async () => {
    const { key } = await issueKey();
    const a = await post("/v1/activate", { key, product: "app", device: dev(1) });
    const r = await post("/v1/renew", { lease: a.data.lease }, { ACTIVE_KID: "k2" });
    const p = await verifyToken(r.data.lease, await pubs(), "lease");
    expect(p.kid).toBe("k2");
  });
});

describe("deactivate churn", () => {
  it("flags the licence after more than 10 deactivations in a month", async () => {
    const { key, license } = await issueKey();
    for (let i = 0; i < 11; i++) {
      setNow(NOW + i * 2 * MIN);
      await post("/v1/activate", { key, product: "app", device: dev(1) });
      await post("/v1/deactivate", { key, device: dev(1) });
    }
    const l = (await rows("SELECT churn, flags FROM licenses WHERE id = ?", license.id))[0];
    expect(l.churn).toBe(11);
    expect(l.flags).toBe("churn");
  });
});

describe("offline-only products: /v1/license", () => {
  it("returns a signed licence file with no device and refuses activation", async () => {
    const { key, license } = await issueKey({ product: "offline" });
    const r = await post("/v1/license", { key });
    expect(r.status).toBe(200);
    const p = await verifyToken(r.data.license, await pubs(), "lic");
    expect(p).toMatchObject({ typ: "lic", lid: license.id, prod: "offline", ed: "std", exp: null });
    expect(p.dev).toBeUndefined();
    expect((await post("/v1/activate", { key, product: "offline", device: dev(1) })).data.error).toBe("offline_only");
    const dk = await issueKey();
    expect((await post("/v1/license", { key: dk.key })).data.error).toBe("activation_required");
  });
});

describe("trial", () => {
  it("one trial per product and device; the same window on a repeat; trial_used after it ends", async () => {
    const r = await post("/v1/trial", { product: "app", device: dev(7) });
    expect(r.status).toBe(200);
    const p = await verifyToken(r.data.lease, await pubs(), "trial");
    expect(p).toMatchObject({ typ: "trial", lid: null, prod: "app", ed: "standard", dev: dev(7), exp: NOW / 1000 + 14 * 86400, grace: 0 });
    setNow(NOW + 5 * DAY);
    const again = await verifyToken((await post("/v1/trial", { product: "app", device: dev(7) })).data.lease, await pubs(), "trial");
    expect(again.exp).toBe(p.exp);
    setNow(NOW + 15 * DAY);
    expect((await post("/v1/trial", { product: "app", device: dev(7) })).data.error).toBe("trial_used");
    expect((await post("/v1/trial", { product: "offline", device: dev(7) })).data.error).toBe("no_trial");
  });
});

describe("keys", () => {
  it("serves the public keys and the active kid", async () => {
    const r = await get("/v1/keys");
    expect(r.data.active).toBe("k1");
    expect(Object.keys(r.data.keys)).toEqual(["k1", "k2"]);
    const r2 = await get("/v1/keys", { REVOKED_KIDS: '["k0"]' });
    expect(r2.data.kids_revoked).toEqual(["k0"]);
  });
});
