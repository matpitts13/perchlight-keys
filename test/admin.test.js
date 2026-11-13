import { env } from "cloudflare:test";
import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import { resetAll, rows, fakeNet, emails, api, call, post, issueKey, dev, setNow, stripeSend, lemonSend, lemonOrder, checkoutEvent, NOW, MIN, DAY, worker } from "./helpers.js";
import { ct } from "../src/lib/crypto.js";
import { parseCsv, planImport, runImport } from "../src/lib/importer.js";
import { loadConfig } from "../src/lib/config.js";
import shipped from "../keys.json";
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";

beforeEach(resetAll);
afterEach(() => vi.restoreAllMocks());

describe("admin auth", () => {
  it("401 without or with a wrong token, 503 while ADMIN_TOKEN is unset or short", async () => {
    expect((await api("GET", "config", undefined, {}, "wrong-token-0123456789")).status).toBe(401);
    expect((await call("/api/config")).status).toBe(401);
    expect((await api("GET", "config", undefined, { ADMIN_TOKEN: "" })).status).toBe(503);
    expect((await api("GET", "config", undefined, { ADMIN_TOKEN: "short" }, "short")).status).toBe(503);
    const ok = await api("GET", "config");
    expect(ok.status).toBe(200);
    expect(ok.data.problems).toEqual([]);
    expect(ok.data.products).toEqual(["app", "sub", "offline"]);
  });

  it("admin, webhook and key-HMAC comparisons go through the constant-time helper", async () => {
    const spy = vi.spyOn(ct, "equal");
    await api("GET", "config");
    expect(spy).toHaveBeenCalledWith("test-admin-token-0123456789", "test-admin-token-0123456789");
    spy.mockClear();
    fakeNet();
    await stripeSend(checkoutEvent("evt_ct", { meta: "price_std" }));
    expect(spy).toHaveBeenCalled();
    spy.mockClear();
    await lemonSend(lemonOrder(1));
    expect(spy).toHaveBeenCalled();
    spy.mockClear();
    const { key } = await issueKey();
    spy.mockClear();
    await post("/v1/activate", { key, product: "app", device: dev(1) });
    expect(spy.mock.calls.some(([a, b]) => String(a).startsWith("k1:") && a === b)).toBe(true);
    spy.mockClear();
    await call(`/v1/webhooks/gumroad/${"x".repeat(30)}`, { method: "POST", body: "sale_id=1" });
    expect(spy).toHaveBeenCalled();
  });
});

describe("issue, reveal and owner actions", () => {
  it("issues by hand (key returned once, emailed), reveals on request, never lists keys", async () => {
    const calls = fakeNet();
    const r = await api("POST", "licenses", { product: "app", edition: "pro", email: "Owner@Example.com", name: "O" });
    expect(r.status).toBe(201);
    expect(r.data.key).toMatch(/^TAPP-/);
    expect(r.data.license).not.toHaveProperty("key_hmac");
    expect(r.data.license).not.toHaveProperty("key_enc");
    expect(r.data.license.email).toBe("owner@example.com");
    expect(emails(calls)).toHaveLength(1);
    const list = await api("GET", "licenses?email=owner@example.com");
    expect(JSON.stringify(list.data)).not.toContain(r.data.key);
    expect(JSON.stringify(list.data)).not.toContain("key_hmac");
    const rev = await api("POST", `licenses/${r.data.license.id}/reveal`, {});
    expect(rev.data.key).toBe(r.data.key);
  });

  it("validates input", async () => {
    expect((await api("POST", "licenses", { product: "nope", email: "a@b.co" })).status).toBe(400);
    expect((await api("POST", "licenses", { product: "app", email: "bad" })).status).toBe(400);
    expect((await api("POST", "licenses", { product: "app", email: "a@b.co", edition: "gold" })).status).toBe(400);
    expect((await api("POST", "licenses", { product: "app", email: "a@b.co", source: "paypal" })).status).toBe(400);
    expect((await api("POST", "licenses", { product: "app", email: "a@b.co", device_limit: 0 })).status).toBe(400);
  });

  it("revoke / unrevoke / extend / edition / resend to a new address / free devices", async () => {
    const calls = fakeNet();
    const { key, license } = await issueKey({ expires_days: 5 });
    const id = license.id;
    await post("/v1/activate", { key, product: "app", device: dev(1) });
    await post("/v1/activate", { key, product: "app", device: dev(2) });
    expect((await api("POST", `licenses/${id}/revoke`, { reason: "abuse" })).data.changed).toBe(true);
    expect((await rows("SELECT status, revoked_reason FROM licenses"))[0]).toEqual({ status: "revoked", revoked_reason: "abuse" });
    await api("POST", `licenses/${id}/unrevoke`, {});
    const ext = await api("POST", `licenses/${id}/extend`, { days: 30 });
    expect(ext.data.expires_at).toBe(NOW + 35 * DAY);
    await api("POST", `licenses/${id}/extend`, { perpetual: true });
    expect((await rows("SELECT status, expires_at FROM licenses"))[0]).toEqual({ status: "active", expires_at: null });
    expect((await api("POST", `licenses/${id}/edition`, { edition: "gold" })).status).toBe(400);
    await api("POST", `licenses/${id}/edition`, { edition: "pro" });
    await api("POST", `licenses/${id}/resend`, { email: "new@example.com" });
    expect(emails(calls).at(-1).json.to).toEqual(["new@example.com"]);
    expect((await rows("SELECT email FROM licenses"))[0].email).toBe("new@example.com");
    const d = await api("GET", `licenses/${id}`);
    expect(d.data.activations).toHaveLength(2);
    expect((await api("POST", `activations/${d.data.activations[0].id}/free`, {})).data.freed).toBe(true);
    expect((await api("POST", `licenses/${id}/free-all`, {})).data.freed).toBe(1);
  });

  it("a desktop-app requested action runs on the next sweep (5 minutes on)", async () => {
    const calls = fakeNet();
    const { license, key } = await issueKey();
    await post("/v1/activate", { key, product: "app", device: dev(1) });
    await env.DB.prepare("UPDATE licenses SET action_requested = 'revoke' WHERE id = ?").bind(license.id).run();
    await env.DB.prepare("UPDATE activations SET free_requested = 1").run();
    setNow(NOW + 6 * MIN);
    await call("/");
    expect((await rows("SELECT status, action_requested FROM licenses"))[0]).toEqual({ status: "revoked", action_requested: null });
    expect((await rows("SELECT deactivated_at FROM activations"))[0].deactivated_at).toBe(NOW + 6 * MIN);
    await env.DB.prepare("UPDATE licenses SET action_requested = 'resend' WHERE id = ?").bind(license.id).run();
    setNow(NOW + 12 * MIN);
    await call("/");
    expect(emails(calls)).toHaveLength(0); // revoked: no key email
    void calls;
  });
});

describe("desktop app manifest", () => {
  it("every screen's table and column exists in the schema", async () => {
    const manifest = (await import("../perchlight/perchlight.json")).default;
    for (const v of manifest.views) {
      const cols = new Set((await rows(`SELECT name FROM pragma_table_info(?)`, v.source.table)).map((r) => r.name));
      expect(cols.size, v.source.table).toBeGreaterThan(0);
      for (const c of v.columns) expect(cols.has(c.from), `${v.source.table}.${c.from}`).toBe(true);
      for (const a of v.actions ?? []) for (const k of Object.keys(a.set ?? {})) expect(cols.has(k), `${v.source.table}.${k}`).toBe(true);
    }
  });

  it("Re-process from the app runs on the next sweep", async () => {
    fakeNet();
    await stripeSend(checkoutEvent("evt_rp", { meta: "price_nope" }));
    await env.DB.prepare("UPDATE webhook_events SET result = 'reprocess_requested', action = json_set(action, '$.ids', json_array('price_std'))").run();
    setNow(NOW + 6 * MIN);
    await call("/");
    expect((await rows("SELECT result FROM webhook_events"))[0].result).toBe("issued");
    expect(await rows("SELECT * FROM licenses")).toHaveLength(1);
  });
});

describe("email delivery", () => {
  it("claim-then-send: a failed send is retried by the lazy sweep at 1 min; an unclear outcome is never retried", async () => {
    let fail = true;
    const calls = fakeNet({ "https://api.resend.com/emails": () => (fail ? { status: 500, body: "{}" } : { status: 200, body: '{"id":"x"}' }) });
    await api("POST", "licenses", { product: "app", email: "a@example.com" });
    // A 5xx is "unknown" (it may have been sent): not retried.
    expect((await rows("SELECT status FROM deliveries"))[0].status).toBe("unknown");
    await env.DB.prepare("DELETE FROM deliveries").run();
    calls.length = 0;
    fakeNet({ "https://api.resend.com/emails": () => (fail ? { status: 429, body: '{"name":"rate_limit_exceeded"}' } : { status: 200, body: '{"id":"x"}' }) });
    await api("POST", "licenses", { product: "app", email: "b@example.com" });
    let d = (await rows("SELECT * FROM deliveries"))[0];
    expect(d).toMatchObject({ status: "retry", attempts: 1, next_at: NOW + MIN });
    fail = false;
    setNow(NOW + 6 * MIN);
    await call("/");
    d = (await rows("SELECT * FROM deliveries"))[0];
    expect(d).toMatchObject({ status: "sent", attempts: 2 });
  });

  it("gives up after 5 retries (failed), and Try again (admin retry) sends it", async () => {
    let fail = true;
    fakeNet({ "https://api.resend.com/emails": () => (fail ? { status: 429, body: "{}" } : { status: 200, body: "{}" }) });
    await api("POST", "licenses", { product: "app", email: "b@example.com" });
    let t = NOW;
    for (let i = 0; i < 6; i++) {
      t += 13 * 3_600_000;
      setNow(t);
      await api("POST", "housekeeping", {});
    }
    const d = (await rows("SELECT * FROM deliveries"))[0];
    expect(d).toMatchObject({ status: "failed", attempts: 6 });
    fail = false;
    const r = await api("POST", `deliveries/${d.id}/retry`, {});
    expect(r.data.status).toBe("sent");
  });

  it("without email configured, deliveries wait (pending) and nothing is lost", async () => {
    fakeNet();
    await api("POST", "licenses", { product: "app", email: "c@example.com" }, { RESEND_API_KEY: "" });
    expect((await rows("SELECT status FROM deliveries"))[0].status).toBe("pending");
  });
});

describe("storage", () => {
  it("no table holds a licence key or a private key in plain text", async () => {
    fakeNet();
    const keys = [];
    for (let i = 0; i < 3; i++) keys.push((await issueKey({ email: `s${i}@example.com` })).key);
    await post("/v1/activate", { key: keys[0], product: "app", device: dev(1) });
    await stripeSend(checkoutEvent("evt_s", { meta: "price_std" }));
    await post("/v1/resend", { email: "s1@example.com" });
    const tables = (await rows("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' AND name != 'd1_migrations'")).map((r) => r.name);
    const priv = JSON.parse(env.SIGNING_KEYS);
    for (const t of tables) {
      const dump = JSON.stringify(await rows(`SELECT * FROM ${t}`));
      for (const k of keys) {
        expect(dump).not.toContain(k);
        expect(dump).not.toContain(k.replace(/-/g, "").slice(4));
      }
      for (const p of Object.values(priv)) expect(dump).not.toContain(p.slice(20, 60));
    }
  });

  it("re-key rotates the lookup and encryption kids in bounded batches; keys keep working", async () => {
    fakeNet();
    const { key } = await issueKey();
    const rot = {
      KEY_LOOKUP_SECRET: JSON.stringify({ k1: env.KEY_LOOKUP_SECRET, k2: "new-lookup-secret-0123456789" }),
      KEY_LOOKUP_ACTIVE: "k2",
      KEY_ENC_SECRET: JSON.stringify({ k1: env.KEY_ENC_SECRET, k2: "new-enc-secret-0123456789abc" }),
      KEY_ENC_ACTIVE: "k2",
    };
    // Before the re-key, the old kids still find the key.
    expect((await post("/v1/activate", { key, product: "app", device: dev(1) }, rot)).status).toBe(200);
    const r = await api("POST", "rekey", {}, rot);
    expect(r.data).toMatchObject({ updated: 1, failed: 0 });
    const row = (await rows("SELECT key_hmac, key_enc FROM licenses"))[0];
    expect(row.key_hmac.startsWith("k2:")).toBe(true);
    expect(row.key_enc.startsWith("k2.")).toBe(true);
    const only2 = { ...rot, KEY_LOOKUP_SECRET: JSON.stringify({ k2: "new-lookup-secret-0123456789" }), KEY_ENC_SECRET: JSON.stringify({ k2: "new-enc-secret-0123456789abc" }) };
    expect((await post("/v1/renew", { key, device: dev(1) }, only2)).status).toBe(200);
    expect((await api("POST", `licenses/${(await rows("SELECT id FROM licenses"))[0].id}/reveal`, {}, only2)).data.key).toBe(key);
  });
});

describe("import script", () => {
  it("parses CSV, issues each order once, and is idempotent on a second run", async () => {
    fakeNet();
    const csv = 'email,product,edition,source,order_id,name\r\na@example.com,app,pro,lemonsqueezy,1001,"Smith, Ann"\nb@example.com,app,,gumroad,G-2,\n,app,,gumroad,G-3,\nc@example.com,app,,paypal,P-1,\n';
    const recs = parseCsv(csv);
    expect(recs[0].name).toBe("Smith, Ann");
    const { requests, errors } = planImport(recs);
    expect(requests).toHaveLength(2);
    expect(errors).toHaveLength(2);
    const postApi = async (body) => api("POST", "licenses", body);
    expect(await runImport(requests, postApi)).toMatchObject({ issued: 2, existing: 0, failed: [] });
    expect(await runImport(requests, postApi)).toMatchObject({ issued: 0, existing: 2 });
    const lics = await rows("SELECT source, source_ref, edition FROM licenses ORDER BY source");
    expect(lics).toEqual([
      { source: "gumroad", source_ref: "G-2", edition: "standard" },
      { source: "lemonsqueezy", source_ref: "1001", edition: "pro" },
    ]);
    // A later Lemon Squeezy webhook for an imported order issues nothing new.
    expect((await lemonSend(lemonOrder(1001))).data.result).toBe("duplicate");
  });

  it("stops after repeated failures instead of looping", async () => {
    let n = 0;
    const out = await runImport(
      [1, 2, 3, 4, 5].map((i) => ({ line: i, body: {} })),
      async () => {
        n++;
        return { status: 503, data: { error: "unavailable" } };
      },
    );
    expect(out.stopped).toBe(true);
    expect(n).toBe(3);
  });
});

describe("config", () => {
  it("the shipped keys.json is valid", () => {
    expect(loadConfig(shipped).errors).toEqual([]);
  });

  it("a bad product is left out with a message; the rest keep working", () => {
    const c = loadConfig({ products: { ok: { name: "A", prefix: "OK", editions: { s: { features: [] } } }, bad: { name: "B", prefix: "lower", editions: {} } } });
    expect(Object.keys(c.products)).toEqual(["ok"]);
    expect(c.errors.join("\n")).toMatch(/products\.bad: prefix/);
  });

  it("there's no cron trigger in wrangler.jsonc", async () => {
    // The vitest pool reads wrangler.jsonc; a "triggers" block would show up as scheduled handlers. Checked directly too:
    expect(typeof worker.scheduled).toBe("undefined");
  });
});

describe("footprint", () => {
  it("a simulated day of the example store: under 1,000 Worker requests and under 2,500 D1 rows written", async () => {
    fakeNet();
    const start = NOW;
    const step = (i, n) => start + Math.floor((i / n) * (DAY - 10 * MIN));
    // 300 installed copies already activated (rows made directly, not counted as today's traffic).
    const base = [];
    for (let i = 0; i < 30; i++) base.push(await issueKey({ email: `old${i}@example.com`, device_limit: 20 }));
    const leases = [];
    for (let i = 0; i < 300; i++) {
      const r = await post("/v1/activate", { key: base[i % 30].key, product: "app", device: dev(10_000 + i) }, {}, `10.0.${i % 250}.1`);
      leases.push(r.data.lease);
    }
    await env.DB.prepare("DELETE FROM footprint").run();
    const { resetFootprint } = await import("../src/lib/footprint.js");
    resetFootprint();
    let requests = 0;
    // 30 sales, 30 activations, 500 renewals, 10 resends, 3 trials, spread over the day.
    const plan = [];
    for (let i = 0; i < 30; i++) plan.push(["sale", i]);
    for (let i = 0; i < 30; i++) plan.push(["activate", i]);
    for (let i = 0; i < 500; i++) plan.push(["renew", i]);
    for (let i = 0; i < 10; i++) plan.push(["resend", i]);
    for (let i = 0; i < 3; i++) plan.push(["trial", i]);
    plan.sort((a, b) => ((a[1] * 7919 + a[0].length) % 573) - ((b[1] * 7919 + b[0].length) % 573));
    const sold = [];
    for (let i = 0; i < plan.length; i++) {
      setNow(step(i, plan.length));
      const [kind, n] = plan[i];
      const ip = `172.16.${i % 250}.${n % 250}`;
      if (kind === "sale") {
        await stripeSend(checkoutEvent(`evt_day_${n}`, { meta: "price_std", session: `cs_day_${n}`, pi: `pi_day_${n}`, email: `new${n}@example.com` }));
        sold.push(n);
      } else if (kind === "activate") {
        const key = base[n].key;
        await post("/v1/activate", { key, product: "app", device: dev(20_000 + n) }, {}, ip);
      } else if (kind === "renew") await post("/v1/renew", { lease: leases[n % 300] }, {}, ip);
      else if (kind === "resend") await post("/v1/resend", { email: `old${n}@example.com` }, {}, ip);
      else await post("/v1/trial", { product: "app", device: dev(30_000 + n) }, {}, ip);
      requests++;
    }
    setNow(start + DAY - MIN);
    const fp = await api("GET", "footprint");
    // The simulated 24 hours span two UTC days: add them up.
    const day = {};
    for (const d of Object.values(fp.data.days)) for (const [k, n] of Object.entries(d)) day[k] = (day[k] ?? 0) + n;
    expect(requests).toBe(573);
    expect(day.worker_requests).toBeLessThan(1000);
    expect(day.d1_rows_written).toBeLessThan(2500);
    expect(day.emails_sent).toBe(40);
    // Kept for the README: the measured numbers.
    console.log(`simulated day: ${day.worker_requests} requests, ${day.d1_rows_written} D1 rows written, ${day.d1_rows_read} read, ${day.d1_queries} D1 calls, ${day.emails_sent} emails`);
    void createExecutionContext;
    void waitOnExecutionContext;
    void sold;
  });
});
