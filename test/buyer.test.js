import { describe, it, expect, beforeEach } from "vitest";
import { resetAll, rows, fakeNet, emails, call, post, issueKey, setNow, NOW, MIN, HOUR } from "./helpers.js";
import { extractDownloadKey } from "../src/routes/buyer.js";

beforeEach(resetAll);

const resend = (email, ip = "198.51.100.1") => post("/v1/resend", { email }, {}, ip);

describe("resend my keys", () => {
  it("the same status, body and headers for a buyer and a non-buyer; only the buyer gets one email listing their keys", async () => {
    const calls = fakeNet();
    const a = await issueKey({ email: "buyer@example.com" });
    const b = await issueKey({ email: "buyer@example.com", product: "sub" });
    const yes = await resend("Buyer@Example.com ");
    const no = await resend("stranger@example.com", "198.51.100.2");
    expect(yes.status).toBe(202);
    expect(no.status).toBe(202);
    expect(yes.data).toEqual({ ok: true });
    expect(no.data).toEqual(yes.data);
    expect([...yes.res.headers.entries()]).toEqual([...no.res.headers.entries()]);
    const sent = emails(calls);
    expect(sent).toHaveLength(1);
    expect(sent[0].json.to).toEqual(["buyer@example.com"]);
    expect(sent[0].json.subject).toBe("Your keys (requested)");
    expect(sent[0].json.text).toContain(a.key);
    expect(sent[0].json.text).toContain(b.key);
  });

  it("malformed input still answers 202", async () => {
    fakeNet();
    expect((await resend("not-an-email")).status).toBe(202);
    const res = await call("/v1/resend", { method: "POST", body: "{bad json" });
    expect(res.status).toBe(202);
  });

  it("1 per 15 minutes and 5 a day per address: a sixth request in a day sends nothing", async () => {
    const calls = fakeNet();
    await issueKey({ email: "buyer@example.com" });
    for (let i = 0; i < 6; i++) {
      setNow(NOW + i * 16 * MIN);
      expect((await resend("buyer@example.com", `198.51.100.${10 + i}`)).status).toBe(202);
    }
    expect(emails(calls)).toHaveLength(5);
    setNow(NOW + 5 * 16 * MIN + MIN);
    await resend("buyer@example.com", "198.51.100.50");
    expect(emails(calls)).toHaveLength(5); // within 15 minutes of the last
  });

  it("10 requests an hour per IP, and the global daily cap", async () => {
    const calls = fakeNet();
    for (let i = 0; i < 12; i++) await issueKey({ email: `b${i}@example.com` });
    for (let i = 0; i < 12; i++) await resend(`b${i}@example.com`, "198.51.100.99");
    expect(emails(calls)).toHaveLength(10);
    setNow(NOW + HOUR);
    const capped = await post("/v1/resend", { email: "b11@example.com" }, { RESEND_DAILY_CAP: "10" }, "198.51.100.100");
    expect(capped.status).toBe(202);
    expect(emails(calls)).toHaveLength(10);
  });

  it("stores no email address or IP in the rate table", async () => {
    fakeNet();
    await resend("buyer@example.com");
    const r = await rows("SELECT bucket FROM rate");
    expect(r.length).toBeGreaterThan(0);
    for (const { bucket } of r) {
      expect(bucket).not.toContain("buyer");
      expect(bucket).not.toContain("198.51");
    }
  });
});

describe("itch.io claim", () => {
  const form = (fields, ip = "192.0.2.1") =>
    call("/claim/itch", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(fields).toString() }, {}, ip);
  const itch = (key) => ({ download_key: { id: 4242, key, game_id: 999, downloads: 1 } });

  it("serves the form", async () => {
    const res = await call("/claim/itch");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Security-Policy")).toContain("default-src 'none'");
    expect(await res.text()).toContain('name="download_key"');
  });

  it("a valid download key claims one licence; claiming again re-shows the same key, re-sends to the first address, and creates nothing new", async () => {
    const calls = fakeNet({ "https://api.itch.io/games/999/download_keys": (url) => ({ body: itch(new URL(url).searchParams.get("download_key")) }) });
    const res = await form({ download_key: "https://seller.itch.io/game/download/AbCdEfGhIjKlMnOp1234", email: "fan@example.com", product: "app" });
    expect(res.status).toBe(200);
    const html = await res.text();
    const key = /TAPP-[0-9A-Z-]+[0-9A-Z*~$=U]/.exec(html)[0];
    expect(calls[0].url).toBe("https://api.itch.io/games/999/download_keys?download_key=AbCdEfGhIjKlMnOp1234");
    expect(calls[0].headers.get("Authorization")).toBe("Bearer itch-api-key");
    expect(await rows("SELECT source, source_ref, email FROM licenses")).toEqual([{ source: "itch", source_ref: "4242", email: "fan@example.com" }]);
    const again = await form({ download_key: "AbCdEfGhIjKlMnOp1234", email: "someone-else@example.com" });
    expect(await again.text()).toContain(key);
    expect(await rows("SELECT * FROM licenses")).toHaveLength(1);
    const sent = emails(calls);
    expect(sent).toHaveLength(2);
    expect(sent.map((s) => s.json.to[0])).toEqual(["fan@example.com", "fan@example.com"]);
  });

  it("a made-up key gets a generic failure and no licence", async () => {
    fakeNet({ "https://api.itch.io/": { status: 404, body: { errors: ["invalid download key"] } } });
    const res = await form({ download_key: "MadeUpKeyMadeUpKey00", email: "x@example.com" });
    expect(await res.text()).toContain("couldn&#39;t be used");
    expect(await rows("SELECT * FROM licenses")).toHaveLength(0);
  });

  it("a key for another game doesn't claim", async () => {
    fakeNet({ "https://api.itch.io/": { body: { download_key: { id: 1, game_id: 123 } } } });
    await form({ download_key: "OtherGameKey00000000", email: "x@example.com" });
    expect(await rows("SELECT * FROM licenses")).toHaveLength(0);
  });

  it("rate-limited per IP (10 an hour) and per download key (5 a day)", async () => {
    const calls = fakeNet({ "https://api.itch.io/": { status: 404, body: {} } });
    for (let i = 0; i < 6; i++) await form({ download_key: "SameKeySameKey000000", email: "x@example.com" }, `192.0.2.${i + 10}`);
    expect(calls).toHaveLength(5);
    for (let i = 0; i < 11; i++) await form({ download_key: `Key${i}xxxxxxxxxxxxxx`, email: "x@example.com" }, "192.0.2.200");
    expect(calls).toHaveLength(15);
  });

  it("extracts the key from a pasted URL or the bare key, and nothing else", () => {
    expect(extractDownloadKey("https://a.itch.io/g/download/Abc_def-1234567890?x=1")).toBe("Abc_def-1234567890");
    expect(extractDownloadKey("  Abc_def-1234567890 ")).toBe("Abc_def-1234567890");
    expect(extractDownloadKey("<script>")).toBeNull();
    expect(extractDownloadKey("x".repeat(400))).toBeNull();
  });
});
