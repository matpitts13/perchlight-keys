import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { generateKey, parseKey, formatKey } from "../src/lib/keyfmt.js";
import { signToken, verifyToken, publicKeys, ownPublicKeys, signingConfig } from "../src/lib/tokens.js";
import { aesEncrypt, aesDecrypt, ct, fromBase64, importSigningKey, toBase64Url, utf8 } from "../src/lib/crypto.js";
import { secretSet } from "../src/lib/appctx.js";

describe("Ed25519 in workerd's WebCrypto", () => {
  it("generates, signs and verifies with {name: 'Ed25519'}", async () => {
    const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const msg = utf8("hello");
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, msg));
    expect(sig.length).toBe(64);
    expect(await crypto.subtle.verify({ name: "Ed25519" }, kp.publicKey, sig, msg)).toBe(true);
    sig[0] ^= 1;
    expect(await crypto.subtle.verify({ name: "Ed25519" }, kp.publicKey, sig, msg)).toBe(false);
  });

  it("imports a PKCS#8 key from SIGNING_KEYS and derives its public key from the JWK export", async () => {
    const cfg = signingConfig(env);
    const { privateKey, publicRaw } = await importSigningKey(cfg.keys.k1);
    expect(publicRaw.length).toBe(32);
    const sig = await crypto.subtle.sign({ name: "Ed25519" }, privateKey, utf8("x"));
    const pub = await crypto.subtle.importKey("raw", publicRaw, { name: "Ed25519" }, false, ["verify"]);
    expect(await crypto.subtle.verify({ name: "Ed25519" }, pub, sig, utf8("x"))).toBe(true);
  });

  it("matches RFC 8032 test 1 (deterministic signature for the empty message)", async () => {
    // RFC 8032 section 7.1, TEST 1 (a published test key, not a real one).
    const seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const pubHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const want =
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    const h2b = (h) => new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)));
    const jwk = { kty: "OKP", crv: "Ed25519", d: toBase64Url(h2b(seed)), x: toBase64Url(h2b(pubHex)) };
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["sign"]);
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, new Uint8Array(0)));
    expect([...sig].map((b) => b.toString(16).padStart(2, "0")).join("")).toBe(want);
  });

  it("signs a lease quickly enough (CPU sanity check, not a production measurement)", async () => {
    const t0 = performance.now();
    for (let i = 0; i < 20; i++) await signToken(env, { typ: "lease", lid: "lic_x", prod: "app", iat: i });
    // workerd's clock only advances on I/O; this just proves 20 signatures don't throw or hang.
    expect(performance.now() - t0).toBeGreaterThanOrEqual(0);
  });
});

describe("licence key format", () => {
  it("is PREFIX- then 26 Crockford symbols and a check symbol, in groups of 5", () => {
    const k = generateKey("TAPP");
    expect(k).toMatch(/^TAPP-([0-9A-HJKMNP-TV-Z]{5}-){5}[0-7A-Z0-9][0-9A-HJKMNP-TV-Z*~$=U]$/);
    expect(parseKey(k)).not.toBeNull();
  });

  it("carries 128 random bits (first symbol 0-7) and never repeats in 2,000 draws", () => {
    const seen = new Set();
    for (let i = 0; i < 2000; i++) {
      const p = parseKey(generateKey("A"));
      expect("01234567").toContain(p.body[0]);
      seen.add(p.body);
    }
    expect(seen.size).toBe(2000);
  });

  it("forgives case, spaces, dashes, O/0 and I/L/1, and ignores the prefix", () => {
    const body = "7K2QMZD0A4RT8VXW3NBCPF9HS1";
    const k = formatKey("TAPP", body);
    const p = parseKey(k);
    expect(p.body).toBe(body);
    const messy = k.toLowerCase().replace(/-/g, " ").replace("d0", "do").replace("s1", "sl");
    expect(parseKey(messy).body).toBe(body);
    expect(parseKey(k.replace("TAPP-", "OTHER-")).body).toBe(body);
    expect(parseKey(k.replace("TAPP-", "")).body).toBe(body);
  });

  it("catches a typo with the check symbol (any single substitution)", () => {
    const k = generateKey("TAPP");
    const chars = k.replace("TAPP-", "").replace(/-/g, "").split("");
    for (let i = 1; i < 26; i++) {
      const alt = chars[i] === "A" ? "B" : "A";
      const bad = [...chars];
      bad[i] = alt;
      expect(parseKey(bad.join(""))).toBeNull();
    }
  });

  it("refuses garbage, too-long input and a first symbol above 7", () => {
    expect(parseKey("")).toBeNull();
    expect(parseKey("TAPP-XXXXX")).toBeNull();
    expect(parseKey("x".repeat(100))).toBeNull();
    expect(parseKey(null)).toBeNull();
    const body = "Z" + "0".repeat(25);
    expect(parseKey(formatKey("TAPP", body))).toBeNull();
  });
});

describe("signed tokens", () => {
  it("round-trips with the active kid and the domain-separated message", async () => {
    const t = await signToken(env, { typ: "lease", lid: "lic_1", prod: "app", dev: "d" });
    expect(t.startsWith("PLK1.")).toBe(true);
    const pk = await publicKeys(env);
    const p = await verifyToken(t, pk.keys, "lease");
    expect(p).toMatchObject({ typ: "lease", kid: "k1", lid: "lic_1" });
    expect(t.length).toBeLessThan(450);
  });

  it("refuses a different typ, a changed byte, an unknown kid and junk", async () => {
    const pk = await ownPublicKeys(env);
    const t = await signToken(env, { typ: "revs", prod: "app", lids: [] });
    expect(await verifyToken(t, pk, "lic")).toBeNull();
    const [h, p, s] = t.split(".");
    const pb = fromBase64(p);
    pb[5] ^= 1;
    expect(await verifyToken(`${h}.${toBase64Url(pb)}.${s}`, pk, "revs")).toBeNull();
    expect(await verifyToken(t, { k9: pk.k1 }, "revs")).toBeNull();
    expect(await verifyToken("PLK1.e30.AAAA", pk)).toBeNull();
    expect(await verifyToken("nope", pk)).toBeNull();
    expect(await verifyToken(`PLK2.${p}.${s}`, pk)).toBeNull();
  });

  it("a revocation list's signature can't be re-labelled as a licence (typ is in the signed prefix)", async () => {
    const pk = await ownPublicKeys(env);
    const t = await signToken(env, { typ: "revs", prod: "app" });
    const [, p, s] = t.split(".");
    const payload = JSON.parse(new TextDecoder().decode(fromBase64(p)));
    payload.typ = "lic";
    const forged = `PLK1.${toBase64Url(utf8(JSON.stringify(payload)))}.${s}`;
    expect(await verifyToken(forged, pk, "lic")).toBeNull();
  });

  it("rotation: switching ACTIVE_KID signs with the new kid; old leases still verify with both public keys", async () => {
    const old = await signToken(env, { typ: "lease", lid: "a" });
    const env2 = { ...env, ACTIVE_KID: "k2" };
    const fresh = await signToken(env2, { typ: "lease", lid: "b" });
    const both = (await publicKeys(env2)).keys;
    expect((await verifyToken(fresh, both, "lease")).kid).toBe("k2");
    expect((await verifyToken(old, both, "lease")).kid).toBe("k1");
    expect(await verifyToken(fresh, { k1: both.k1 }, "lease")).toBeNull();
  });

  it("refuses a bad signing config with a message that names no key", () => {
    expect(() => signingConfig({ SIGNING_KEYS: "", ACTIVE_KID: "k1" })).toThrow(/SIGNING_KEYS/);
    expect(() => signingConfig({ SIGNING_KEYS: '{"k1":"x"}', ACTIVE_KID: "k9" })).toThrow(/ACTIVE_KID/);
  });
});

describe("AES-GCM key copies", () => {
  it("encrypts with a kid, binds to the licence id, and decrypts after rotation", async () => {
    const v = await aesEncrypt("k1", "secret-one-0123456789", "TAPP-KEY", "lic_1");
    expect(v.startsWith("k1.")).toBe(true);
    expect(v).not.toContain("TAPP");
    expect(await aesDecrypt({ k1: "secret-one-0123456789" }, v, "lic_1")).toBe("TAPP-KEY");
    expect(await aesDecrypt({ k1: "secret-one-0123456789" }, v, "lic_2")).toBeNull(); // AAD
    expect(await aesDecrypt({ k2: "secret-two-0123456789" }, v, "lic_1")).toBeNull();
    expect(await aesDecrypt({ k1: "secret-one-0123456789", k2: "secret-two-0123456789" }, v, "lic_1")).toBe("TAPP-KEY");
  });

  it("secretSet: a plain string is kid k1; JSON names kids; short secrets are refused", () => {
    expect(secretSet({ S: "a".repeat(20) }, "S", "SA")).toEqual({ active: "k1", secrets: { k1: "a".repeat(20) } });
    expect(secretSet({ S: JSON.stringify({ old: "a".repeat(20), new: "b".repeat(20) }), SA: "new" }, "S", "SA").active).toBe("new");
    expect(() => secretSet({ S: "short" }, "S", "SA")).toThrow(/16/);
    expect(() => secretSet({}, "S", "SA")).toThrow(/isn't set/);
  });
});

describe("constant-time compare", () => {
  it("compares by hashing both sides", async () => {
    expect(await ct.equal("abc", "abc")).toBe(true);
    expect(await ct.equal("abc", "abd")).toBe(false);
    expect(await ct.equal("abc", "abcd")).toBe(false);
  });
});
