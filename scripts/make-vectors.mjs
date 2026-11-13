#!/usr/bin/env node
// Writes samples/vectors/rfc8032.json and samples/vectors/tokens.json.
//
// rfc8032.json: RFC 8032 section 7.1 TEST 1-3 (checked here against node:crypto
// before writing), negative cases (a flipped bit, S >= L), and a few longer
// messages signed by node:crypto with the RFC's test key.
// tokens.json: perchlight-keys tokens signed with the RFC 8032 TEST 1 key
// (a published test key, never a real one) and the expected verdict for each.
// Ed25519 is deterministic, so re-running produces the same files;
// test/vectors.test.js checks the Worker's own signer produces them byte for byte.
import crypto from "node:crypto";
import { writeFileSync, mkdirSync } from "node:fs";

const RFC = [
  {
    name: "RFC 8032 7.1 TEST 1",
    secret: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    public: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    message: "",
    signature: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  },
  {
    name: "RFC 8032 7.1 TEST 2",
    secret: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    public: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    message: "72",
    signature: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
  },
  {
    name: "RFC 8032 7.1 TEST 3",
    secret: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    public: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    message: "af82",
    signature: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
  },
];

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const privOf = (seedHex) => crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seedHex, "hex")]), format: "der", type: "pkcs8" });
const pubOf = (seedHex) => crypto.createPublicKey(privOf(seedHex)).export({ format: "der", type: "spki" }).subarray(-32);
const sign = (seedHex, msg) => crypto.sign(null, msg, privOf(seedHex));

for (const v of RFC) {
  if (pubOf(v.secret).toString("hex") !== v.public) throw new Error(`${v.name}: public key mismatch`);
  if (sign(v.secret, Buffer.from(v.message, "hex")).toString("hex") !== v.signature) throw new Error(`${v.name}: signature mismatch`);
}

const valid = RFC.map((v) => ({ name: v.name, public: v.public, message: v.message, signature: v.signature, valid: true }));
const t1 = RFC[0];
const L = BigInt("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");
const sigBytes = Buffer.from(RFC[1].signature, "hex");
const s = BigInt("0x" + Buffer.from(sigBytes.subarray(32)).reverse().toString("hex"));
const sPlusL = Buffer.from((s + L).toString(16).padStart(64, "0"), "hex").reverse();
const malleable = Buffer.concat([sigBytes.subarray(0, 32), sPlusL]).toString("hex");
const flip = (hex, i) => {
  const b = Buffer.from(hex, "hex");
  b[i] ^= 1;
  return b.toString("hex");
};
const negative = [
  { name: "TEST 2 with a flipped bit in R", public: RFC[1].public, message: RFC[1].message, signature: flip(RFC[1].signature, 0), valid: false },
  { name: "TEST 2 with a flipped bit in S", public: RFC[1].public, message: RFC[1].message, signature: flip(RFC[1].signature, 40), valid: false },
  { name: "TEST 2 with a different message", public: RFC[1].public, message: "73", signature: RFC[1].signature, valid: false },
  { name: "TEST 2 with TEST 3's public key", public: RFC[2].public, message: RFC[1].message, signature: RFC[1].signature, valid: false },
  { name: "TEST 2 with S + L (malleable; RFC 8032 5.1.7 requires S < L)", public: RFC[1].public, message: RFC[1].message, signature: malleable, valid: false },
];
const longer = [33, 255, 1023].map((n) => {
  const msg = Buffer.alloc(n);
  for (let i = 0; i < n; i++) msg[i] = (i * 31 + 7) & 0xff;
  return { name: `node:crypto, TEST 1 key, ${n}-byte message`, public: t1.public, message: msg.toString("hex"), signature: sign(t1.secret, msg).toString("hex"), valid: true };
});

// ---------------------------------------------------------------- tokens
const KID = "rfc8032-test1";
const b64u = (b) => Buffer.from(b).toString("base64url");
export function token(seedHex, payload) {
  const bytes = Buffer.from(JSON.stringify(payload), "utf8");
  const msg = Buffer.concat([Buffer.from(`perchlight-keys/v1\n${payload.typ}\n`, "utf8"), bytes]);
  return `PLK1.${b64u(bytes)}.${b64u(sign(seedHex, msg))}`;
}
const NOW = 1772438400; // 2026-03-02T08:00:00Z
const DEV = "3f1c9a0d6b5e4a7f8c2d1e0b9a8f7e6d5c4b3a2918070605040302010f0e0d0c";
const lease = (over = {}) => ({
  typ: "lease",
  lid: "lic_00000000000000test",
  prod: "myapp",
  ed: "pro",
  feat: ["core", "export"],
  iat: NOW,
  nbf: NOW,
  exp: NOW + 30 * 86400,
  dev: DEV,
  renew: NOW + 23 * 86400,
  grace: 7 * 86400,
  ...over,
  kid: over.kid ?? KID,
});
const good = token(t1.secret, lease());
const [, gp, gs] = good.split(".");
const tamperedPayload = Buffer.from(gp, "base64url");
tamperedPayload[tamperedPayload.indexOf("pro") + 1] ^= 1; // "pro" -> "pso"
const tokens = {
  description: "perchlight-keys PLK1 tokens signed with the RFC 8032 TEST 1 key (a published test key). Verify with publicKeys, product, device and now as given.",
  publicKeys: { [KID]: t1.public },
  product: "myapp",
  device: DEV,
  now: NOW + 86400,
  cases: [
    { name: "valid lease", token: good, types: ["lease", "trial"], expect: "Valid" },
    { name: "a changed payload byte", token: `PLK1.${b64u(tamperedPayload)}.${gs}`, types: ["lease"], expect: "BadSignature" },
    { name: "a changed signature byte", token: `PLK1.${gp}.${b64u(Buffer.from(flip(Buffer.from(gs, "base64url").toString("hex"), 10), "hex"))}`, types: ["lease"], expect: "BadSignature" },
    { name: "another device's lease", token: token(t1.secret, lease({ dev: "0".repeat(64) })), types: ["lease"], expect: "WrongDevice" },
    { name: "another product's lease", token: token(t1.secret, lease({ prod: "otherapp" })), types: ["lease"], expect: "WrongProduct" },
    { name: "an unknown kid (signed by TEST 2's key)", token: token(RFC[1].secret, lease({ kid: "k-unknown" })), types: ["lease"], expect: "UnknownKid" },
    { name: "past exp + grace (+ 24 h slack)", token: token(t1.secret, lease({ iat: NOW - 60 * 86400, nbf: NOW - 60 * 86400, exp: NOW - 30 * 86400, renew: NOW - 37 * 86400 })), types: ["lease"], expect: "Expired" },
    { name: "inside the grace period", token: token(t1.secret, lease({ iat: NOW - 33 * 86400, nbf: NOW - 33 * 86400, exp: NOW - 3 * 86400 })), types: ["lease"], expect: "Valid" },
    { name: "issued in the future (clock set back)", token: token(t1.secret, lease({ iat: NOW + 5 * 86400, nbf: NOW + 5 * 86400, exp: NOW + 35 * 86400 })), types: ["lease"], expect: "ClockBehind" },
    { name: "a revocation list offered as a lease", token: token(t1.secret, { typ: "revs", prod: "myapp", iat: NOW, since: 0, lids: [], kids_revoked: [], more: false, next_since: null, kid: KID }), types: ["lease"], expect: "WrongType" },
    {
      name: "valid perpetual licence file",
      token: token(t1.secret, { typ: "lic", lid: "lic_00000000000000test", prod: "myapp", ed: "pro", feat: ["core"], iat: NOW, nbf: NOW, exp: null, grace: 604800, kid: KID }),
      types: ["lic"],
      expect: "Valid",
    },
    { name: "not PLK1", token: `PLK2.${gp}.${gs}`, types: ["lease"], expect: "Malformed" },
  ],
  revocations: {
    token: token(t1.secret, { typ: "revs", prod: "myapp", iat: NOW, since: 0, lids: ["lic_revoked0000000001"], kids_revoked: [], more: false, next_since: null, kid: KID }),
    revoked: "lic_revoked0000000001",
    notRevoked: "lic_00000000000000test",
  },
};

mkdirSync(new URL("../samples/vectors/", import.meta.url), { recursive: true });
writeFileSync(new URL("../samples/vectors/rfc8032.json", import.meta.url), JSON.stringify({ description: "Ed25519 (RFC 8032 pure) verification vectors. hex everywhere.", vectors: [...valid, ...negative, ...longer] }, null, 2) + "\n");
writeFileSync(new URL("../samples/vectors/tokens.json", import.meta.url), JSON.stringify(tokens, null, 2) + "\n");
console.log("wrote samples/vectors/rfc8032.json and samples/vectors/tokens.json");
