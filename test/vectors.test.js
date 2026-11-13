// The committed test vectors (samples/vectors/) must be exactly what the
// Worker produces: the server's signer, given the RFC 8032 TEST 1 key, must
// write the vector's lease byte for byte, and the server's verifier must agree
// with the vectors at the signature level.
import { describe, it, expect } from "vitest";
import { signToken, verifyToken } from "../src/lib/tokens.js";
import { fromHex, toBase64 } from "../src/lib/crypto.js";
import tokens from "../samples/vectors/tokens.json";
import rfc from "../samples/vectors/rfc8032.json";

const seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"; // RFC 8032 TEST 1 (published test key)
const pkcs8 = toBase64(fromHex(`302e020100300506032b657004220420${seed}`));
const env = { SIGNING_KEYS: JSON.stringify({ "rfc8032-test1": pkcs8 }), ACTIVE_KID: "rfc8032-test1" };
const pubs = Object.fromEntries(Object.entries(tokens.publicKeys).map(([k, v]) => [k, fromHex(v)]));

describe("test vectors", () => {
  it("the Worker's signer writes the vector lease byte for byte", async () => {
    const vec = tokens.cases.find((c) => c.name === "valid lease").token;
    const payload = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(vec.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0))));
    const { kid, ...rest } = payload;
    void kid;
    expect(await signToken(env, rest)).toBe(vec);
  });

  it("the Worker's verifier agrees with every vector at the signature level", async () => {
    const sigLevel = { BadSignature: false, UnknownKid: false, Malformed: false };
    for (const c of tokens.cases) {
      const p = await verifyToken(c.token, pubs);
      if (c.expect in sigLevel) expect(p, c.name).toBeNull();
      else expect(p, c.name).not.toBeNull();
    }
  });

  it("WebCrypto agrees with the RFC 8032 vectors file", async () => {
    for (const v of rfc.vectors) {
      const key = await crypto.subtle.importKey("raw", fromHex(v.public), { name: "Ed25519" }, false, ["verify"]);
      let ok;
      try {
        ok = await crypto.subtle.verify({ name: "Ed25519" }, key, fromHex(v.signature), fromHex(v.message));
      } catch {
        ok = false;
      }
      expect(ok, v.name).toBe(v.valid);
    }
  });
});
