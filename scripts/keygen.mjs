#!/usr/bin/env node
// Makes an Ed25519 signing key pair locally. Prints:
//   - the SIGNING_KEYS JSON to paste into `npx wrangler secret put SIGNING_KEYS`
//   - the public key (base64url and hex) to embed in your app
// The private key is printed once to your terminal and stored nowhere.
//
//   node scripts/keygen.mjs [kid]        (default kid: k<year>)
import crypto from "node:crypto";

const kid = process.argv[2] ?? `k${new Date().getUTCFullYear()}`;
if (!/^[A-Za-z0-9_-]{1,32}$/.test(kid)) {
  console.error("kid: 1-32 letters, digits, _ or -");
  process.exit(2);
}
const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
const pkcs8 = privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
const raw = publicKey.export({ format: "der", type: "spki" }).subarray(-32);

console.log("SIGNING_KEYS (secret; add to any existing kids when rotating):");
console.log(JSON.stringify({ [kid]: pkcs8 }));
console.log(`\nACTIVE_KID: ${kid}`);
console.log("\nPublic key to embed in your app (not secret):");
console.log(`  kid:       ${kid}`);
console.log(`  base64url: ${raw.toString("base64url")}`);
console.log(`  hex:       ${raw.toString("hex")}`);
