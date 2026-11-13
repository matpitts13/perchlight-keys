import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";

const root = path.dirname(fileURLToPath(import.meta.url));

// Signing keys and secrets are generated fresh for every test run: no key
// material is ever committed.
const pkcs8 = () => crypto.generateKeyPairSync("ed25519").privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
const rnd = (n = 24) => crypto.randomBytes(n).toString("base64url");

export default defineConfig(async () => {
  const migrations = await readD1Migrations(path.join(root, "migrations"));
  return {
    plugins: [
      cloudflareTest({
        main: "./test/worker.js",
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: {
          bindings: {
            TEST_MIGRATIONS: migrations,
            ADMIN_TOKEN: "test-admin-token-0123456789",
            SIGNING_KEYS: JSON.stringify({ k1: pkcs8(), k2: pkcs8() }),
            ACTIVE_KID: "k1",
            KEY_LOOKUP_SECRET: rnd(),
            KEY_ENC_SECRET: rnd(),
            IP_SALT: rnd(),
            STRIPE_WEBHOOK_SECRET: "whsec_test_secret_0123456789",
            LEMONSQUEEZY_WEBHOOK_SECRET: "ls-signing-secret-0123456789",
            GUMROAD_PING_TOKEN: "gumroad-ping-token-0123456789abc",
            GUMROAD_ACCESS_TOKEN: "gumroad-access-token",
            GUMROAD_SELLER_ID: "seller-1",
            ITCH_API_KEY: "itch-api-key",
            LEMONSQUEEZY_API_KEY: "ls-api-key",
            LEMONSQUEEZY_STORE_ID: "1",
            RESEND_API_KEY: "re_test_key",
            MAIL_FROM: "Store <keys@example.com>",
            PUBLIC_URL: "https://keys.test",
          },
        },
      }),
    ],
    test: {
      setupFiles: ["./test/apply-migrations.js"],
      include: ["test/**/*.test.js"],
      testTimeout: 30_000,
    },
  };
});
