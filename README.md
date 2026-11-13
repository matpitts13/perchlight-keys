# perchlight-keys

A free, self-hosted licence-key service that runs on your own Cloudflare account: one Worker, one D1 database, no cron trigger, no runtime dependencies. For indie developers selling desktop apps, games, editor tools or plugins on their own site, Stripe, Lemon Squeezy, Gumroad or itch.io. Part of the [Perchlight](https://perchlight.ravenburst.com) family.

> **Read this first: what licensing can and can't do.** Every check that runs on the buyer's machine can be patched out. Signed licences stop people from **forging** keys and make casual sharing (a key posted in a forum, one copy on ten PCs) stop working. They don't stop a cracker who edits your binary, and no client-side scheme can. perchlight-keys includes no obfuscation or anti-tamper, on purpose.

> **Not for Unity Asset Store packages.** The Asset Store's submission rules forbid DRM and licence checks in store assets. Use perchlight-keys for products sold **outside** the Asset Store (your own site, itch.io, Gumroad and the rest) and for finished games and standalone apps.

- **Issues keys** when a payment webhook arrives (Stripe, Lemon Squeezy, Gumroad), when an itch.io buyer claims one with their download key, or when you issue one by hand. The key is emailed to the buyer (Resend).
- **Signs licence files and device leases** with Ed25519. Your app embeds the public key and checks them **offline**.
- **Activates devices**: a key allows N devices; each activation returns a signed lease bound to that device, valid 30 days with 7 days' grace, renewed now and then. Buyers can free a device themselves.
- **Revokes and expires**: refunds, chargebacks and ended subscriptions end through lease expiry and a signed revocation list.
- **"Resend my keys"** answers the same way whether or not the address bought anything, so nobody can probe who's a customer.

The design is in [docs/SDD.md](docs/SDD.md); the token format and test vectors for other languages are in [docs/FORMAT.md](docs/FORMAT.md).

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/matpitts13/perchlight-keys)

## Set up

You need a Cloudflare account (the free plan is enough), Node 22+, and for email a [Resend](https://resend.com) account with a verified domain.

1. **Signing key.** `npm run keygen` prints a `SIGNING_KEYS` value (secret) and the public key to embed in your app. The private key is printed once and stored nowhere else.
2. **`keys.json`** (repo root): your products, editions and how each store's product ids map to them. See below. `npm test` checks it.
3. **Deploy.**
   ```sh
   npm install
   npx wrangler d1 create perchlight-keys            # copy the database_id into wrangler.mine.jsonc (a copy of wrangler.jsonc, gitignored)
   npx wrangler secret put ADMIN_TOKEN -c wrangler.mine.jsonc         # openssl rand -hex 32
   npx wrangler secret put SIGNING_KEYS -c wrangler.mine.jsonc        # from npm run keygen
   npx wrangler secret put ACTIVE_KID -c wrangler.mine.jsonc
   npx wrangler secret put KEY_LOOKUP_SECRET -c wrangler.mine.jsonc   # openssl rand -hex 32
   npx wrangler secret put KEY_ENC_SECRET -c wrangler.mine.jsonc      # openssl rand -hex 32
   npx wrangler secret put RESEND_API_KEY -c wrangler.mine.jsonc
   npx wrangler d1 migrations apply DB --remote -c wrangler.mine.jsonc
   npx wrangler deploy -c wrangler.mine.jsonc
   ```
   Set `vars.MAIL_FROM` (e.g. `"My Store <keys@example.com>"`) and `vars.PUBLIC_URL` in your `wrangler.mine.jsonc`.
4. **Connect your stores** (any of them):
   - **Stripe:** a webhook endpoint at `https://<host>/v1/webhooks/stripe` for `checkout.session.completed`, `checkout.session.async_payment_succeeded`, `charge.refunded`, `charge.dispute.created`, `customer.subscription.updated` and `.deleted`; `wrangler secret put STRIPE_WEBHOOK_SECRET`. Map by `metadata.perchlight` on the session, by Payment Link id, or (set `STRIPE_SECRET_KEY`, a restricted key with Checkout Sessions read) by price or product id.
   - **Lemon Squeezy:** a webhook at `https://<host>/v1/webhooks/lemonsqueezy` (events `order_created`, `order_refunded`, `subscription_updated`, `subscription_cancelled`, `subscription_resumed`, `subscription_expired`); `LEMONSQUEEZY_WEBHOOK_SECRET`. Map by variant id. For the re-sync, `LEMONSQUEEZY_API_KEY` and `vars.LEMONSQUEEZY_STORE_ID`.
   - **Gumroad:** set `GUMROAD_PING_TOKEN` (22+ random URL-safe characters) and `GUMROAD_ACCESS_TOKEN`, and your Ping URL to `https://<host>/v1/webhooks/gumroad/<GUMROAD_PING_TOKEN>`. Set `vars.GUMROAD_SELLER_ID` too. Map by product id.
   - **itch.io:** `ITCH_API_KEY` (scope `game:view:purchases`); map your game id; link buyers to `https://<host>/claim/itch`.
5. **Check it.** `curl -H "Authorization: Bearer $ADMIN_TOKEN" https://<host>/api/config` lists any problem, then issue a test key with `POST /api/licenses`.

## `keys.json`

```jsonc
{
  "products": {
    "myapp": {
      "name": "My App",
      "prefix": "MYAPP",                       // shown at the start of keys; 1-12 A-Z/0-9
      "editions": { "standard": { "features": ["core"] }, "pro": { "features": ["core", "export"] } },
      "defaultEdition": "standard",
      "deviceLimit": 3,
      "duration": "perpetual",                 // or a number of days
      "trialDays": 14,                         // 0 = no trial
      "activation": "device",                  // or "none": licence files only, no device limit, no revocation
      "leaseDays": 30, "renewAfterDays": 23, "graceDays": 7,
      "map": {
        "stripe": { "price_123": "pro", "plink_456": "standard", "price_up": { "edition": "pro", "upgrade": true } },
        "lemonsqueezy": { "98765": "standard" },
        "gumroad": { "abcDEF==": "standard" },
        "itch": { "1234567": "standard" }
      }
    }
  },
  "refunds": { "stripe": "full-only", "lemonsqueezy": "full-only", "gumroad": "full-only" }, // or "any" / "never" (flag only)
  "disputes": "revoke"                                                                         // or "flag"
}
```

An unknown mapping stores the event as `unmapped` (no licence); fix the mapping, deploy, and *Re-process* it. An `upgrade` mapping changes the edition of the buyer's existing licence for that product instead of issuing a new one.

## In your app

1. Compute a device id: `SHA-256(appSalt || platform id)` as hex (the C# sample has `DeviceId.Compute`; on Unity use `SystemInfo.deviceUniqueIdentifier`).
2. On first run, `POST /v1/activate {key, product, device, label}` and store the returned `lease`. Over the limit you get `409 device_limit` with the activated devices (labels, last-seen dates and an id to free one with `POST /v1/deactivate {key, activation}`).
3. On every launch, verify the lease **offline** with the embedded public key(s): signature, `typ`, `prod`, `dev`, and `nbf <= now <= exp + grace` (24 hours' slack). No network call.
4. After `renew`, call `POST /v1/renew {lease}` in the background; on failure keep using the lease until `exp + grace`. Back off on `429` and `5xx`.
5. Optional: `GET /v1/revocations?product=&since=` for a signed list of revoked licence ids, if you want revocation faster than lease expiry.

**Leases are what keep it free.** An app that calls home on every launch costs a request per launch; with 30-day leases a copy calls about once every 3 weeks.

| Route | What |
|---|---|
| `POST /v1/activate` `{key, product, device, label?}` | `200 {lease, server_time, renew_after, expires}` · `404 invalid_key` · `403 revoked` / `expired` · `409 device_limit {devices}` · `429` |
| `POST /v1/renew` `{lease}` or `{key, device}` | a fresh lease (picks up edition changes); `403 revoked` / `not_activated` |
| `POST /v1/deactivate` `{key, device}` or `{key, activation}` | frees the slot |
| `POST /v1/license` `{key}` | the licence file, for `activation: "none"` products |
| `POST /v1/trial` `{product, device}` | a trial lease; one per product and device |
| `GET /v1/revocations?product=&since=` | a signed `revs` token, `Cache-Control: max-age=3600` |
| `GET /v1/keys` | public keys and the active `kid` |
| `POST /v1/resend` `{email}` | always `202 {"ok":true}` |
| `GET/POST /claim/itch` | the itch.io claim page |

`invalid_key` is the same answer for a mistyped key, an unknown key and another product's key.

### C# sample (.NET, Unity)

`samples/csharp/PerchlightKeys/` has `LicenseVerifier` (the offline checks above, plus revocation lists and a clock-rewind check), `DeviceId`, a small JSON reader, and `Ed25519` (verify only). **The Ed25519 code is a port of [TweetNaCl](https://tweetnacl.cr.yp.to/) 20140427 (public domain, by Bernstein, van Gastel, Janssen, Lange, Schwabe and Smetsers)**, function by function, with an added `S < L` check; see [NOTICE](NOTICE). It passes the RFC 8032 section 7.1 vectors and the token vectors: `npm run test:csharp` (needs the .NET SDK). No NuGet packages.

## Key rotation

- **Signing keys:** add a new kid to `SIGNING_KEYS`, ship app builds that embed both public keys, then switch `ACTIVE_KID`. New leases use the new key; old ones expire within 30 days; `renew` accepts a lease signed by any configured kid.
- **Compromise:** remove the kid from `SIGNING_KEYS`, add it to `vars.REVOKED_KIDS` (listed in `/v1/keys` and every revocation list), ship builds that drop it, and buyers renew onto the new key. Copies of your app that never update keep trusting the leaked key, and it can mint licences for them. That's the limit of offline signing.
- **`KEY_LOOKUP_SECRET` / `KEY_ENC_SECRET`:** set them to JSON `{"old": "...", "new": "..."}` with `KEY_LOOKUP_ACTIVE` / `KEY_ENC_ACTIVE` = `new`, then call `POST /api/rekey` until `more` is false (25 licences a call). Keys keep working throughout. If `KEY_ENC_SECRET` is ever lost, `RESEND_REISSUE=1` lets "resend my keys" replace keys it can't decrypt.

## No cron trigger: how housekeeping runs

On any request, if the last sweep is over 5 minutes old, one request claims it (a conditional `UPDATE`) and, after answering: carries out the desktop app's requested actions, sends up to 5 due email retries (1 / 5 / 30 min, 2 h, 12 h), deletes expired rate rows and events older than 90 days (200 at a time), and drops refunds whose order never arrived after 7 days. A deployment with no traffic does nothing and needs nothing; an email retry waits for the next request. `POST /api/housekeeping` runs one now.

## Admin API

`Authorization: Bearer <ADMIN_TOKEN>` (constant-time compare, 16+ characters; `/api/*` answers `503` until it's set).

| Endpoint | What |
|---|---|
| `GET /api/config` | Problems with `keys.json` and the secrets; which stores and email are set up |
| `GET /api/licenses?email=&product=&status=&before=&limit=`, `GET /api/licenses/:id` | Licences (never keys), one licence with its activations |
| `POST /api/licenses` `{product, email, edition?, name?, source?, source_ref?, expires_days?, perpetual?, device_limit?, notes?, send_email?}` | Issue a key (returned once, and emailed). With `source` + `source_ref` it's idempotent. |
| `POST /api/licenses/:id/reveal` | Decrypt one key |
| `POST /api/licenses/:id/revoke` `{reason}` · `/unrevoke` · `/extend` `{days}` or `{perpetual: true}` · `/edition` `{edition}` · `/resend` `{email?}` · `/free-all` | Owner actions (`resend` to a new address also changes the licence's email) |
| `POST /api/activations/:id/free` | Free one device |
| `GET /api/events?result=`, `POST /api/events/:provider/:event_id/reprocess` | Webhook events; re-process `unmapped`, `error` or `dropped` |
| `GET /api/deliveries?status=`, `POST /api/deliveries/:id/retry` | Emails |
| `POST /api/resync/lemonsqueezy` `{days: 7}` · `POST /api/resync/gumroad` `{sale_id}` | Issue anything a missed webhook didn't |
| `POST /api/rekey`, `POST /api/housekeeping`, `GET /api/footprint` | Rotation, housekeeping now, measured counts |

**Importing existing buyers** (Lemon Squeezy or Gumroad native keys aren't accepted): `ADMIN_TOKEN=... node scripts/import.mjs orders.csv https://<host>` with columns `email,product,edition,source,order_id,name`. Each order gets one perchlight key, emailed; running it again issues nothing new, and a later webhook for an imported order is a duplicate. `--dry-run` checks the file, `--no-email` skips the emails.

## Perchlight desktop app

`perchlight/perchlight.json` adds screens for Products, Licences (*Revoke*, *Unrevoke*, *Extend 30 / 365 days*, *Re-send email*, *Free all devices*; notes editable), Activations (*Free device*), Webhook events (*Re-process*) and Emails (*Try again*). Replace `YOUR-D1-DATABASE-ID`. The app's actions set a requested-action column that the next sweep carries out (within about 5 minutes of traffic). Keys never appear on these screens; *Issue key* and *Reveal* go through the admin API (the v1 screen format can't call an API).

## Security notes

- Keys are never stored in plain text: `HMAC-SHA256(KEY_LOOKUP_SECRET, key)` for lookup (one indexed read, then a constant-time re-compare) and `AES-GCM(KEY_ENC_SECRET, key)` bound to the licence id for re-sending. A leaked D1 export alone exposes no key. Private signing keys live only in Worker secrets.
- Every secret comparison (admin token, key HMACs, Stripe and Lemon Squeezy signatures, the Gumroad URL token) hashes both sides and uses `timingSafeEqual`.
- Webhooks: the signature is checked first; Stripe's timestamp must be within 300 s; then one D1 batch claims the event (`(provider, event_id)` unique) and issues the licence (`(source, source_ref)` unique), so a replayed or concurrent delivery issues one licence and one email. Lemon Squeezy documents no timestamp or delivery id, so replay protection there is the event id (event, object id, `updated_at`) plus one licence per order. Gumroad has no signatures: the secret URL token plus an API lookup of every sale means a forged ping can't issue anything.
- "Resend my keys" answers `202` with the same body and headers for everyone and does all the work after answering; limits: 1 per 15 minutes and 5 a day per address, 10 an hour per IP, `RESEND_DAILY_CAP` a day overall. It emails only the address on file.
- Rate limits: 20 a minute per IP and per key on the licensing routes (isolate memory), D1-backed limits on resend and the itch.io claim. Request bodies are capped (8 KB public, 512 KB webhooks). SQL is always parameterised. Each request stays within 45 subrequests.

## Privacy

Buyers' email addresses and names (from the store) are stored with their licences. Device ids are hashes the app computes; the server never sees hardware ids. IP addresses are never stored: rate-limit rows hold an HMAC with a daily salt and expire after 48 hours. Webhook bodies aren't stored, only their SHA-256 and what re-processing needs. Logs never print keys, tokens or addresses.

## What it costs

Nothing inside Workers Free, D1 Free and Resend's free tier. Measured in `npm test` for a simulated day of the SDD's example store (30 sales, 30 activations, 500 renewals, 10 resends, 3 trials, with lazy housekeeping): **574 Worker requests (0.6% of 100,000), 1,308 D1 rows written (1.3%), about 5,800 rows read (0.1% of 5 million), 40 emails.** At most 45 subrequests per invocation. With 30-day leases, renewals alone would reach the request limit at about 2 million installed copies. `GET /api/footprint` shows your own counts (a lower bound: an isolate evicted before its 15-minute flush loses its counts). Bundle: 109 KiB (30 KiB gzipped).

## Tested, and not tested

- **`npm test`: 104 tests** with vitest and the Workers pool (local D1, a fake network, signing keys generated fresh each run). They cover:
  - crypto: Ed25519 in workerd's WebCrypto (generate, sign, verify, PKCS#8 import, public key from the JWK export, RFC 8032 TEST 1 byte for byte), domain separation, a `revs` relabelled as `lic` refused, rotation, AES-GCM with kid and AAD, constant-time compare
  - keys: format, 128 random bits, forgiving input, every single-symbol typo caught by the check symbol
  - licensing: lease contents, device limit (409 with labels only, freeing by device or activation id, re-activation uses no slot, 5 concurrent activations for 2 slots), `invalid_key` identical for typo / unknown / other product, revoked / expired, lease capped at licence expiry, rate limit, body cap, renew by lease or key (last-seen at most daily, expired lease renews, forged / freed refused), revoke then renew `403` plus a signed revocation list, edition change on renew, rotation on renew, churn flag, offline-only licence files, trials
  - webhooks: Stripe (one licence and one email, duplicate event, 5 concurrent deliveries, a second event for the same session, one changed byte, 6-minute-old signature, several `v1`, unpaid then async success, line-item and Payment Link mapping, a line-item 5xx answering 503, unmapped then re-process, full refund with notice, partial refund flag, dispute, subscription updated / deleted / renewed, refund before its order, upgrade, D1 down 503, not configured, too large); Lemon Squeezy (issue, replay, bad signature, `license_key_created` ignored, full and partial refunds, cancel / resume / expire, unpaid, 7-day re-sync idempotent); Gumroad (lookup decides, not the ping body; repeat ping; wrong token with no lookup; other seller; unknown sale; later refund; admin re-sync; no access token; outage 503 with one call)
  - buyers: resend (same status, body and headers for buyer and non-buyer; one email listing every key; 1 per 15 min, 5 a day, 10 an hour per IP, global cap; no address or IP in rate rows); itch.io claim (form, claim, re-claim shows the same key and re-sends to the first address, made-up key, another game's key, IP and per-key limits)
  - admin: auth (401 / 503), the constant-time helper used for admin, Stripe, Lemon Squeezy, Gumroad and key HMACs, issue / reveal / never listed, validation, every owner action, desktop requested actions and *Re-process* via the sweep, the manifest's tables and columns exist, email retries (unknown not retried, 429 retried at 1 min, failed after 5 retries, *Try again*), email not configured, no plain-text key or private key in any table, re-key rotation, the import script (CSV quoting, idempotent re-run, later webhook a duplicate, stops after repeated failures), the shipped `keys.json`, the simulated day's footprint
  - review regressions: a failed re-process (admin or sweep) goes back to `error`, a stuck `processing` claim is released after 10 minutes, a broken pending event doesn't fail its order's webhook; extending a perpetual licence leaves it perpetual; a reactivation without an end date keeps the expiry (Stripe, Lemon Squeezy `subscription_updated` renewals); random paths can't create metric names; resend and trial floods from one IP can't spend D1 writes; sweep queries use indexes; a Lemon Squeezy event named only in the header
  - vectors: the Worker's signer writes `samples/vectors/tokens.json`'s lease byte for byte; WebCrypto agrees with `rfc8032.json`
- **C# sample: 31 checks passed** (`dotnet run --project samples/csharp/Tests`, .NET 8 SDK, 2026-11-12): RFC 8032 TEST 1-3, five negatives including `S + L`, three longer messages; the SDD's list (valid lease accepted; a changed payload or signature byte, another device, another product, an unknown kid and past `exp + grace` rejected), grace period, clock rewind, wrong type, perpetual licence file, revoked kid, revocation lists. Not yet run inside Unity.
- **`wrangler deploy --dry-run`** bundles; `npm audit --audit-level=high` clean.
- **Not tested on a real Cloudflare account yet** (free, but needs you): deploying; Stripe test mode with `stripe trigger` / `stripe listen`; a Lemon Squeezy test-mode store; a $0 Gumroad product's ping; a creator-generated itch.io download key against the real API (the response fields of `download_keys` couldn't be checked); Resend delivering real email; Ed25519 CPU time on production workerd; whether D1 calls count as subrequests (assumed yes); the footprint over a real day; the Unity sample in the Unity editor.
- **Not tested, because it costs money or needs a card:** Stripe live mode (test-mode signatures have the same form); Lemon Squeezy live payments; Gumroad paid sales; itch.io paid purchases; SES, Mailgun and Postmark (not wired in v0.1); Workers Paid; Cloudflare Email Service to arbitrary addresses.

## License

MIT. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Not affiliated with Cloudflare, Stripe, Lemon Squeezy, Gumroad, itch.io, Resend or Unity.
