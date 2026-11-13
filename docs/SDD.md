# SDD: perchlight-keys

**Version:** 0.1
**Date:** 2026-11-12
**Status:** Approved 2026-11-12; v0.1 built. All 8 open questions decided as recommended (see "Decisions").

## Summary

A free, self-hosted licence-key service that runs on your own Cloudflare account (one Worker, one D1 database, no cron trigger). It's for indie developers selling desktop apps, games, editor tools or plugins on their own site, Stripe, Lemon Squeezy, Gumroad or itch.io. It does four things:

1. **Issues keys** when a payment webhook arrives (Stripe, Lemon Squeezy, Gumroad), when an itch.io buyer claims one with their download key, or when you issue one by hand from the Perchlight desktop app or the admin API. The key is emailed to the buyer.
2. **Signs licence files** with Ed25519. Your app embeds the public key and checks the file **offline**, with no call home.
3. **Activates devices** (optional, online): a key allows N devices; each activation returns a signed, device-bound **lease** that the app re-checks offline and renews now and then. Buyers can free a device themselves.
4. **Revokes and expires**: refunds, chargebacks, cancelled subscriptions and trials end through lease expiry and a signed revocation list.

Buyers can ask for their keys to be re-sent by email. The answer is the same whether or not the address bought anything, so nobody can probe who's a customer. Part of the Perchlight family: the desktop app gets screens for products, licences, activations, webhook events and failed emails.

**Not for Unity Asset Store packages.** The Asset Store's submission rules forbid DRM and licence checks in store assets. perchlight-keys is for products sold **outside** the Asset Store (your own site, itch.io, Gumroad and the rest) and for finished games or standalone apps. The README and the Unity sample say so at the top.

**Threat model, plainly:** every check that runs on the buyer's machine can be patched out. Signing stops people from **forging** keys and makes casual sharing (posting a key in a forum, putting one copy on ten PCs) stop working. It doesn't stop a cracker who edits your binary, and no client-side scheme can. The README says this before anything else.

## Why

- Hosted licensing (Keygen, Cryptlex, LicenseSpring) charges per month or per licence once you're past a small free tier. Their current prices weren't checked for this draft.
- Lemon Squeezy and Gumroad each have their own licence-key API, but each works only for sales in that store, needs a call home, and offers no offline signed file. If you sell in two places, you end up with two key systems.
- With perchlight-keys you get one key system across stores, offline verification, and no subscription. Your buyers' data stays in your own account.

## Requirements

### Must have

- **Products** in `keys.json`: id, name, editions (for example `standard`, `pro`), features, device limit, licence length (`perpetual` or a number of days), trial length, and how each payment provider's product or price ids map to an edition.
- **Licence keys:** 128 random bits, shown as `PROD-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-X` (Crockford base32 plus a check character, so typos are caught before any network call). They're stored as an HMAC for lookup and AES-GCM ciphertext for re-sending, **never in plain text** (see "Storage of keys").
- **Signed licence files and leases:** Ed25519 through WebCrypto, with a key id (`kid`) and domain separation (format below). Verifying one needs only the public key.
- **Activation:** `POST /v1/activate` with a key, the product and a device id (a salted hash the app computes; the server never sees hardware ids). It returns a lease bound to that device, valid for 30 days by default, with a 7-day offline grace period after that. Re-activating the same device takes no new slot. Over the limit, the answer is `409 device_limit` with the list of activated devices (labels and last-seen dates only).
- **Deactivation:** `POST /v1/deactivate` (the key plus a device id) frees a slot. Self-service for the buyer from the app, and also from the admin API and the desktop app.
- **Revocation:** refunds and chargebacks (from webhooks, configurable per provider) and manual revocation. Revoked licences can't activate or renew. `GET /v1/revocations?product=&since=` serves a signed list of revoked licence ids for apps that want to check more often than once a lease.
- **Expiry and trials:** `exp` in the licence file and the lease; subscriptions follow provider events. A trial is a server-issued lease (`POST /v1/trial`), one per product per device id.
- **Payment webhooks:** Stripe, Lemon Squeezy and Gumroad, each checked by that provider's scheme (see "Payment providers"), **idempotent** (one licence per provider event and per order), protected against replays, and answering `2xx` only after the licence is stored.
- **itch.io claim:** itch.io has no purchase webhook, so a buyer pastes their itch.io download key on a claim page and the Worker checks it against itch.io's server-side API.
- **Manual issue** through the admin API (`ADMIN_TOKEN`), and the *Issue key* action in the desktop app (`perchlight/perchlight.json`).
- **Email delivery** of keys, using perchlight-list's mail module (Resend, SES, Mailgun, Postmark; see "Email"). Every send is claimed first, then sent, and retried on failure.
- **Resend my keys** (`POST /v1/resend`): the same `202` answer and the same timing for every address, rate-limited, emailing only the address on file.
- **Constant-time comparisons** for every secret (admin token, HMACs, webhook signatures).
- **Rate limits** on activate, trial, resend and claim (see "Abuse").
- **No cron trigger.** Housekeeping and email retries run lazily on incoming requests (decision 3).
- **Signing keys in Worker secrets**, with rotation (see "Key rotation").
- **Client verifier samples:** C# (Unity, .NET), plus a short spec with test vectors so other languages can be added. The samples include no licensed or obfuscated code, because the threat model says obfuscation isn't the point.
- **Footprint stated in numbers** and `GET /api/footprint`, as the rest of the family. Deploy to Cloudflare button, `npm test` (vitest with `@cloudflare/vitest-pool-workers`), README, MIT licence, no runtime dependencies, graphify on creation, CI on GitHub Actions' free tier.

### Should have

- **Offline-only mode** per product (`activation: "none"`): the licence file alone, no device limit, no revocation. The README is honest about what that gives up.
- **Turnstile** on the resend and claim forms (free, optional).
- **Godot (GDScript/C#) and C++ verifier samples**, and a hosted single-page "Manage my devices" form for buyers.
- **Seat transfer:** the buyer frees all devices, at most once every 30 days without admin help.
- **An outgoing heartbeat** (`HEARTBEAT_URL`) to perchlight-hooks after each successful housekeeping run.

### Out of scope (v0.1), with reasons

- **Unity Asset Store packages.** DRM in store assets is forbidden by Asset Store policy (see Summary).
- **Code obfuscation, anti-tamper, anti-debugging.** These don't fit the threat model, and they're a separate product.
- **Floating or concurrent-seat licences** ("5 people at once"). They need frequent check-ins (heartbeats), which cost Worker requests per running copy a day. That doesn't fit 100,000 requests a day for a popular app.
- **Usage metering or pay-per-use.** That's a different product (Metronome, Stripe Billing).
- **Hosting checkout or taking payments.** The stores do that. This tool only listens to them.
- **Paddle, FastSpring, Steam, Epic, app stores.** Paddle and FastSpring could be added later. Steam and the console stores have their own entitlements.
- **Customer accounts with passwords.** Self-service is key-based (deactivate) or email-based (resend).
- **Sending email through Cloudflare `send_email` to buyers.** On Free it reaches only verified addresses. Cloudflare Email Service for arbitrary addresses needs Workers Paid (as noted in the hooks SDD).
- **Durable Objects in v0.1.** Nothing has to happen at an exact time: leases expire on the client, and retries can wait for the next request (decision 3).

## Technical design

### Pieces

```
Stores                                 Your Cloudflare account
â”€â”€â”€â”€â”€â”€                                 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
Stripe / Lemon Squeezy â”€â”€POST /v1/webhooks/<provider>â”€â”€â–¶ Worker
Gumroad â”€â”€POST /v1/webhooks/gumroad/<token>â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–¶   â”œâ”€ webhooks: verify â†’ dedupe â†’ issue â†’ email
                                                          â”œâ”€ claim (itch.io) â”€â”€fetchâ”€â”€â–¶ api.itch.io
Your app â”€â”€/v1/activate, /deactivate, /trial,â”€â”€â”€â”€â”€â”€â”€â”€â”€â–¶   â”œâ”€ licensing API (public, rate-limited)
           /revocations                                   â”œâ”€ resend (constant answer, work in waitUntil)
Buyer's browser â”€â”€/v1/resend, /claimâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–¶   â”œâ”€ admin API (ADMIN_TOKEN)
You / Perchlight app â”€â”€/api/* â”€ D1 (direct reads) â”€â”€â”€â”€â–¶   â”œâ”€ lazy housekeeping + email retry (throttled)
                                                          â”œâ”€â”€â–¶ D1: products, licenses, activations,
                                                          â”‚        webhook_events, deliveries, rate, state
                                                          â””â”€â”€â–¶ Resend / SES / Mailgun / Postmark
```

### What's shared with the family

Copied, not imported (to keep zero runtime dependencies), with a comment naming the source:

| From | What | Changes for keys |
|---|---|---|
| perchlight-list `src/` mail providers | Resend, SES, Mailgun, Postmark send, idempotency keys (Resend), `unknown` on unclear outcomes | transactional sends only; no list or unsubscribe logic |
| perchlight-forms `src/lib/deliveries.js` | claim-then-send, retries 1 / 5 / 30 min, 2 h, 12 h | the retries run lazily (below) |
| perchlight-forms `src/lib/budget.js` | subrequest budget (45 of 50) | one budget per request |
| perchlight-status `src/lib/crypto.js` | `hmacHex()`, constant-time compare | plus Ed25519 and AES-GCM helpers |
| perchlight-hooks signature table | the Stripe `t=â€¦,v1=â€¦` check, 300 s tolerance | plus Lemon Squeezy |
| perchlight-updates `admin.js` | `Authorization: Bearer <ADMIN_TOKEN>` | â€” |

### Key and file formats

**Licence key** (what the buyer types or pastes): `<PREFIX>-` plus 26 Crockford base32 characters (128 bits from `crypto.getRandomValues`), in groups of 5, plus one check character (mod 37). The prefix is a per-product hint, such as `MYAPP`, and isn't secret. The key alone grants nothing offline; it's exchanged for a signed file.

**Signed token** (used for the licence file, the lease, the trial lease and the revocation list):

```
PLK1.<base64url(payload JSON)>.<base64url(Ed25519 signature)>
signature = Ed25519(private[kid], "perchlight-keys/v1\n" || type || "\n" || payloadBytes)
```

The payload is `{ "typ": "lic"|"lease"|"trial"|"revs", "kid", "lid" (licence id, not the key), "prod", "ed", "feat": [...], "iat", "nbf", "exp" (null = perpetual), "dev" (device-id hash, leases only), "renew" (renew-after time, leases), "grace" (seconds), "sub" (an optional display name the buyer chose; never the email) }`.

- **Domain separation** (the prefix plus the `typ`) means a revocation list can't be passed off as a licence, and a v1 signature can't be reused for a later format.
- **What the app checks offline:** the signature against an embedded public key with a matching `kid`, then `typ`, `prod`, `nbf â‰¤ now â‰¤ exp + grace`, and that `dev` equals its own device-id hash. The clock can be set back, which the threat model accepts. The samples refuse a lease whose `iat` is later than the newest time the app has seen, which catches clock rewinds when it's cheap to do so.
- **Size:** about 300â€“450 bytes, small enough to paste or to store in `PlayerPrefs` or a file.
- **Device id:** `SHA-256(appSalt || platform id)`, computed by the app. The samples use OS machine ids where available. The server stores only this hash. It can be spoofed, which is accepted.

### Storage of keys

- `licenses.key_hmac = HMAC-SHA256(KEY_LOOKUP_SECRET, normalised key)`, with a unique index. A lookup is one indexed read, and the HMAC is re-compared in constant time.
- `licenses.key_enc = AES-GCM(KEY_ENC_SECRET, key)`, so the original key can be re-sent. If D1 alone leaks (an export, the desktop app's copy), the keys don't leak with it.
- Both secrets are Worker secrets. Losing `KEY_ENC_SECRET` means resends issue a fresh key, which a flag allows (decision 2).

### Payment providers

| Provider | How it's verified | Replay and idempotency | Events used | Free to test? |
|---|---|---|---|---|
| **Stripe** | `Stripe-Signature: t=â€¦,v1=â€¦`, HMAC-SHA256 hex over `<t>.<raw body>`, any matching `v1` passes, `t` within 300 s ([Stripe signatures](https://docs.stripe.com/webhooks/signature)) | timestamp window, plus a unique `(stripe, event.id)` row; licence unique on `(stripe, checkout session id)` | `checkout.session.completed` (`payment_status = paid`), `checkout.session.async_payment_succeeded`, `charge.refunded`, `charge.dispute.created`, `customer.subscription.deleted` / `.updated` | **yes**, test mode and `stripe trigger`; live mode **Not tested** |
| **Lemon Squeezy** | `X-Signature`: HMAC-SHA256 **hex** of the raw body with your signing secret; event in `X-Event-Name` and `meta.event_name` ([signing](https://docs.lemonsqueezy.com/help/webhooks/signing-requests), [requests](https://docs.lemonsqueezy.com/help/webhooks/webhook-requests), checked 2026-11-12) | **no timestamp and no delivery id are documented.** Idempotency comes from a unique `(lemonsqueezy, event_name:data.id)` row plus a licence unique on order id; a replayed `order_created` can't issue twice. Retries: up to 3 (5, 25, 125 s). | `order_created`, `order_refunded`, `subscription_expired` / `_cancelled` / `_resumed` | test mode (free; not confirmed it needs no payout details) |
| **Gumroad** | **no signature scheme found in the docs.** The Ping URL has a secret path token (`/v1/webhooks/gumroad/<128-bit token>`), and the Worker then **looks the sale up** with `GET https://api.gumroad.com/v2/sales/<sale_id>` using `GUMROAD_ACCESS_TOKEN`, checking `seller_id`, `product_id` and the refund state. The ping body is used only for the sale id. | unique `(gumroad, sale_id)`; the API lookup makes forged or replayed pings harmless | sale ping; refunds through the lookup when a later ping or admin re-sync arrives | a $0 test product is likely free (not confirmed); paid sales **Not tested** |
| **itch.io** | **no purchase webhook.** Claim page: the buyer pastes the download key (or the download URL that contains it); the Worker calls `GET /games/<GAME_ID>/download_keys?download_key=â€¦` with `ITCH_API_KEY` (scope `game:view:purchases`) ([itch.io server-side API](https://itch.io/docs/api/serverside), checked 2026-11-12) | unique `(itch, download key id)`, so a claim is idempotent and the same key is re-shown and re-emailed | n/a (refunds aren't seen; revoke by hand) | **yes**, itch.io lets creators generate download keys for free |

- **Never by email lookup** for itch.io claims: itch.io's docs warn that email lookup needs proof the person owns the address. The claim takes the download key only, and asks for an email address to deliver to (it's stored as the licence email).
- **Order of work in a webhook:** verify the signature (constant time) â†’ one D1 batch: `INSERT â€¦ ON CONFLICT DO NOTHING` into `webhook_events`, insert the licence if the order is new, insert the delivery claim â†’ answer `200` â†’ send the email in `waitUntil`. A duplicate event answers `200` with no new rows. A D1 failure answers `503`, so the provider retries.
- **Out-of-order events** (a refund before the licence was created): the event is stored as `pending_target` and applied when the order arrives, or after 7 days it's dropped and flagged in the app.
- **Mapping:** a Stripe price or product id, Lemon Squeezy variant id, Gumroad product id or itch.io game id maps to a product and edition in `keys.json`. An unknown mapping stores the event as `unmapped` (no licence) and shows it in the app.

### API

| Route | Who | What |
|---|---|---|
| `POST /v1/activate` `{key, product, device, label?}` | app | `200 {lease}` Â· `404 invalid_key` Â· `403 revoked` / `expired` Â· `409 device_limit {devices}` Â· `429` |
| `POST /v1/renew` `{lease}` or `{key, device}` | app | A fresh lease if the licence is still valid and the device is still active. If the last-seen date is under 1 day old, it isn't written again. |
| `POST /v1/deactivate` `{key, device}` | app / buyer | frees the slot |
| `POST /v1/license` `{key}` | app (optional) | The licence file for offline-only products. |
| `POST /v1/trial` `{product, device}` | app | A trial lease; one per (product, device). |
| `GET /v1/revocations?product=&since=` | app | A signed `revs` token. Cacheable (`Cache-Control: max-age=3600`). |
| `GET /v1/keys` | anyone | Public keys `{kid: base64}` and the active `kid`, for apps that fetch new keys during rotation. |
| `POST /v1/resend` `{email}` | buyer | Always `202 {"ok":true}`. The work happens in `waitUntil`. |
| `GET/POST /claim/itch` | buyer | The claim form and its handler. |
| `POST /v1/webhooks/{stripe,lemonsqueezy}` Â· `/v1/webhooks/gumroad/:token` | stores | above |
| `/api/*` | `ADMIN_TOKEN` | Licences (issue, revoke, unrevoke, extend, change edition, re-send), activations (free one, free all), events (re-process), deliveries (retry), footprint. |

Errors are JSON `{error, message}`. `invalid_key` is returned both for a well-formed key that isn't on file and for a bad check character, so the answer can't be used to learn which keys exist.

### Resend without enumeration

- The answer is always `202`, with the same body and headers, and the lookup and send run in `waitUntil` so timing doesn't leak anything. Throttle hits answer the same way.
- Limits: per normalised email, 1 send every 15 minutes and 5 a day; per IP hash, 10 requests an hour; globally, `RESEND_DAILY_CAP` (default 200) to protect the mail provider's free quota. Over a limit, nothing is sent and the answer doesn't change.
- The email goes **only** to the address on the licence. It lists every licence for that address, with keys (decrypted) and links to manage devices. Nothing is shown in the browser.
- Optional Turnstile (Should). The README notes that a buyer who changed email addresses needs you (admin re-send to a new address).

### Abuse and rate limits

- **Keys can't be guessed** (128 bits). Rate limits stop people from wasting your quota, not from guessing.
- **Counters:** isolate memory first (activate, renew, trial: per IP hash and per key, for example 20 a minute), then D1 `rate` rows only for resend and claim (their limits must hold across isolates). The IP hash is `HMAC(IP_SALT, ip)` with a daily salt, kept 48 hours. The optional Workers rate-limiting binding is commented out, as in perchlight-hooks (its availability on Free couldn't be confirmed).
- **Key sharing signals:** activations of one key from many devices are capped by the device limit. Deactivate-then-activate churn above 10 a month flags the licence in the app (no automatic action).
- **Trials:** one per device id. Anyone can reset a device id, as the threat model accepts.
- **Flooding:** every request counts toward the 100,000 Worker requests a day, as in hooks. Leases mean apps call rarely (see "Footprint"), and the samples back off on `429` or `5xx` and stay inside the offline grace period. If the Worker is unreachable, licensed apps keep working until `exp + grace`.

### Key rotation

- Secrets: `SIGNING_KEYS` (JSON `{kid: base64 PKCS#8 Ed25519 private key}`), `ACTIVE_KID`. `npm run keygen` makes a pair locally and prints the public key to embed. The private key never goes into D1, the config or logs.
- **Routine rotation:** add a new `kid`, ship app updates that embed both public keys, then switch `ACTIVE_KID`. New leases use the new key, and old leases expire within 30 days. Old licence files stay valid while apps still trust the old `kid`.
- **Compromise:** remove the `kid` from `SIGNING_KEYS`, put it on the revocation list as a key-level entry (`revs` carries `kids_revoked`), ship app updates that drop it, and have users renew to get leases signed by the new key. The README is honest: copies of your app that never update keep trusting the leaked key, and the leaked key can mint licences for them. That's the limit of offline signing.
- `KEY_LOOKUP_SECRET` and `KEY_ENC_SECRET` rotate through an admin re-key run that walks every licence in bounded batches.

### Email

- perchlight-list's mail module, `MAIL_PROVIDER = resend` by default. Resend's free tier is the expected fit for a small store (its limits weren't checked for this draft). Cloudflare `send_email` is accepted only as an "owner copy" to your own verified address.
- Messages: "Your licence key for <product>", "Your keys (requested)", "Licence refunded". Plain text plus escaped HTML. A key is never put in a URL query string.
- **Delivery rows:** claim-then-send, Resend idempotency key `lic-<licence id>-<kind>`. A failed send is retried at 1 / 5 / 30 min, 2 h and 12 h by the lazy sweep. An `unknown` result isn't retried automatically.

### Lazy housekeeping (no cron, no Durable Object)

On any request, if `state.sweep_at` is more than 5 minutes old, a conditional `UPDATE state SET sweep_at = now WHERE sweep_at = old` claims the sweep, and `waitUntil` then: sends up to 5 due email retries; deletes up to 200 expired `rate` rows, `webhook_events` older than 90 days and dropped `pending_target` events; and writes footprint counters. A deployment with no traffic does no housekeeping, and it needs none: nothing becomes due without a request. Exception: email retries wait for the next request. That gap is decision 3.

### Data model (D1)

- `products`: id, name, prefix, editions JSON, features, device_limit, duration_days, trial_days, activation (`device` | `none`), lease_days, grace_days. Loaded from `keys.json` at deploy and upserted once per isolate.
- `licenses`: id (ULID), product_id, edition, key_hmac (unique), key_enc, email (lower-case), name, source (`stripe` | `lemonsqueezy` | `gumroad` | `itch` | `manual`), source_ref (order or session id), status (`active` | `revoked` | `expired`), revoked_reason, expires_at, device_limit (override), created_at, notes. Unique `(source, source_ref)`; index on email.
- `activations`: id, license_id, device_hash, label, first_at, last_seen_at, deactivated_at, kind (`full` | `trial`). Unique `(license_id, device_hash)` for active rows; trials unique `(product_id, device_hash)`.
- `webhook_events`: `(provider, event_id)` primary key, type, received_at, result (`issued` | `duplicate` | `unmapped` | `pending_target` | `applied` | `ignored` | `error`), license_id, error. No raw body is stored (it holds personal data); a SHA-256 of the body is kept.
- `deliveries`: as perchlight-forms; kinds `key_issued` | `resend` | `refund_notice`.
- `rate`: `(bucket, window_start)` primary key, count.
- `state`: sweep claim, footprint counters per day, schema version.

### Desktop app screens (`perchlight/perchlight.json`)

- **Products** (read-only; they come from `keys.json`).
- **Licences**: email, product, edition, source, status, devices used / limit, created. Actions *Issue key* (a form calling `POST /api/licenses`), *Revoke*, *Unrevoke*, *Extend*, *Re-send email*. Keys are never shown in a list; *Reveal* calls the admin API.
- **Activations** (by licence): label, first and last seen; *Free device*.
- **Webhook events**: provider, type, result, time; *Re-process* for `unmapped` and `error`.
- **Failed emails** (`deliveries`): *Try again*.

### Footprint

**Cost of one thing:**

| Oneâ€¦ | Worker requests | D1 rows written | Subrequests |
|---|---|---|---|
| sale by webhook (event, licence + 3 index rows, delivery, later delete of event) | 1 | ~8 | 2 D1 + 1 email (+1 Gumroad lookup) |
| itch.io claim | 1 | ~7 (+1â€“2 rate) | 2 D1 + 1 itch + 1 email |
| first activation | 1 | ~3 | 2 |
| lease renewal (last-seen written at most once a day) | 1 | 0â€“2 | 1â€“2 |
| resend request | 1 | ~2 rate + 1 delivery | 2 D1 + â‰¤1 email |
| housekeeping sweep (every 5 min at most) | 0 | 1 + deletes | â‰¤ 8 |

**Example store:** 30 sales a day, 5,000 installed copies on 30-day leases renewing at day 23 (~220 renewals a day) plus copies that renew early after downtime (~500 a day all told), 30 new activations, 10 resends, 3 trials.

| | Limit (Free) | Example | Share |
|---|---|---|---|
| Worker requests | 100,000/day | ~600 | 0.6% |
| D1 rows written (sales 240, activations 90, renewals ~1,000, resends 30, sweeps ~400, footprint) | 100,000/day | ~1,800 | 1.8% |
| D1 rows read | 5,000,000/day | ~10,000 | 0.2% |
| D1 storage (100,000 licences Ã— ~1 KB plus activations) | 500 MB | ~150 MB at 100k licences | 30% |
| Subrequests per invocation | 50 | â‰¤ 5 | â€” |
| Emails | your provider's free tier | ~40/day | â€” |

- **Leases are what keep it small.** An app that called home on every launch would cost a request per launch: 5,000 daily players would be 5,000+ requests and up to 10,000 writes a day. The samples don't do this, and the README explains why.
- **The ceiling:** at 100,000 requests a day, with 30-day leases, about **2 million** installed copies before renewals alone would hit the limit. At 7-day leases, about 500,000.
- **CPU:** Ed25519 signing and AES-GCM run natively in WebCrypto. Each request does at most one signature, one HMAC and one AES operation, well inside 10 ms (to be measured).
- **What it costs you:** nothing inside Workers Free, D1 Free, and your mail provider's free tier.

## Edge cases

- **The same webhook delivered twice, or concurrently:** the unique `(provider, event_id)` row and the unique `(source, source_ref)` licence in one D1 batch mean exactly one licence and one email.
- **Lemon Squeezy `order_created` and `license_key_created` both arrive:** only `order_created` issues a licence; the other is `ignored`.
- **Stripe async payments** (bank debits): a session completing as `unpaid` issues nothing; `async_payment_succeeded` issues.
- **A refund after devices were activated:** the licence is `revoked` and renewals fail. Apps keep working until `exp + grace` unless they fetch `/v1/revocations`. That's documented.
- **A partial refund** (Lemon Squeezy and Stripe send these): not revoked by default; flagged in the app (`refundPolicy: "full-only"`).
- **Upgrade** (standard to pro): an admin edition change, or a second purchase mapped to `upgrade` that updates the existing licence for that email. New leases carry the new features at the next renewal, or at once on `renew`.
- **A device reinstalls its OS** and its device id changes: it takes a new slot. The buyer frees the old one in the app, or with the key on the manage page.
- **The buyer's clock is wrong:** `nbf`/`exp` are checked with Â±24 h slack; the activate answer includes server time so the app can warn the user.
- **D1 unavailable:** activations answer `503`, and apps stay on their current lease plus grace. Webhooks answer `503`, so the stores retry (Stripe for days; Lemon Squeezy only 3 times in about 2.5 minutes, so the app flags missing orders from the provider's admin re-sync, see decision 5).
- **Email fails permanently:** the licence still exists and is shown in the app; resend and admin re-send work.
- **An expired subscription renews late:** `subscription.updated` or `subscription_resumed` sets the licence active again with a new `expires_at`.
- **A Gumroad ping for another seller's sale,** sent to your URL: the lookup with your token fails or `seller_id` doesn't match, so the result is `ignored`.

## Decisions (all decided 2026-11-12, as recommended)

1. **Lease length and grace by default.** **Decided:** a 30-day lease with renewal attempts from day 23, plus 7 days' grace. That's a month of offline use, revocation within 37 days at worst, and about 1 request per copy per 3 weeks. Settable per product (`leaseDays`, `renewAfterDays`, `graceDays`).
2. **Store keys so they can be re-sent (AES-GCM), or hash only.** **Decided:** AES-GCM (with a key id, so `KEY_ENC_SECRET` can rotate) plus an HMAC lookup. "Resend my key" is the most-wanted support feature, and a leaked D1 copy alone still doesn't expose keys. `RESEND_REISSUE=1` lets a resend replace a key it can't decrypt (a lost secret).
3. **Email retries without cron.** **Decided:** lazy only in v0.1. Activations and renewals arrive all day for any real store, and resend is the backstop. An optional single-DO alarm (as hooks' Scheduler) can come later if quiet stores report stuck emails.
4. **Refund policy by default.** **Decided:** revoke on a full refund and on a dispute or chargeback; flag partial refunds; settable per provider (`refunds`, `disputes` in `keys.json`).
5. **Missed Lemon Squeezy webhooks** (only 3 retries). **Decided:** an admin "re-sync last 7 days" action (`POST /api/resync/lemonsqueezy`) that lists orders through the Lemon Squeezy API (1 subrequest a page) and issues anything missing, idempotently.
6. **Gumroad without signatures.** **Decided:** a secret URL token plus a sale lookup through the API on every ping. Gumroad isn't enabled without `GUMROAD_ACCESS_TOKEN`.
7. **Lemon Squeezy and Gumroad native keys.** **Decided:** not accepted in v0.1. A one-off import script (`scripts/import.mjs`) mints perchlight keys for existing orders and emails them.
8. **The C# Ed25519 verifier.** **Decided:** a small, auditable verify-only implementation in the sample, ported from TweetNaCl 20140427 (public domain; cited in the file header, README and NOTICE), not written from scratch, and tested against the RFC 8032 section 7.1 vectors. No BouncyCastle dependency.

### Clarifications made while building v0.1

- **Key layout:** 26 data symbols plus the check symbol is 27 symbols, grouped 5-5-5-5-5-2 (`PROD-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XC`); the `-X` in "Must have" above showed the check symbol only.
- **Resend idempotency key:** `lic-<licence id>-<kind>-<delivery id>`, so an admin re-send within Resend's 24-hour key window still sends (a retry of the same delivery reuses its key).
- **Lemon Squeezy event id:** `<event_name>:<data.id>:<attributes.updated_at>`, so a replayed body is a duplicate while a second change to the same order or subscription (a second refund, cancel then resume) is a new event.
- **Desktop app actions:** the v1 manifest can only set columns, so *Revoke*, *Unrevoke*, *Extend*, *Re-send*, *Free device*, *Re-process* and *Try again* set a requested-action column that the lazy sweep carries out; *Issue key* and *Reveal* go through the admin API (the manifest has no "add row" or "call API" action).
- **Footprint table:** one JSON row per UTC day, flushed at most every 15 minutes per isolate as a single row write.
- **Deferred from v0.1** (in TECH_DEBT.md): SES, Mailgun and Postmark (Resend only is wired), and the Should-haves (Turnstile, Godot/C++ samples, the hosted manage page, seat transfer, the outgoing heartbeat).
- **Stripe mapping:** by `metadata.perchlight`, the Payment Link id, or (with an optional `STRIPE_SECRET_KEY`) the line items' price and product ids, since `checkout.session.completed` carries no line items.

## Acceptance criteria

- A Stripe test-mode `checkout.session.completed` (through `stripe trigger` or a test Checkout) creates exactly one licence and one email. Re-sending the same event gives `200` and no new rows. A body with one byte changed gives `400` and nothing stored. A valid signature 6 minutes old is refused.
- A Lemon Squeezy test-mode order creates one licence. A replayed delivery creates nothing new. A wrong `X-Signature` is refused.
- An itch.io download key generated in the creator dashboard claims one licence. Claiming it again re-sends the same key and creates nothing new. A made-up key gets a generic failure.
- An issued licence activates on 2 devices with `device_limit: 2`. A third gets `409` with the 2 devices listed. Deactivating one lets the third in. Re-activating an active device uses no slot.
- The C# sample accepts a valid lease offline. It rejects a lease with any byte changed, a different `dev`, a different `prod`, an unknown `kid`, and a lease past `exp + grace`.
- After a refund webhook, `renew` fails with `403 revoked`, and the licence id appears in a correctly signed `/v1/revocations`.
- `POST /v1/resend` gives the same status, body and headers for a buyer and a non-buyer. The buyer's address gets one email listing their keys. A sixth request in a day sends nothing.
- Rotating `ACTIVE_KID` signs new leases with the new `kid`, and leases signed with the old key still verify in an app that has both public keys.
- No D1 table contains a licence key in plain text or a private key. Admin, webhook and HMAC comparisons are constant-time (a unit test checks that the helper is used).
- `GET /api/footprint` after a simulated day of the example store shows under 1,000 Worker requests and under 2,500 D1 rows written. There's no cron trigger in `wrangler.jsonc`.

### Not tested (costs money, or needs a live or card-backed account)

- Stripe live mode (test-mode signatures have the same form and are tested).
- Lemon Squeezy live payments; Gumroad paid sales (a $0 product is used if Gumroad allows it, see below).
- itch.io paid purchases (creator-generated download keys are used).
- SES, Mailgun and Postmark sending (code copied from perchlight-list; Resend's free tier is used for tests).
- Workers Paid; Cloudflare Email Service to arbitrary addresses.

## Couldn't verify (2026-11-12)

- **Gumroad:** whether Ping requests carry any signature, their exact content type (believed to be form-encoded), whether a $0 test sale fires a ping, and the exact sale-lookup path (only third-party mirrors were readable; gumroad.com/api rendered empty).
- **Lemon Squeezy:** whether any unique delivery id or timestamp exists (none on the signing or request pages); whether test mode needs payout details.
- **itch.io:** the exact response fields of `download_keys` on api.itch.io (the page lists endpoints and scopes only).
- **Stripe:** the 300-second tolerance on the current docs page (it's the libraries' default, as noted in the hooks SDD).
- **Unity Asset Store:** the current wording of the no-DRM rule (from family memory; check the Submission Guidelines before the README quotes it).
- **Workers:** Ed25519 in workerd's WebCrypto (`{name: "Ed25519"}`) and its CPU cost on Free; whether the rate-limiting binding is available on Free; whether D1 index updates count as rows written (assumed yes).
- **Others:** Resend's current free-tier limits; Keygen, Cryptlex and LicenseSpring prices; whether .NET's newest base library has Ed25519.
