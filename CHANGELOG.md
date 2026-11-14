# Changelog

## v0.1.0

The first release of perchlight-keys: free, self-hosted software license keys on your own Cloudflare account (Workers + D1).

**Set up in one click** with the Deploy to Cloudflare button in the [README](https://github.com/matpitts13/perchlight-keys#readme), or by hand with `npm run deploy`.

### What's in it

- **Simple keys, offline checks:** buyers get a random key. Their app trades it once for an Ed25519-signed lease tied to the device, then checks the lease offline. Leases last 30 days, plus 7 days of grace when the device is offline.
- **Activations:** device limits, deactivation, revocation (leases expire, plus an optional signed revocation list), trials and expiry.
- **Keys issued when someone pays:**
  - Stripe: signature plus a timestamp check.
  - Lemon Squeezy: signature, with a "re-sync the last 7 days" button.
  - Gumroad: each sale is confirmed with Gumroad's API.
  - itch.io: a claim page where buyers paste their download key.
- **Duplicate webhooks do nothing:** each event is recorded once and each order makes one licence. Full refunds and chargebacks switch the key off, and partial refunds are flagged for you.
- **"Resend my key"** always gives the same answer, is rate-limited, and only emails the address on file. Keys are stored as a lookup hash plus an AES-GCM encrypted copy.
- **Key rotation:** every signature carries a key id.
- **A C# verify-only checker** for Unity and .NET apps, ported from TweetNaCl (public domain). It passes the RFC 8032 test vectors.
- **An import script** for keys you already sold elsewhere, plus screens for the [Perchlight](https://github.com/matpitts13/perchlight) desktop app.
- **Email through Resend.**

### Honest limits

This discourages casual key sharing. It can't stop someone who cracks your app. Unity Asset Store packages aren't a use case, because the store bans DRM; use it for games and apps you sell elsewhere.

### Tested, and not tested

104 automated tests, including Ed25519 signing in workerd matching RFC 8032 byte for byte, plus 31 C# checks on .NET 8.

Not tested: deploying on a real account, Stripe test mode end to end, a Lemon Squeezy test store, a real Gumroad ping, the real itch.io API, real Resend delivery, the Unity editor, and anything paid (Stripe live mode, paid sales).
