// Rate limits (docs/SDD.md, "Abuse and rate limits").
// - Isolate memory for activate / renew / trial / deactivate / license: cheap,
//   per IP hash and per key, e.g. 20 a minute. Not shared across isolates,
//   which is fine: they only stop one client from wasting the daily quota.
// - D1 `rate` rows for resend and claim, whose limits must hold everywhere.
// IP addresses are never stored: the IP hash is HMAC(daily salt, ip), the
// daily salt being HMAC(IP_SALT, day); rows are kept 48 hours.
import { hmacHex } from "./crypto.js";
import { utcDay } from "./http.js";

const MAX_KEYS = 5000;
let windows = new Map(); // key -> { start, n }

export function resetRate() {
  windows = new Map();
}

/** true if allowed. Fixed one-minute (or windowMs) windows in isolate memory. */
export function memoryHit(key, limit, now, windowMs = 60_000) {
  const start = Math.floor(now / windowMs) * windowMs;
  const w = windows.get(key);
  if (!w || w.start !== start) {
    if (windows.size >= MAX_KEYS) {
      // Drop finished windows first; clear everything only if all are current.
      for (const [k, v] of windows) if (v.start + v.ms <= now) windows.delete(k);
      if (windows.size >= MAX_KEYS) windows = new Map();
    }
    windows.set(key, { start, n: 1, ms: windowMs });
    return true;
  }
  w.n++;
  return w.n <= limit;
}

export async function ipHash(app, request) {
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const salt = app.env.IP_SALT || app.env.KEY_LOOKUP_SECRET || "perchlight-keys";
  const daily = await hmacHex(salt, `ip-salt/${utcDay(app.now)}`);
  return (await hmacHex(daily, ip)).slice(0, 32);
}

/**
 * Statements that count one hit in each bucket; run them in one batch. Each
 * returns the bucket's new count. buckets: [{ bucket, windowMs }].
 */
export function rateStmts(app, buckets) {
  return buckets.map(({ bucket, windowMs }) => {
    const start = Math.floor(app.now / windowMs) * windowMs;
    return app.db
      .prepare(
        "INSERT INTO rate (bucket, window_start, count, expires_at) VALUES (?, ?, 1, ?) ON CONFLICT (bucket, window_start) DO UPDATE SET count = count + 1 RETURNING count",
      )
      .bind(bucket, start, Math.max(start + windowMs, app.now + 48 * 3_600_000));
  });
}

/** Runs rateStmts and returns true when every bucket is within its limit. */
export async function d1Hits(app, buckets) {
  const res = await app.db.batch(rateStmts(app, buckets));
  return buckets.every((b, i) => (res[i].results[0]?.count ?? Infinity) <= b.limit);
}
