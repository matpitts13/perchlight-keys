// Copies keys.json products into D1 for the desktop app, only when the
// config changed (a hash in state), so isolate starts cost no writes.
import { sha256Hex } from "./crypto.js";

export async function syncProducts(app) {
  const prods = Object.values(app.cfg.products);
  const hash = await sha256Hex(JSON.stringify(prods));
  const row = await app.db.prepare("SELECT value FROM state WHERE key = 'config_hash'").first();
  if (row?.value === hash) return false;
  const stmts = prods.map((p) =>
    app.db
      .prepare(
        `INSERT INTO products (id, name, prefix, editions, device_limit, duration_days, trial_days, activation, lease_days, grace_days, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET name = excluded.name, prefix = excluded.prefix, editions = excluded.editions, device_limit = excluded.device_limit,
           duration_days = excluded.duration_days, trial_days = excluded.trial_days, activation = excluded.activation, lease_days = excluded.lease_days,
           grace_days = excluded.grace_days, updated_at = excluded.updated_at`,
      )
      .bind(p.id, p.name, p.prefix, JSON.stringify(p.editions), p.deviceLimit, p.duration === "perpetual" ? null : p.duration, p.trialDays, p.activation, p.leaseDays, p.graceDays, app.now),
  );
  stmts.push(app.db.prepare("INSERT INTO state (key, value) VALUES ('config_hash', ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value").bind(hash));
  await app.db.batch(stmts);
  return true;
}
