// Lazy housekeeping: no cron trigger, no Durable Object (docs/SDD.md, open
// question 3, decided "lazy"). On any request, if the last sweep is more than
// 5 minutes old, a conditional UPDATE claims the sweep (only one request wins)
// and waitUntil then: runs the desktop app's requested actions, sends up to 5
// due emails, deletes expired rate rows and old events (bounded), and drops
// pending_target events older than 7 days. A deployment with no traffic does
// nothing and needs nothing; email retries wait for the next request.
import { licenseAction, REQUESTED } from "./actions.js";
import { sendDelivery, sendDue } from "./deliveries.js";
import { left } from "./budget.js";
import { flushFootprint } from "./footprint.js";
import { syncProducts } from "./products.js";
import { claimExisting, reprocessClaimed } from "./licenses.js";

export const SWEEP_EVERY_MS = 5 * 60_000;
const DAY = 86_400_000;

// The newest sweep time this isolate has seen: until 5 minutes after it, no
// request even reads the state row.
let seenSweepAt = 0;
export function resetSweepMemory() {
  seenSweepAt = 0;
}

/** Claims the sweep if it's due. Returns true if this request won it. */
export async function claimSweep(app, force = false) {
  if (!force && app.now - seenSweepAt < SWEEP_EVERY_MS) return false;
  const row = await app.db.prepare("SELECT value FROM state WHERE key = 'sweep_at'").first();
  const last = Number(row?.value ?? 0);
  seenSweepAt = Math.max(seenSweepAt, last);
  if (!force && app.now - last < SWEEP_EVERY_MS) return false;
  seenSweepAt = app.now;
  const r = await app.db.prepare("UPDATE state SET value = ? WHERE key = 'sweep_at' AND value = ?").bind(String(app.now), row?.value ?? "0").run();
  return r.meta.changes > 0;
}

export async function runSweep(app) {
  const out = { actions: 0, emails: 0, deleted: 0, dropped: 0 };
  await syncProducts(app);
  // Desktop app requests: licence actions, freed activations, re-sends.
  const reqs = (await app.db.prepare("SELECT id, action_requested FROM licenses WHERE action_requested IS NOT NULL LIMIT 5").all()).results;
  for (const r of reqs) {
    if (left(app.budget) < 12) break;
    const spec = REQUESTED[r.action_requested];
    if (spec) {
      const res = await licenseAction(app, r.id, spec[0], spec[1]);
      if (res.deliveryId) await sendDelivery(app, res.deliveryId);
      out.actions++;
    }
    await app.db.prepare("UPDATE licenses SET action_requested = NULL WHERE id = ? AND action_requested = ?").bind(r.id, r.action_requested).run();
  }
  const evs = (await app.db.prepare("SELECT provider, event_id FROM webhook_events WHERE result = 'reprocess_requested' LIMIT 3").all()).results;
  for (const e of evs) {
    if (left(app.budget) < 14) break;
    const ev = await claimExisting(app, e.provider, e.event_id, ["reprocess_requested"]);
    if (!ev) continue;
    try {
      const r = await reprocessClaimed(app, ev); // releases the claim as 'error' on failure
      if (r.deliveryId) await sendDelivery(app, r.deliveryId);
      out.actions++;
    } catch (err) {
      console.error(`sweep re-process: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  if (left(app.budget) > 10) {
    // Claims interrupted mid-way (an evicted isolate) go back to 'error', re-processable.
    const stuck = await app.db
      .prepare("UPDATE webhook_events SET result = 'error', error = 'interrupted while re-processing', claim = NULL, claimed_at = NULL WHERE result = 'processing' AND claimed_at < ?")
      .bind(app.now - 10 * 60_000)
      .run();
    out.actions += stuck.meta.changes;
  }
  if (left(app.budget) > 10) {
    const freed = await app.db
      .prepare(
        "UPDATE activations SET deactivated_at = CASE WHEN kind = 'full' AND deactivated_at IS NULL THEN ? ELSE deactivated_at END, free_requested = 0 WHERE free_requested = 1",
      )
      .bind(app.now)
      .run();
    out.actions += freed.meta.changes;
  }
  if (left(app.budget) > 10) {
    const d = await app.db.batch([
      app.db.prepare("DELETE FROM rate WHERE rowid IN (SELECT rowid FROM rate WHERE expires_at < ? LIMIT 200)").bind(app.now),
      app.db.prepare("DELETE FROM webhook_events WHERE rowid IN (SELECT rowid FROM webhook_events WHERE received_at < ? AND result != 'pending_target' LIMIT 200)").bind(app.now - 90 * DAY),
      app.db
        .prepare("UPDATE webhook_events SET result = 'dropped', error = 'the order it refers to never arrived (7 days)' WHERE result = 'pending_target' AND received_at < ?")
        .bind(app.now - 7 * DAY),
    ]);
    out.deleted = d[0].meta.changes + d[1].meta.changes;
    out.dropped = d[2].meta.changes;
  }
  out.emails = await sendDue(app, 5);
  await flushFootprint(app.env.DB, app.now);
  return out;
}

/** Called on every request: claims and runs the sweep in waitUntil when due. */
export function maybeSweep(app) {
  app.waitUntil(
    (async () => {
      if (await claimSweep(app)) await runSweep(app);
      else await flushFootprint(app.env.DB, app.now);
    })(),
  );
}
