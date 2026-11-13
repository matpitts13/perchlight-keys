// Measured footprint: per-isolate counters (Worker requests by route, D1
// calls, rows read and written as D1 reports them, emails), flushed at most
// once every 15 minutes per isolate as ONE row write: a single JSON row per
// UTC day, added to in SQL. Counters of an isolate that's evicted before it
// flushes are lost, so the numbers are a lower bound. GET /api/footprint
// forces a flush and reads them.
import { utcDay } from "./http.js";

export const FLUSH_MS = 15 * 60_000;
let pending = new Map(); // day -> Map(metric -> n)
let lastFlush = 0;

export function bump(metric, n = 1, now = Date.now()) {
  if (!n) return;
  const day = utcDay(now);
  let m = pending.get(day);
  if (!m) pending.set(day, (m = new Map()));
  m.set(metric, (m.get(metric) ?? 0) + n);
}

export function resetFootprint() {
  pending = new Map();
  lastFlush = 0;
}

const METRIC_RE = /^[a-z0-9_]{1,40}$/;

/** Writes pending counters (raw D1 binding, not metered, so it can't recurse). */
export async function flushFootprint(rawDb, now, force = false) {
  if (!rawDb || !pending.size || (!force && now - lastFlush < FLUSH_MS)) return;
  lastFlush = now;
  const batch = pending;
  pending = new Map();
  const stmts = [];
  for (const [day, m] of batch) {
    const entries = [...m.entries()].filter(([k]) => METRIC_RE.test(k));
    if (!entries.length) continue;
    // Metric names are fixed identifiers from this code (checked above), never input; the numbers are bound.
    const obj = entries.map(([k]) => `'${k}', ?`).join(", ");
    const sets = entries.map(([k]) => `'$.${k}', COALESCE(json_extract(footprint.data, '$.${k}'), 0) + ?`).join(", ");
    const nums = entries.map(([, n]) => n);
    stmts.push(
      rawDb
        .prepare(`INSERT INTO footprint (day, data) VALUES (?, json_object(${obj})) ON CONFLICT (day) DO UPDATE SET data = json_set(footprint.data, ${sets})`)
        .bind(day, ...nums, ...nums),
    );
  }
  try {
    const res = await rawDb.batch(stmts);
    // The flush's own row counts next time.
    bump("d1_rows_written", res.reduce((s, r) => s + (r.meta?.rows_written ?? 0), 0), now);
    bump("d1_queries", 1, now);
  } catch {
    for (const [day, m] of batch) for (const [k, n] of m) bump(k, n, Date.parse(`${day}T12:00:00Z`));
  }
}
