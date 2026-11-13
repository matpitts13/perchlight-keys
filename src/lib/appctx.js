// The per-request context: config, env, a metered D1, the budget and "now".
import { newBudget } from "./budget.js";
import { metered } from "./db.js";

/** Replaceable in tests. */
export const clock = { now: () => Date.now() };

export function makeApp(cfg, env, ctx, origin = "") {
  const now = clock.now();
  const budget = newBudget();
  return {
    cfg,
    env,
    ctx,
    now,
    budget,
    db: metered(env.DB, budget, now),
    publicUrl: (env.PUBLIC_URL || origin).replace(/\/+$/, ""),
    waitUntil: (p) => ctx.waitUntil(p.catch((err) => console.error(`background: ${err instanceof Error ? err.message : String(err)}`))),
  };
}

/**
 * A secret that can rotate: a plain string (kid "k1"), or JSON {kid: secret}
 * with the active kid named by `activeVar` (default: the first). Each secret
 * must be 16+ characters. Returns { active, secrets } or throws.
 */
export function secretSet(env, name, activeVar) {
  const raw = env[name];
  if (!raw) throw new Error(`${name} isn't set`);
  let secrets = null;
  if (raw.trim().startsWith("{")) {
    try {
      const v = JSON.parse(raw);
      if (v && typeof v === "object" && !Array.isArray(v)) secrets = v;
    } catch {
      throw new Error(`${name} looks like JSON but doesn't parse`);
    }
  }
  if (!secrets) secrets = { k1: raw };
  const kids = Object.keys(secrets);
  if (!kids.length) throw new Error(`${name} is empty`);
  for (const k of kids) {
    if (!/^[A-Za-z0-9_-]{1,16}$/.test(k)) throw new Error(`${name}: kid "${k}" must be 1-16 letters, digits, _ or -`);
    if (typeof secrets[k] !== "string" || secrets[k].length < 16) throw new Error(`${name}: each secret needs 16+ characters`);
  }
  const active = env[activeVar] || kids[0];
  if (!secrets[active]) throw new Error(`${activeVar} isn't one of the ${name} kids`);
  return { active, secrets };
}
