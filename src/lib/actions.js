// Owner actions on a licence or an activation, shared by the admin API and
// the desktop app's requested actions (processed by the lazy sweep).
import { sortableId } from "./crypto.js";
import { deliveryStmt, opSql } from "./licenses.js";

const DAY = 86_400_000;

/**
 * op: revoke | unrevoke | extend | edition | resend | free_all.
 * args: { reason, days, expiresAt, perpetual, edition, email }.
 * Returns { ok, changed, deliveryId?, error? }.
 */
export async function licenseAction(app, id, op, args = {}) {
  const lic = await app.db.prepare("SELECT * FROM licenses WHERE id = ?").bind(id).first();
  if (!lic) return { ok: false, error: "not_found" };
  const run = async (sql, ...binds) => (await app.db.prepare(sql).bind(...binds).run()).meta.changes;
  switch (op) {
    case "revoke":
    case "unrevoke": {
      const q = opSql(op, { reason: String(args.reason ?? "manual").slice(0, 100) }, app.now);
      return { ok: true, changed: (await run(`UPDATE licenses SET ${q.set} WHERE id = ? AND (${q.where})`, ...q.args, id)) > 0 };
    }
    case "extend": {
      let exp;
      if (args.perpetual === true) exp = null;
      else if (Number.isFinite(args.expiresAt)) exp = args.expiresAt;
      else if (Number.isInteger(args.days) && args.days > 0 && args.days <= 36500) {
        // Extending a perpetual licence by days would make it expire: leave it perpetual.
        if (lic.expires_at == null) return { ok: true, changed: false, expires_at: null };
        exp = Math.max(lic.expires_at, app.now) + args.days * DAY;
      } else return { ok: false, error: "bad_request" };
      const changed = await run(
        "UPDATE licenses SET expires_at = ?, status = CASE WHEN status = 'expired' THEN 'active' ELSE status END, updated_at = ? WHERE id = ?",
        exp,
        app.now,
        id,
      );
      return { ok: true, changed: changed > 0, expires_at: exp };
    }
    case "edition": {
      const prod = app.cfg.products[lic.product_id];
      if (!prod || typeof args.edition !== "string" || !Object.hasOwn(prod.editions, args.edition)) return { ok: false, error: "bad_edition" };
      return { ok: true, changed: (await run("UPDATE licenses SET edition = ?, updated_at = ? WHERE id = ?", args.edition, app.now, id)) > 0 };
    }
    case "resend": {
      // Optionally to a new address (a buyer who changed email): the licence's email changes too.
      const email = args.email ?? lic.email;
      const deliveryId = sortableId("dlv_", app.now);
      const stmts = [];
      if (email !== lic.email) stmts.push(app.db.prepare("UPDATE licenses SET email = ?, updated_at = ? WHERE id = ?").bind(email, app.now, id));
      stmts.push(deliveryStmt(app, { id: deliveryId, licenseId: id, kind: "key_issued", email }));
      await app.db.batch(stmts);
      return { ok: true, changed: true, deliveryId };
    }
    case "free_all": {
      const changed = await run("UPDATE activations SET deactivated_at = ? WHERE license_id = ? AND kind = 'full' AND deactivated_at IS NULL", app.now, id);
      return { ok: true, changed: changed > 0, freed: changed };
    }
    default:
      return { ok: false, error: "unknown_action" };
  }
}

/** The desktop app's action values (licenses.action_requested) -> licenseAction calls. */
export const REQUESTED = {
  revoke: ["revoke", { reason: "manual" }],
  unrevoke: ["unrevoke", {}],
  resend: ["resend", {}],
  extend_30: ["extend", { days: 30 }],
  extend_365: ["extend", { days: 365 }],
  free_all: ["free_all", {}],
};
