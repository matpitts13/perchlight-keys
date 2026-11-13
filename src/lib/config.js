// keys.json: products, editions, provider mappings and refund policy.
// A product with a problem is left out (and named in GET /api/config); the
// rest keep working.
import { PREFIX_RE } from "./keyfmt.js";

export const PROVIDERS = ["stripe", "lemonsqueezy", "gumroad", "itch"];
const REFUND_POLICIES = ["full-only", "any", "never"];
const DEFAULTS = { deviceLimit: 3, duration: "perpetual", trialDays: 0, activation: "device", leaseDays: 30, renewAfterDays: 23, graceDays: 7 };

const isInt = (v, min, max) => Number.isInteger(v) && v >= min && v <= max;

function checkProduct(id, p, errors) {
  const err = (m) => errors.push(`products.${id}: ${m}`);
  const before = errors.length;
  if (!/^[a-z0-9][a-z0-9_-]{0,39}$/.test(id)) err("the id must be 1-40 lower-case letters, digits, _ or -");
  if (!p || typeof p !== "object") {
    err("must be an object");
    return null;
  }
  const out = { id, ...DEFAULTS, ...p };
  if (typeof out.name !== "string" || !out.name || out.name.length > 100) err("name: 1-100 characters");
  if (typeof out.prefix !== "string" || !PREFIX_RE.test(out.prefix)) err("prefix: 1-12 upper-case letters or digits");
  if (!out.editions || typeof out.editions !== "object" || !Object.keys(out.editions).length) err("editions: at least one");
  else
    for (const [ed, e] of Object.entries(out.editions)) {
      if (!/^[a-z0-9][a-z0-9_-]{0,31}$/.test(ed)) err(`editions.${ed}: bad name`);
      if (!e || !Array.isArray(e.features) || e.features.some((f) => typeof f !== "string" || f.length > 40) || e.features.length > 50) err(`editions.${ed}.features: up to 50 strings`);
    }
  const eds = Object.keys(out.editions ?? {});
  out.defaultEdition ??= eds[0];
  out.trialEdition ??= out.defaultEdition;
  if (!eds.includes(out.defaultEdition)) err("defaultEdition isn't an edition");
  if (!eds.includes(out.trialEdition)) err("trialEdition isn't an edition");
  if (!isInt(out.deviceLimit, 1, 1000)) err("deviceLimit: 1-1000");
  if (out.duration !== "perpetual" && !isInt(out.duration, 1, 36500)) err('duration: "perpetual" or 1-36500 days');
  if (!isInt(out.trialDays, 0, 365)) err("trialDays: 0-365");
  if (!["device", "none"].includes(out.activation)) err('activation: "device" or "none"');
  if (!isInt(out.leaseDays, 1, 365)) err("leaseDays: 1-365");
  if (!isInt(out.renewAfterDays, 0, out.leaseDays)) err("renewAfterDays: 0-leaseDays");
  if (!isInt(out.graceDays, 0, 90)) err("graceDays: 0-90");
  out.map ??= {};
  for (const [prov, m] of Object.entries(out.map)) {
    if (!PROVIDERS.includes(prov)) err(`map.${prov}: unknown provider`);
    else if (!m || typeof m !== "object") err(`map.${prov}: must be an object`);
    else
      for (const [ext, v] of Object.entries(m)) {
        const ed = typeof v === "string" ? v : v?.edition;
        if (!eds.includes(ed)) err(`map.${prov}.${ext}: "${ed}" isn't an edition`);
      }
  }
  return errors.length === before ? out : null;
}

/** Validates a keys.json object. Returns { products, refunds, disputes, errors }. */
export function loadConfig(raw) {
  const errors = [];
  const products = {};
  const prefixes = new Set();
  for (const [id, p] of Object.entries(raw?.products ?? {})) {
    const prod = checkProduct(id, p, errors);
    if (!prod) continue;
    if (prefixes.has(prod.prefix)) {
      errors.push(`products.${id}: prefix ${prod.prefix} is used twice`);
      continue;
    }
    prefixes.add(prod.prefix);
    products[id] = prod;
  }
  const refunds = { stripe: "full-only", lemonsqueezy: "full-only", gumroad: "full-only", ...(raw?.refunds ?? {}) };
  for (const [k, v] of Object.entries(refunds)) if (!REFUND_POLICIES.includes(v)) {
    errors.push(`refunds.${k}: one of ${REFUND_POLICIES.join(", ")}`);
    refunds[k] = "full-only";
  }
  const disputes = raw?.disputes ?? "revoke";
  if (!["revoke", "flag"].includes(disputes)) errors.push('disputes: "revoke" or "flag"');
  return { products, refunds, disputes: disputes === "flag" ? "flag" : "revoke", errors };
}

/**
 * The product and edition a provider's id maps to. ids: candidates in order
 * (e.g. Stripe price, product, payment link). Returns { product, edition,
 * upgrade, ext } or null (unmapped).
 */
export function findMapping(cfg, provider, ids) {
  for (const raw of ids) {
    if (raw == null || raw === "") continue;
    const ext = String(raw);
    for (const p of Object.values(cfg.products)) {
      const m = p.map?.[provider];
      if (m && Object.hasOwn(m, ext)) {
        const v = m[ext];
        return { product: p, edition: typeof v === "string" ? v : v.edition, upgrade: typeof v === "object" && !!v.upgrade, ext };
      }
    }
  }
  return null;
}

/** Expiry for a new licence of a product (ms), or null for perpetual. */
export function expiryFor(product, now) {
  return product.duration === "perpetual" ? null : now + product.duration * 86_400_000;
}
