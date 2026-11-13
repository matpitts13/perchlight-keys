// The one-off import (SDD open question 7, decided): mints perchlight keys for
// existing Lemon Squeezy / Gumroad / other orders and emails them. Pure code,
// shared by scripts/import.mjs (Node) and the tests. Each row becomes one
// POST /api/licenses with source + source_ref, so running it twice issues
// nothing new (licences are unique per (source, source_ref)).

/** Parses CSV with a header row (RFC 4180 quotes). Returns an array of objects. */
export function parseCsv(text) {
  const rowsOut = [];
  let field = "";
  let row = [];
  let quoted = false;
  const s = String(text).replace(/^﻿/, "");
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quoted) {
      if (c === '"' && s[i + 1] === '"') {
        field += '"';
        i++;
      } else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && s[i + 1] === "\n") i++;
      row.push(field);
      field = "";
      if (row.some((f) => f !== "")) rowsOut.push(row);
      row = [];
    } else field += c;
  }
  row.push(field);
  if (row.some((f) => f !== "")) rowsOut.push(row);
  if (!rowsOut.length) return [];
  const head = rowsOut[0].map((h) => h.trim().toLowerCase());
  return rowsOut.slice(1).map((r) => Object.fromEntries(head.map((h, i) => [h, (r[i] ?? "").trim()])));
}

const SOURCES = ["lemonsqueezy", "gumroad", "stripe", "itch", "import"];

/**
 * Turns CSV rows (email, product, edition?, source, order_id, name?) into
 * POST /api/licenses bodies. Returns { requests, errors }.
 */
export function planImport(records, { sendEmail = true } = {}) {
  const requests = [];
  const errors = [];
  records.forEach((r, i) => {
    const line = i + 2;
    const source = (r.source || "import").toLowerCase();
    if (!r.email || !r.product || !r.order_id) return errors.push(`line ${line}: email, product and order_id are required`);
    if (!SOURCES.includes(source)) return errors.push(`line ${line}: source must be one of ${SOURCES.join(", ")}`);
    const body = { product: r.product, email: r.email, source, source_ref: r.order_id, send_email: sendEmail, notes: "imported" };
    if (r.edition) body.edition = r.edition;
    if (r.name) body.name = r.name;
    requests.push({ line, body });
  });
  return { requests, errors };
}

/**
 * Runs the plan one request at a time. post(body) -> { status, data }.
 * Stops after `maxFailures` failures in a row (no retry loop on a persistent error).
 */
export async function runImport(requests, post, { maxFailures = 3 } = {}) {
  const out = { issued: 0, existing: 0, failed: [], stopped: false };
  let streak = 0;
  for (const { line, body } of requests) {
    const r = await post(body);
    if (r.status === 201) out.issued++;
    else if (r.status === 200 && r.data?.existing) out.existing++;
    else {
      out.failed.push(`line ${line}: ${r.status} ${r.data?.error ?? ""}`.trim());
      if (++streak >= maxFailures) {
        out.stopped = true;
        break;
      }
      continue;
    }
    streak = 0;
  }
  return out;
}
