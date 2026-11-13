#!/usr/bin/env node
// One-off import of existing orders (Lemon Squeezy, Gumroad, ...) as
// perchlight keys, emailed to each buyer. Safe to run again: an order that
// already has a licence is skipped.
//
//   ADMIN_TOKEN=... node scripts/import.mjs orders.csv https://keys.example.com [--no-email] [--dry-run]
//
// CSV header: email,product,edition,source,order_id,name  (edition and name optional;
// source: lemonsqueezy | gumroad | stripe | itch | import)
import { readFile } from "node:fs/promises";
import { parseCsv, planImport, runImport } from "../src/lib/importer.js";

const [file, base, ...flags] = process.argv.slice(2);
if (!file || !base) {
  console.error("usage: ADMIN_TOKEN=... node scripts/import.mjs <orders.csv> <https://your-worker> [--no-email] [--dry-run]");
  process.exit(2);
}
const token = process.env.ADMIN_TOKEN;
if (!token && !flags.includes("--dry-run")) {
  console.error("Set ADMIN_TOKEN in the environment (it's never taken as an argument, so it stays out of shell history).");
  process.exit(2);
}
const { requests, errors } = planImport(parseCsv(await readFile(file, "utf8")), { sendEmail: !flags.includes("--no-email") });
for (const e of errors) console.error(e);
console.log(`${requests.length} orders to import, ${errors.length} rows skipped.`);
if (flags.includes("--dry-run")) process.exit(errors.length ? 1 : 0);

const url = `${base.replace(/\/+$/, "")}/api/licenses`;
const out = await runImport(requests, async (body) => {
  const res = await fetch(url, { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  return { status: res.status, data };
});
console.log(`issued ${out.issued}, already there ${out.existing}, failed ${out.failed.length}${out.stopped ? " (stopped after repeated failures)" : ""}`);
for (const f of out.failed) console.error(f);
process.exit(out.failed.length ? 1 : 0);
