// A thin D1 wrapper: every call spends one unit of the request's budget and
// adds D1's own rows_read / rows_written to the footprint counters. SQL is
// always parameterised (bind), never built from input.
import { must } from "./budget.js";
import { bump } from "./footprint.js";

function count(meta, now) {
  bump("d1_queries", 1, now);
  bump("d1_rows_read", meta?.rows_read ?? 0, now);
  bump("d1_rows_written", meta?.rows_written ?? 0, now);
}

/** @returns {{ prepare(sql: string): any, batch(stmts: any[]): Promise<any[]>, raw: any }} */
export function metered(raw, budget, now) {
  const wrap = (stmt) => ({
    stmt,
    bind: (...args) => wrap(stmt.bind(...args)),
    async run() {
      must(budget);
      const r = await stmt.run();
      count(r.meta, now);
      return r;
    },
    async all() {
      must(budget);
      const r = await stmt.all();
      count(r.meta, now);
      return r;
    },
    async first() {
      must(budget);
      const r = await stmt.all();
      count(r.meta, now);
      return r.results[0] ?? null;
    },
  });
  return {
    raw,
    prepare: (sql) => wrap(raw.prepare(sql)),
    async batch(stmts) {
      if (!stmts.length) return [];
      must(budget);
      const res = await raw.batch(stmts.map((s) => s.stmt));
      bump("d1_queries", 1, now);
      for (const r of res) {
        bump("d1_rows_read", r.meta?.rows_read ?? 0, now);
        bump("d1_rows_written", r.meta?.rows_written ?? 0, now);
      }
      return res;
    },
  };
}
