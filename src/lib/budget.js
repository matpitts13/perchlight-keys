// A per-invocation budget of binding calls and outbound requests.
// Copied from perchlight-hooks src/lib/budget.js (from perchlight-forms); one
// budget per request here (the request's own work plus its waitUntil work).
//
// Workers Free allows 50 subrequests per invocation, and D1 50 queries per
// invocation. Whether D1 binding calls count toward the 50 subrequests isn't
// confirmed, so this assumes they do and keeps an invocation under 45.

export const SUBREQUEST_BUDGET = 45;

export class BudgetError extends Error {
  constructor() {
    super("subrequest budget used up for this invocation");
    this.name = "BudgetError";
  }
}

export function newBudget(total = SUBREQUEST_BUDGET) {
  return { left: total, used: 0 };
}

export const left = (budget) => (budget ? budget.left : Infinity);

/** Takes n from the budget if it's there. */
export function spend(budget, n = 1) {
  if (!budget) return true;
  if (budget.left < n) return false;
  budget.left -= n;
  budget.used += n;
  return true;
}

/** Like spend, but throws BudgetError when it isn't there. */
export function must(budget, n = 1) {
  if (!spend(budget, n)) throw new BudgetError();
}
