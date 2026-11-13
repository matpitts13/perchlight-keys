// The Worker, built around a keys config (keys.json in production; tests pass
// their own). No cron trigger: housekeeping runs lazily on requests.
import { makeApp } from "./lib/appctx.js";
import { loadConfig } from "./lib/config.js";
import { fail, text } from "./lib/http.js";
import { bump } from "./lib/footprint.js";
import { maybeSweep } from "./lib/sweep.js";
import { BudgetError } from "./lib/budget.js";
import { handleLicensing } from "./routes/licensing.js";
import { handleWebhook } from "./routes/webhooks.js";
import { handleResend, handleClaim } from "./routes/buyer.js";
import { handleAdmin } from "./routes/admin.js";

// A fixed set of metric names: never built from the request path, so a flood
// of random paths can't grow the counters (or the flush statement).
const ROUTES = new Set(["activate", "renew", "deactivate", "license", "trial", "revocations", "keys", "resend"]);
const HOOKS = new Set(["stripe", "lemonsqueezy", "gumroad"]);
function routeName(path) {
  const p = path.split("/");
  if (path.startsWith("/v1/webhooks/")) return HOOKS.has(p[3]) ? `webhook_${p[3]}` : "other";
  if (path.startsWith("/v1/")) return ROUTES.has(p[2]) && p.length === 3 ? p[2] : "other";
  if (path.startsWith("/api/")) return "admin";
  if (path === "/claim/itch") return "claim";
  return "other";
}

export function makeWorker(raw) {
  const cfg = loadConfig(raw);
  for (const e of cfg.errors) console.error(`keys.json: ${e}`);
  return {
    async fetch(request, env, ctx) {
      const url = new URL(request.url);
      const path = url.pathname;
      const app = makeApp(cfg, env, ctx, url.origin);
      bump("worker_requests", 1, app.now);
      bump(`req_${routeName(path)}`, 1, app.now);
      try {
        let res = null;
        if (path.startsWith("/v1/webhooks/")) res = await handleWebhook(request, app, path);
        else if (path === "/v1/resend" && request.method === "POST") res = await handleResend(request, app);
        else if (path.startsWith("/v1/")) res = await handleLicensing(request, app, path, url);
        else if (path.startsWith("/api/")) res = await handleAdmin(request, app, path.slice(5));
        else if (path === "/claim/itch") res = await handleClaim(request, app);
        else if (path === "/") res = text("perchlight-keys\n");
        if (!res) res = fail(404, "not_found", "Not found.");
        maybeSweep(app);
        return res;
      } catch (err) {
        console.error(`${request.method} ${path.replace(/gumroad\/.*/, "gumroad/<token>")}: ${err instanceof Error ? err.message : String(err)}`);
        maybeSweep(app);
        if (err instanceof BudgetError) return fail(503, "busy", "Try again shortly.", {}, { "Retry-After": "5" });
        return fail(path.startsWith("/v1/") || path.startsWith("/api/") ? 503 : 500, "unavailable", "Something went wrong. Try again later.", {}, { "Retry-After": "30" });
      }
    },
  };
}
