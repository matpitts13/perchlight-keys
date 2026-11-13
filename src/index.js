// perchlight-keys: licence keys, signed licence files and device leases on
// Cloudflare Workers + D1. Your products are in keys.json at the repo root; a
// push redeploys. There is no cron trigger (docs/SDD.md, "Lazy housekeeping").
import config from "../keys.json";
import { makeWorker } from "./app.js";

export default makeWorker(config);
