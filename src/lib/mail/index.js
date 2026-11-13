// The email service. perchlight-list's sender interface (src/lib/senders/
// index.js), with Resend as the one provider wired in v0.1. SES, Mailgun and
// Postmark have the same shape in perchlight-list and can be copied in (see
// TECH_DEBT.md); MAIL_PROVIDER names the provider.
import { resendSender } from "./resend.js";

/**
 * @typedef {{ to: string, subject: string, text: string, html: string, headers?: Record<string, string> }} Message
 * @typedef {{ status: "sent", id: string | null }
 *   | { status: "rejected" | "retry" | "throttled" | "config" | "unknown" | "conflict", error: string }} SendResult
 * @typedef {{ name: string, idempotent: boolean, send(m: Message, o?: { idempotencyKey?: string }): Promise<SendResult> }} EmailSender
 */

/** The configured sender, or null if email isn't set up (deliveries wait). */
export function getSender(env) {
  const from = env.MAIL_FROM || "";
  if (!from) return null;
  const provider = String(env.MAIL_PROVIDER || "resend").toLowerCase();
  if (provider === "resend") return env.RESEND_API_KEY ? resendSender(env.RESEND_API_KEY, from) : null;
  console.error(`MAIL_PROVIDER "${provider}" isn't supported in v0.1. Use resend.`);
  return null;
}
