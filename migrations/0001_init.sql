-- perchlight-keys schema v1 (docs/SDD.md, "Data model").
-- No licence key and no private key is ever stored in plain text: keys are an
-- HMAC (lookup) plus AES-GCM ciphertext (resend). Times are Unix milliseconds
-- unless a column name says otherwise.

-- Copied from keys.json for the desktop app (read-only there).
CREATE TABLE products (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  prefix TEXT NOT NULL,
  editions TEXT NOT NULL,          -- JSON {edition: {features: [...]}}
  device_limit INTEGER NOT NULL,
  duration_days INTEGER,           -- NULL = perpetual
  trial_days INTEGER NOT NULL,
  activation TEXT NOT NULL,        -- device | none
  lease_days INTEGER NOT NULL,
  grace_days INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE licenses (
  id TEXT PRIMARY KEY,
  product_id TEXT NOT NULL,
  edition TEXT NOT NULL,
  key_hmac TEXT NOT NULL UNIQUE,   -- "<lookup kid>:<hex HMAC-SHA256 of the normalised key>"
  key_enc TEXT NOT NULL,           -- "<enc kid>.<iv>.<AES-GCM ciphertext>" (base64url), AAD = id
  email TEXT NOT NULL,             -- lower-case
  name TEXT,
  source TEXT NOT NULL,            -- stripe | lemonsqueezy | gumroad | itch | manual | import
  source_ref TEXT NOT NULL,        -- order / session / sale / download-key id
  status TEXT NOT NULL DEFAULT 'active', -- active | revoked | expired
  revoked_reason TEXT,
  revoked_at INTEGER,
  expires_at INTEGER,              -- NULL = perpetual
  device_limit INTEGER,            -- NULL = the product's
  flags TEXT,                      -- partial_refund, churn, ... (comma-separated, shown in the app)
  churn INTEGER NOT NULL DEFAULT 0,
  churn_month TEXT,
  action_requested TEXT,           -- desktop app: revoke | unrevoke | resend | extend_30 | extend_365 | free_all
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  notes TEXT,
  UNIQUE (source, source_ref)
);
CREATE INDEX licenses_email ON licenses (email);
CREATE INDEX licenses_revoked ON licenses (product_id, status, revoked_at);
CREATE INDEX licenses_action ON licenses (action_requested) WHERE action_requested IS NOT NULL;

-- Extra provider ids pointing at a licence (payment intent, subscription,
-- order id), so refunds and subscription events find it.
CREATE TABLE license_refs (
  source TEXT NOT NULL,
  ref TEXT NOT NULL,
  license_id TEXT NOT NULL,
  PRIMARY KEY (source, ref)
);

CREATE TABLE activations (
  id TEXT PRIMARY KEY,             -- random; shown to buyers instead of the device hash
  license_id TEXT,                 -- NULL for trials
  product_id TEXT NOT NULL,
  device_hash TEXT NOT NULL,
  label TEXT,
  kind TEXT NOT NULL,              -- full | trial
  first_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  expires_at INTEGER,              -- trials only
  deactivated_at INTEGER,
  free_requested INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX activations_active ON activations (license_id, device_hash) WHERE deactivated_at IS NULL AND kind = 'full';
CREATE UNIQUE INDEX activations_trial ON activations (product_id, device_hash) WHERE kind = 'trial';
CREATE INDEX activations_license ON activations (license_id, deactivated_at);

CREATE TABLE webhook_events (
  provider TEXT NOT NULL,
  event_id TEXT NOT NULL,
  type TEXT NOT NULL,
  received_at INTEGER NOT NULL,
  result TEXT NOT NULL,            -- issued | duplicate | unmapped | pending_target | applied | ignored | error | dropped | reprocess_requested
  license_id TEXT,
  target_ref TEXT,                 -- pending_target: the provider id the event waits for
  action TEXT,                     -- JSON, only what re-processing needs (no raw body)
  error TEXT,
  body_sha256 TEXT,
  claim TEXT,                      -- per-attempt nonce (claim-then-act)
  PRIMARY KEY (provider, event_id)
);
CREATE INDEX webhook_events_result ON webhook_events (result, received_at);
CREATE INDEX webhook_events_target ON webhook_events (provider, target_ref) WHERE result = 'pending_target';

CREATE TABLE deliveries (
  id TEXT PRIMARY KEY,
  license_id TEXT,                 -- NULL for a "resend my keys" email
  kind TEXT NOT NULL,              -- key_issued | resend | refund_notice
  email TEXT NOT NULL,
  status TEXT NOT NULL,            -- pending | sending | sent | retry | failed | unknown | retry_requested
  attempts INTEGER NOT NULL DEFAULT 0,
  next_at INTEGER NOT NULL,
  claimed_at INTEGER,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  sent_at INTEGER
);
CREATE INDEX deliveries_due ON deliveries (status, next_at);

CREATE TABLE rate (
  bucket TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (bucket, window_start)
);
CREATE INDEX rate_expires ON rate (expires_at);

-- One row per UTC day: JSON {metric: count}, added to by each flush (one row write).
CREATE TABLE footprint (
  day TEXT PRIMARY KEY,
  data TEXT NOT NULL
);

CREATE TABLE state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
INSERT INTO state (key, value) VALUES ('sweep_at', '0'), ('schema_version', '1'), ('config_hash', '');
