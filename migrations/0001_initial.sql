PRAGMA foreign_keys = ON;

CREATE TABLE admins (
  id TEXT PRIMARY KEY NOT NULL,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY NOT NULL,
  admin_id TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  csrf_token TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE settings (
  key TEXT PRIMARY KEY NOT NULL,
  value_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE sources (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('url', 'manual')),
  url TEXT,
  payload_encrypted TEXT,
  user_agent TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  refresh_interval INTEGER NOT NULL DEFAULT 60,
  timeout_ms INTEGER NOT NULL DEFAULT 15000,
  next_refresh_at TEXT,
  last_attempt_at TEXT,
  last_success_at TEXT,
  last_error TEXT,
  content_hash TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE source_fetch_logs (
  id TEXT PRIMARY KEY NOT NULL,
  source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  status TEXT NOT NULL,
  node_count INTEGER NOT NULL DEFAULT 0,
  bytes INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE nodes (
  id TEXT PRIMARY KEY NOT NULL,
  source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL,
  name TEXT NOT NULL,
  protocol TEXT NOT NULL,
  server TEXT NOT NULL,
  port INTEGER NOT NULL,
  config_json TEXT NOT NULL,
  tags_json TEXT NOT NULL DEFAULT '[]',
  raw_uri TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  present INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (source_id, fingerprint)
);

CREATE TABLE templates (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  target TEXT NOT NULL,
  content TEXT NOT NULL,
  is_default INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE subscriptions (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  enabled INTEGER NOT NULL DEFAULT 1,
  default_target TEXT NOT NULL DEFAULT 'mihomo',
  rules_json TEXT NOT NULL DEFAULT '{}',
  template_id TEXT REFERENCES templates(id) ON DELETE SET NULL,
  revision INTEGER NOT NULL DEFAULT 1,
  expires_at TEXT,
  cache_ttl INTEGER NOT NULL DEFAULT 300,
  last_generated_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE subscription_sources (
  subscription_id TEXT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
  source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  PRIMARY KEY (subscription_id, source_id)
);

CREATE TABLE subscription_tokens (
  id TEXT PRIMARY KEY NOT NULL,
  subscription_id TEXT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  token_prefix TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_access_at TEXT,
  expires_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE audit_logs (
  id TEXT PRIMARY KEY NOT NULL,
  admin_id TEXT REFERENCES admins(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  details_json TEXT NOT NULL DEFAULT '{}',
  request_id TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sources_next_refresh_at ON sources(enabled, next_refresh_at);
CREATE INDEX idx_source_logs_source_created ON source_fetch_logs(source_id, created_at DESC);
CREATE INDEX idx_nodes_source_present ON nodes(source_id, present);
CREATE INDEX idx_nodes_protocol_enabled ON nodes(protocol, enabled, present);
CREATE INDEX idx_nodes_fingerprint ON nodes(fingerprint);
CREATE INDEX idx_subscription_tokens_hash ON subscription_tokens(token_hash);
CREATE INDEX idx_subscription_sources_source ON subscription_sources(source_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);
