-- 0004_refresh_safety
-- Refresh-safety support for atomic source refreshes:
--
--   1. `sources.refresh_lease` — an atomic lease used to serialize
--      concurrent refreshes of the same source. Format: `<leaseId>:<expiresAtISO>`.
--      A refresh acquires the lease with a guarded UPDATE (only when the
--      previous lease is absent or expired), and releases it only while the
--      lease still carries its own lease id (so an expired lease taken over
--      by a newer refresh is never clobbered).
--
--   2. `nodes_staging` — a staging buffer for parsed node sets. A refresh
--      writes the freshly parsed nodes here first (chunked, idempotent),
--      then promotes them into `nodes` with a single atomic D1 batch
--      (demote old rows, upsert from staging, update the source, bump
--      subscription revisions, record the success log). Because the whole
--      promotion is one batch, a failure before it leaves the previously
--      promoted node set fully intact (last-good preservation). A failure
--      during staging only ever touches `nodes_staging`, never `nodes`.
--
-- Both changes are purely additive and safe to apply to an existing
-- database. Existing node rows keep `present = 1`; there is no backfill.

ALTER TABLE sources ADD COLUMN refresh_lease TEXT;

CREATE TABLE nodes_staging (
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

CREATE INDEX IF NOT EXISTS idx_nodes_staging_source ON nodes_staging (source_id);
