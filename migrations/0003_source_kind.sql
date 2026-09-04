-- 0003_source_kind
-- Distinguishes subscription feeds from standalone single-node sources.
--   * 'subscription' — upstream URL or manual multi-node configuration
--     (existing rows are backfilled to this value via the column default).
--   * 'standalone'   — a manual source whose content is exactly one node URI.
-- SQLite cannot add a CHECK constraint with ALTER TABLE, so the value space
-- is enforced by the application schema (drizzle enum) and a covering index.

ALTER TABLE sources ADD COLUMN source_kind TEXT NOT NULL DEFAULT 'subscription';

CREATE INDEX IF NOT EXISTS idx_sources_source_kind
  ON sources (source_kind);
