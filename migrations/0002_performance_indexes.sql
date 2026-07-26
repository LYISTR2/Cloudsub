-- 0002_performance_indexes
-- Adds covering indexes for the two hottest read paths:
--   1. Subscription generation filters nodes by (source_id, present, enabled).
--   2. The dashboard/subscription list views resolve the latest enabled token
--      per subscription, ordered by created_at.
-- Both are additive and safe to apply to an existing database.

CREATE INDEX IF NOT EXISTS idx_nodes_source_present_enabled
  ON nodes (source_id, present, enabled);

CREATE INDEX IF NOT EXISTS idx_subscription_tokens_subscription
  ON subscription_tokens (subscription_id, enabled, created_at DESC);
