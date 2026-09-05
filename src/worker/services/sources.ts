import type { NormalizedNode } from "../../shared/types";
import { parseStandaloneUri, parseSubscriptionContent } from "../adapters/input";
import type { Env } from "../env";
import { decryptJson, randomToken, sha256Hex } from "../security/crypto";
import { safeFetchText } from "../security/safe-fetch";
import { AppError, publicErrorMessage } from "../shared/errors";

interface SourceRow {
  id: string;
  name: string;
  type: "url" | "manual";
  source_kind: "subscription" | "standalone";
  url: string | null;
  payload_encrypted: string | null;
  user_agent: string | null;
  enabled: number;
  refresh_interval: number;
  timeout_ms: number;
  last_attempt_at: string | null;
  content_hash: string | null;
}

interface SourcePayload {
  content?: string;
  headers?: Record<string, string>;
  url?: string;
}

// A refresh lease that outlives the worst-case refresh (30s timeout +
// parsing + promotion) so a crashed refresh cannot deadlock the source,
// while still being short enough that a stale lease is re-acquirable.
const LEASE_TTL_MS = 120_000;
const LEASE_ID_BYTES = 12;

async function sourceContent(env: Env, source: SourceRow): Promise<{ text: string; bytes: number }> {
  if (!env.DATA_ENCRYPTION_KEY) throw new AppError(503, "尚未配置数据加密密钥", "missing_encryption_key");
  const payload = source.payload_encrypted ? await decryptJson<SourcePayload>(source.payload_encrypted, env.DATA_ENCRYPTION_KEY) : {};
  if (source.type === "manual") {
    const text = payload.content ?? "";
    const bytes = new TextEncoder().encode(text).byteLength;
    const maxBytes = Math.max(1024, Math.min(Number(env.MAX_SOURCE_SIZE) || 5_242_880, 10_485_760));
    if (bytes > maxBytes) throw new AppError(413, "数据源内容超过大小限制", "source_too_large");
    return { text, bytes };
  }
  const upstreamUrl = payload.url ?? source.url;
  if (!upstreamUrl) throw new AppError(422, "数据源缺少上游地址", "missing_source_url");
  return safeFetchText({
    url: upstreamUrl,
    headers: payload.headers,
    userAgent: source.user_agent ?? "CloudSub/0.1",
    timeoutMs: Math.max(1000, Math.min(source.timeout_ms, 30_000)),
    maxBytes: Math.max(1024, Math.min(Number(env.MAX_SOURCE_SIZE) || 5_242_880, 10_485_760)),
  });
}

/**
 * Stage one parsed node into `nodes_staging`. Staging rows are internal:
 * they are replaced wholesale on every refresh and only reach `nodes` via
 * the atomic promotion batch.
 */
function stagingStatement(env: Env, sourceId: string, node: NormalizedNode, now: string): D1PreparedStatement {
  return env.DB.prepare(
    "INSERT INTO nodes_staging (id, source_id, fingerprint, name, protocol, server, port, config_json, tags_json, raw_uri, enabled, present, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, ?) ON CONFLICT(source_id, fingerprint) DO UPDATE SET protocol = excluded.protocol, server = excluded.server, port = excluded.port, config_json = excluded.config_json, raw_uri = excluded.raw_uri, updated_at = excluded.updated_at",
  ).bind(
    crypto.randomUUID(), sourceId, node.fingerprint, node.name, node.protocol, node.server, node.port,
    JSON.stringify(node.config), JSON.stringify(node.tags), node.rawUri ?? null, now, now,
  );
}

async function batchInChunks(env: Env, statements: D1PreparedStatement[]): Promise<void> {
  for (let offset = 0; offset < statements.length; offset += 75) {
    await env.DB.batch(statements.slice(offset, offset + 75));
  }
}

function leaseValue(): { lease: string; expiresAt: string } {
  const leaseId = randomToken(LEASE_ID_BYTES);
  const expiresAt = new Date(Date.now() + LEASE_TTL_MS).toISOString();
  return { lease: leaseId + ":" + expiresAt, expiresAt };
}

/**
 * Acquire the per-source refresh lease atomically. The guarded UPDATE only
 * succeeds when no live lease exists (absent or already expired), so two
 * concurrent refreshes of the same source can never both proceed.
 * Lease format: `<leaseId>:<expiresAtISO>`; the expiry is read with
 * `instr` so it works regardless of the stored lease's id length.
 */
async function acquireRefreshLease(env: Env, sourceId: string): Promise<string | null> {
  const { lease } = leaseValue();
  const now = new Date().toISOString();
  const result = await env.DB.prepare(
    "UPDATE sources SET refresh_lease = ?, updated_at = ? WHERE id = ? AND (refresh_lease IS NULL OR refresh_lease = '' OR substr(refresh_lease, instr(refresh_lease, ':') + 1) <= ?)",
  ).bind(lease, now, sourceId, now).run();
  return result.meta.changes > 0 ? lease : null;
}

/** Release the lease only while it still belongs to this refresh. */
async function releaseRefreshLease(env: Env, sourceId: string, lease: string): Promise<void> {
  await env.DB.prepare("UPDATE sources SET refresh_lease = NULL, updated_at = ? WHERE id = ? AND refresh_lease = ?")
    .bind(new Date().toISOString(), sourceId, lease).run();
}

/**
 * Promote the staged node set into `nodes` atomically.
 *
 * The entire promotion — demoting old rows, upserting from staging (which
 * deliberately preserves the user's name/enabled/tags edits on matching
 * fingerprints), updating the source row, bumping every affected
 * subscription revision and recording the success log — is a single D1
 * batch, which D1 executes atomically. If any statement fails, none of it
 * applies and the previously promoted (last-good) node set remains served.
 */
async function promoteStagedNodes(env: Env, sourceId: string, source: SourceRow, nodes: NormalizedNode[], content: { text: string; bytes: number }, contentHash: string, started: number, now: string): Promise<void> {
  const nextRefresh = new Date(Date.now() + Math.max(5, source.refresh_interval) * 60_000).toISOString();
  await env.DB.batch([
    env.DB.prepare("UPDATE nodes SET present = 0, updated_at = ? WHERE source_id = ? AND present = 1").bind(now, sourceId),
    env.DB.prepare(
      "INSERT INTO nodes (id, source_id, fingerprint, name, protocol, server, port, config_json, tags_json, raw_uri, enabled, present, created_at, updated_at) " +
      "SELECT id, source_id, fingerprint, name, protocol, server, port, config_json, tags_json, raw_uri, enabled, present, created_at, updated_at FROM nodes_staging WHERE source_id = ? " +
      "ON CONFLICT(source_id, fingerprint) DO UPDATE SET protocol = excluded.protocol, server = excluded.server, port = excluded.port, config_json = excluded.config_json, raw_uri = excluded.raw_uri, present = 1, updated_at = excluded.updated_at",
    ).bind(sourceId),
    env.DB.prepare("UPDATE sources SET last_success_at = ?, last_error = NULL, content_hash = ?, next_refresh_at = ?, updated_at = ? WHERE id = ?").bind(now, contentHash, nextRefresh, now, sourceId),
    env.DB.prepare("INSERT INTO source_fetch_logs (id, source_id, status, node_count, bytes, duration_ms, error, created_at) VALUES (?, ?, 'success', ?, ?, ?, NULL, ?)").bind(crypto.randomUUID(), sourceId, nodes.length, content.bytes, Date.now() - started, now),
    env.DB.prepare("UPDATE subscriptions SET revision = revision + 1, updated_at = ? WHERE id IN (SELECT subscription_id FROM subscription_sources WHERE source_id = ?)").bind(now, sourceId),
  ]);
}

export async function refreshSource(env: Env, sourceId: string, options: { force?: boolean } = {}): Promise<{ nodeCount: number; bytes: number; changed: boolean }> {
  const source = await env.DB.prepare("SELECT id, name, type, source_kind, url, payload_encrypted, user_agent, enabled, refresh_interval, timeout_ms, last_attempt_at, content_hash FROM sources WHERE id = ? LIMIT 1").bind(sourceId).first<SourceRow>();
  if (!source) throw new AppError(404, "数据源不存在", "source_not_found");
  if (!source.enabled && !options.force) throw new AppError(409, "数据源已停用", "source_disabled");
  if (source.last_attempt_at && !options.force && Date.now() - new Date(source.last_attempt_at).getTime() < 30_000) {
    throw new AppError(429, "刷新过于频繁，请稍后重试", "refresh_cooldown");
  }

  const started = Date.now();
  const now = new Date().toISOString();
  // Serialize concurrent refreshes of this source: only one refresh may hold
  // the lease; everyone else gets a 409 instead of racing the promotion.
  const lease = await acquireRefreshLease(env, sourceId);
  if (!lease) throw new AppError(409, "该数据源正在刷新中", "refresh_in_progress");
  // Record the attempt only after acquiring the lease. Otherwise a competing
  // request would create a cooldown without ever performing a refresh.
  await env.DB.prepare("UPDATE sources SET last_attempt_at = ?, updated_at = ? WHERE id = ? AND refresh_lease = ?")
    .bind(now, now, sourceId, lease).run();
  try {
    const content = await sourceContent(env, source);
    // Standalone sources keep their strict single-URI invariant on refresh
    // too; anything else fails the refresh and leaves the last-good node set
    // untouched.
    const nodes = source.source_kind === "standalone"
      ? [await parseStandaloneUri(content.text)]
      : await parseSubscriptionContent(content.text);
    const contentHash = await sha256Hex(content.text);

    if (contentHash === source.content_hash) {
      // No-op refresh: same content, nothing changed. Skip every node write
      // and, crucially, do NOT bump subscription revisions (the cached
      // subscription output stays valid). Only bookkeeping is updated.
      const nextRefresh = new Date(Date.now() + Math.max(5, source.refresh_interval) * 60_000).toISOString();
      await env.DB.batch([
        env.DB.prepare("UPDATE sources SET last_success_at = ?, last_error = NULL, content_hash = ?, next_refresh_at = ?, updated_at = ? WHERE id = ?").bind(now, contentHash, nextRefresh, now, sourceId),
        env.DB.prepare("INSERT INTO source_fetch_logs (id, source_id, status, node_count, bytes, duration_ms, error, created_at) VALUES (?, ?, 'success', ?, ?, ?, NULL, ?)").bind(crypto.randomUUID(), sourceId, nodes.length, content.bytes, Date.now() - started, now),
      ]);
      return { nodeCount: nodes.length, bytes: content.bytes, changed: false };
    }

    // Stage the freshly parsed set (idempotent, touches only nodes_staging),
    // then promote it with one atomic batch.
    await env.DB.prepare("DELETE FROM nodes_staging WHERE source_id = ?").bind(sourceId).run();
    await batchInChunks(env, nodes.map((node) => stagingStatement(env, sourceId, node, now)));
    await promoteStagedNodes(env, sourceId, source, nodes, content, contentHash, started, now);
    return { nodeCount: nodes.length, bytes: content.bytes, changed: true };
  } catch (error) {
    // Any failure leaves the previously promoted node set fully intact:
    // staging writes never touch `nodes`, and the promotion batch is atomic.
    const message = publicErrorMessage(error).slice(0, 500);
    await env.DB.batch([
      env.DB.prepare("UPDATE sources SET last_error = ?, updated_at = ? WHERE id = ?").bind(message, now, sourceId),
      env.DB.prepare("INSERT INTO source_fetch_logs (id, source_id, status, node_count, bytes, duration_ms, error, created_at) VALUES (?, ?, 'error', 0, 0, ?, ?, ?)").bind(crypto.randomUUID(), sourceId, Date.now() - started, message, now),
    ]);
    throw error;
  } finally {
    // Release only if the lease is still ours (an expired lease taken over
    // by a newer refresh is never clobbered).
    await releaseRefreshLease(env, sourceId, lease);
  }
}

export async function refreshDueSources(env: Env): Promise<void> {
  const now = new Date().toISOString();
  // Refresh due sources — process in batches of 10, sorted by next_refresh_at
  const result = await env.DB.prepare(
    "SELECT id FROM sources WHERE enabled = 1 AND type = 'url' AND (next_refresh_at IS NULL OR next_refresh_at <= ?) ORDER BY next_refresh_at ASC NULLS FIRST LIMIT 20",
  ).bind(now).all<{ id: string }>();
  for (const source of result.results) {
    try { await refreshSource(env, source.id); } catch { /* The refresh service records a sanitized failure log. */ }
  }
  // Clean up expired sessions
  await env.DB.prepare("DELETE FROM sessions WHERE expires_at <= ?").bind(now).run();
  // Clean up old fetch logs (keep last 7 days)
  const cutoff = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  await env.DB.prepare("DELETE FROM source_fetch_logs WHERE created_at <= ?").bind(cutoff).run();
}
