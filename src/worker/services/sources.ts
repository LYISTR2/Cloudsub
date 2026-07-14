import type { NormalizedNode } from "../../shared/types";
import { parseSubscriptionContent } from "../adapters/input";
import type { Env } from "../env";
import { decryptJson, sha256Hex } from "../security/crypto";
import { safeFetchText } from "../security/safe-fetch";
import { AppError, publicErrorMessage } from "../shared/errors";

interface SourceRow {
  id: string;
  name: string;
  type: "url" | "manual";
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

function nodeStatement(env: Env, sourceId: string, node: NormalizedNode, now: string): D1PreparedStatement {
  return env.DB.prepare(
    "INSERT INTO nodes (id, source_id, fingerprint, name, protocol, server, port, config_json, tags_json, raw_uri, enabled, present, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, ?) ON CONFLICT(source_id, fingerprint) DO UPDATE SET protocol = excluded.protocol, server = excluded.server, port = excluded.port, config_json = excluded.config_json, raw_uri = excluded.raw_uri, present = 1, updated_at = excluded.updated_at",
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

export async function refreshSource(env: Env, sourceId: string, options: { force?: boolean } = {}): Promise<{ nodeCount: number; bytes: number; changed: boolean }> {
  const source = await env.DB.prepare("SELECT * FROM sources WHERE id = ? LIMIT 1").bind(sourceId).first<SourceRow>();
  if (!source) throw new AppError(404, "数据源不存在", "source_not_found");
  if (!source.enabled && !options.force) throw new AppError(409, "数据源已停用", "source_disabled");
  if (source.last_attempt_at && !options.force && Date.now() - new Date(source.last_attempt_at).getTime() < 30_000) {
    throw new AppError(429, "刷新过于频繁，请稍后重试", "refresh_cooldown");
  }
  const started = Date.now();
  const now = new Date().toISOString();
  await env.DB.prepare("UPDATE sources SET last_attempt_at = ?, updated_at = ? WHERE id = ?").bind(now, now, sourceId).run();
  try {
    const content = await sourceContent(env, source);
    const nodes = await parseSubscriptionContent(content.text);
    const contentHash = await sha256Hex(content.text);
    await env.DB.prepare("UPDATE nodes SET present = 0, updated_at = ? WHERE source_id = ?").bind(now, sourceId).run();
    await batchInChunks(env, nodes.map((node) => nodeStatement(env, sourceId, node, now)));
    const nextRefresh = new Date(Date.now() + Math.max(5, source.refresh_interval) * 60_000).toISOString();
    const changed = contentHash !== source.content_hash;
    await env.DB.batch([
      env.DB.prepare("UPDATE sources SET last_success_at = ?, last_error = NULL, content_hash = ?, next_refresh_at = ?, updated_at = ? WHERE id = ?").bind(now, contentHash, nextRefresh, now, sourceId),
      env.DB.prepare("INSERT INTO source_fetch_logs (id, source_id, status, node_count, bytes, duration_ms, error, created_at) VALUES (?, ?, 'success', ?, ?, ?, NULL, ?)").bind(crypto.randomUUID(), sourceId, nodes.length, content.bytes, Date.now() - started, now),
      env.DB.prepare("UPDATE subscriptions SET revision = revision + 1, updated_at = ? WHERE id IN (SELECT subscription_id FROM subscription_sources WHERE source_id = ?)").bind(now, sourceId),
    ]);
    return { nodeCount: nodes.length, bytes: content.bytes, changed };
  } catch (error) {
    const message = publicErrorMessage(error).slice(0, 500);
    await env.DB.batch([
      env.DB.prepare("UPDATE sources SET last_error = ?, updated_at = ? WHERE id = ?").bind(message, now, sourceId),
      env.DB.prepare("INSERT INTO source_fetch_logs (id, source_id, status, node_count, bytes, duration_ms, error, created_at) VALUES (?, ?, 'error', 0, 0, ?, ?, ?)").bind(crypto.randomUUID(), sourceId, Date.now() - started, message, now),
    ]);
    throw error;
  }
}

export async function refreshDueSources(env: Env): Promise<void> {
  const now = new Date().toISOString();
  const result = await env.DB.prepare(
    "SELECT id FROM sources WHERE enabled = 1 AND type = 'url' AND (next_refresh_at IS NULL OR next_refresh_at <= ?) ORDER BY next_refresh_at ASC LIMIT 10",
  ).bind(now).all<{ id: string }>();
  for (const source of result.results) {
    try { await refreshSource(env, source.id); } catch { /* The refresh service records a sanitized failure log. */ }
  }
  await env.DB.prepare("DELETE FROM sessions WHERE expires_at <= ?").bind(now).run();
}
