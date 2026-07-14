import type { NormalizedNode, SubscriptionRules, SubscriptionTarget } from "../../shared/types";
import { applySubscriptionRules, renderSubscription } from "../adapters/output";
import type { Env } from "../env";
import { hmacSha256Hex, randomToken, sha256Hex } from "../security/crypto";
import { AppError } from "../shared/errors";

interface AccessRow {
  token_id: string;
  subscription_id: string;
  name: string;
  slug: string;
  default_target: SubscriptionTarget;
  rules_json: string;
  revision: number;
  cache_ttl: number;
  subscription_expires_at: string | null;
  token_expires_at: string | null;
}

interface NodeRow {
  id: string;
  source_id: string;
  fingerprint: string;
  name: string;
  protocol: string;
  server: string;
  port: number;
  config_json: string;
  tags_json: string;
  raw_uri: string | null;
  enabled: number;
}

export async function issueSubscriptionToken(env: Env, subscriptionId: string): Promise<{ token: string; prefix: string }> {
  if (!env.APP_SECRET) throw new AppError(503, "尚未配置应用密钥", "missing_app_secret");
  const token = randomToken(32);
  const prefix = token.slice(0, 8);
  await env.DB.prepare(
    "INSERT INTO subscription_tokens (id, subscription_id, token_hash, token_prefix, enabled, created_at) VALUES (?, ?, ?, ?, 1, ?)",
  ).bind(crypto.randomUUID(), subscriptionId, await hmacSha256Hex(env.APP_SECRET, token), prefix, new Date().toISOString()).run();
  return { token, prefix };
}

function parseRules(value: string): SubscriptionRules {
  try { return JSON.parse(value) as SubscriptionRules; } catch { return {}; }
}

function rowToNode(row: NodeRow): NormalizedNode {
  return {
    id: row.id,
    sourceId: row.source_id,
    fingerprint: row.fingerprint,
    name: row.name,
    protocol: row.protocol,
    server: row.server,
    port: row.port,
    config: JSON.parse(row.config_json) as Record<string, unknown>,
    tags: JSON.parse(row.tags_json) as string[],
    rawUri: row.raw_uri ?? undefined,
    enabled: Boolean(row.enabled),
  };
}

export async function generateSubscription(env: Env, token: string, requestedTarget?: string): Promise<{
  body: string;
  contentType: string;
  extension: string;
  etag: string;
  name: string;
  cacheTtl: number;
  tokenId: string;
}> {
  if (token.length < 32 || token.length > 200) throw new AppError(404, "订阅不可用", "subscription_unavailable");
  const now = new Date().toISOString();
  if (!env.APP_SECRET) throw new AppError(503, "尚未配置应用密钥", "missing_app_secret");
  const access = await env.DB.prepare(
    "SELECT t.id AS token_id, s.id AS subscription_id, s.name, s.slug, s.default_target, s.rules_json, s.revision, s.cache_ttl, s.expires_at AS subscription_expires_at, t.expires_at AS token_expires_at FROM subscription_tokens t JOIN subscriptions s ON s.id = t.subscription_id WHERE t.token_hash = ? AND t.enabled = 1 AND s.enabled = 1 LIMIT 1",
  ).bind(await hmacSha256Hex(env.APP_SECRET, token)).first<AccessRow>();
  if (!access || (access.subscription_expires_at && access.subscription_expires_at <= now) || (access.token_expires_at && access.token_expires_at <= now)) {
    throw new AppError(404, "订阅不可用", "subscription_unavailable");
  }
  const target = (requestedTarget || access.default_target) as SubscriptionTarget;
  if (!["raw", "mihomo", "json"].includes(target)) throw new AppError(404, "订阅不可用", "subscription_unavailable");
  const cacheKey = "subscription:" + access.subscription_id + ":" + target + ":" + access.revision;
  const cached = await env.CACHE.get<{ body: string; contentType: string; extension: string; etag: string }>(cacheKey, "json");
  const cacheTtl = Math.max(60, Math.min(access.cache_ttl || Number(env.SUB_CACHE_TTL) || 300, 86_400));
  if (cached) return { ...cached, name: access.slug || access.name, cacheTtl, tokenId: access.token_id };
  const result = await env.DB.prepare(
    "SELECT n.* FROM nodes n JOIN subscription_sources ss ON ss.source_id = n.source_id WHERE ss.subscription_id = ? AND n.enabled = 1 AND n.present = 1",
  ).bind(access.subscription_id).all<NodeRow>();
  const nodes = applySubscriptionRules(result.results.map(rowToNode), parseRules(access.rules_json));
  const rendered = renderSubscription(nodes, target);
  const etag = '"' + await sha256Hex(rendered.body) + '"';
  await env.CACHE.put(cacheKey, JSON.stringify({ ...rendered, etag }), { expirationTtl: cacheTtl });
  await env.DB.prepare("UPDATE subscriptions SET last_generated_at = ? WHERE id = ?").bind(now, access.subscription_id).run();
  return { ...rendered, etag, name: access.slug || access.name, cacheTtl, tokenId: access.token_id };
}
