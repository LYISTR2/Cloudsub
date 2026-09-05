import type { Hono } from "hono";
import type { NormalizedNode, SubscriptionRules, SubscriptionTarget } from "../../shared/types";
import { applySubscriptionRules, renderSubscription } from "../adapters/output";
import type { AppBindings, Env } from "../env";
import { body, pageParams, slugify } from "../http";
import { writeAudit } from "../services/audit";
import { issueSubscriptionToken } from "../services/subscriptions";
import { AppError } from "../shared/errors";
import { previewSchema, subscriptionCreateSchema, subscriptionUpdateSchema } from "../validation";

async function subscriptionPreview(env: Env, id: string, targetOverride?: SubscriptionTarget): Promise<{ rendered: ReturnType<typeof renderSubscription>; count: number }> {
  const subscription = await env.DB.prepare("SELECT default_target, rules_json FROM subscriptions WHERE id = ?").bind(id).first<{ default_target: SubscriptionTarget; rules_json: string }>();
  if (!subscription) throw new AppError(404, "订阅不存在", "subscription_not_found");
  const result = await env.DB.prepare("SELECT n.* FROM nodes n JOIN subscription_sources ss ON ss.source_id = n.source_id JOIN sources s ON s.id = n.source_id WHERE ss.subscription_id = ? AND s.enabled = 1 AND n.enabled = 1 AND n.present = 1").bind(id).all<any>();
  const nodes: NormalizedNode[] = result.results.map((row) => ({
    id: row.id, sourceId: row.source_id, fingerprint: row.fingerprint, name: row.name, protocol: row.protocol, server: row.server, port: row.port,
    config: JSON.parse(row.config_json), tags: JSON.parse(row.tags_json), rawUri: row.raw_uri ?? undefined, enabled: Boolean(row.enabled),
  }));
  const filtered = applySubscriptionRules(nodes, JSON.parse(subscription.rules_json) as SubscriptionRules);
  return { rendered: renderSubscription(filtered, targetOverride ?? subscription.default_target), count: filtered.length };
}

/** CRUD + token rotation + preview + cache invalidation for subscriptions. */
export function registerSubscriptionRoutes(app: Hono<AppBindings>): void {
  app.get("/api/subscriptions", async (context) => {
    const { page, pageSize, offset } = pageParams(context);
    const [items, total] = await Promise.all([
      context.env.DB.prepare("SELECT s.id, s.name, s.slug, s.enabled, s.default_target, s.rules_json, s.revision, s.expires_at, s.cache_ttl, s.last_generated_at, s.created_at, s.updated_at, GROUP_CONCAT(DISTINCT ss.source_id) AS source_ids, (SELECT token_prefix FROM subscription_tokens t WHERE t.subscription_id = s.id AND t.enabled = 1 ORDER BY t.created_at DESC LIMIT 1) AS token_prefix, (SELECT last_access_at FROM subscription_tokens t WHERE t.subscription_id = s.id AND t.enabled = 1 ORDER BY t.created_at DESC LIMIT 1) AS last_access_at FROM subscriptions s LEFT JOIN subscription_sources ss ON ss.subscription_id = s.id GROUP BY s.id ORDER BY s.created_at DESC LIMIT ? OFFSET ?").bind(pageSize, offset).all<any>(),
      context.env.DB.prepare("SELECT COUNT(*) AS count FROM subscriptions").first<{ count: number }>(),
    ]);
    return context.json({ data: { items: items.results.map((item) => ({ ...item, sourceIds: item.source_ids ? String(item.source_ids).split(",") : [], rules: JSON.parse(item.rules_json), source_ids: undefined, rules_json: undefined })), page, pageSize, total: total?.count ?? 0 } });
  });

  app.post("/api/subscriptions", async (context) => {
    const input = await body(context, subscriptionCreateSchema);
    const placeholders = input.sourceIds.map(() => "?").join(",");
    const available = await context.env.DB.prepare("SELECT COUNT(*) AS count FROM sources WHERE id IN (" + placeholders + ")").bind(...input.sourceIds).first<{ count: number }>();
    if (available?.count !== new Set(input.sourceIds).size) throw new AppError(422, "包含不存在的数据源", "invalid_source_selection");
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const baseSlug = slugify(input.name);
    const collision = await context.env.DB.prepare("SELECT id FROM subscriptions WHERE slug = ?").bind(baseSlug).first();
    const slug = collision ? baseSlug + "-" + id.slice(0, 6) : baseSlug;
    await context.env.DB.batch([
      context.env.DB.prepare("INSERT INTO subscriptions (id, name, slug, enabled, default_target, rules_json, revision, expires_at, cache_ttl, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)").bind(id, input.name, slug, input.enabled ? 1 : 0, input.defaultTarget, JSON.stringify(input.rules), input.expiresAt ?? null, input.cacheTtl, now, now),
      ...[...new Set(input.sourceIds)].map((sourceId) => context.env.DB.prepare("INSERT INTO subscription_sources (subscription_id, source_id) VALUES (?, ?)").bind(id, sourceId)),
    ]);
    const token = await issueSubscriptionToken(context.env, id, input.expiresAt ?? undefined);
    const principal = context.get("principal");
    await writeAudit(context.env, { adminId: principal.adminId, action: "subscription.create", targetType: "subscription", targetId: id, details: { name: input.name, sources: input.sourceIds.length }, requestId: context.get("requestId") });
    return context.json({ data: { id, slug, token: token.token, tokenPrefix: token.prefix } }, 201);
  });

  app.get("/api/subscriptions/:id", async (context) => {
    const item = await context.env.DB.prepare("SELECT s.*, GROUP_CONCAT(ss.source_id) AS source_ids, (SELECT token_prefix FROM subscription_tokens t WHERE t.subscription_id = s.id AND t.enabled = 1 ORDER BY t.created_at DESC LIMIT 1) AS token_prefix FROM subscriptions s LEFT JOIN subscription_sources ss ON ss.subscription_id = s.id WHERE s.id = ? GROUP BY s.id").bind(context.req.param("id")).first<any>();
    if (!item) throw new AppError(404, "订阅不存在", "subscription_not_found");
    return context.json({ data: { ...item, sourceIds: item.source_ids ? String(item.source_ids).split(",") : [], rules: JSON.parse(item.rules_json), source_ids: undefined, rules_json: undefined } });
  });

  app.put("/api/subscriptions/:id", async (context) => {
    const input = await body(context, subscriptionUpdateSchema);
    const id = context.req.param("id");
    const current = await context.env.DB.prepare("SELECT * FROM subscriptions WHERE id = ?").bind(id).first<any>();
    if (!current) throw new AppError(404, "订阅不存在", "subscription_not_found");
    if (input.sourceIds) {
      const placeholders = input.sourceIds.map(() => "?").join(",");
      const available = await context.env.DB.prepare("SELECT COUNT(*) AS count FROM sources WHERE id IN (" + placeholders + ")").bind(...input.sourceIds).first<{ count: number }>();
      if (available?.count !== new Set(input.sourceIds).size) throw new AppError(422, "包含不存在的数据源", "invalid_source_selection");
    }
    const now = new Date().toISOString();
    const statements: D1PreparedStatement[] = [
      context.env.DB.prepare("UPDATE subscriptions SET name = ?, enabled = ?, default_target = ?, rules_json = ?, revision = revision + 1, expires_at = ?, cache_ttl = ?, updated_at = ? WHERE id = ?").bind(
        input.name ?? current.name,
        (input.enabled ?? Boolean(current.enabled)) ? 1 : 0,
        input.defaultTarget ?? current.default_target,
        JSON.stringify(input.rules ?? JSON.parse(current.rules_json)),
        input.expiresAt === undefined ? current.expires_at : input.expiresAt,
        input.cacheTtl ?? current.cache_ttl,
        now,
        id,
      ),
    ];
    if (input.sourceIds) {
      statements.push(
        context.env.DB.prepare("DELETE FROM subscription_sources WHERE subscription_id = ?").bind(id),
        ...[...new Set(input.sourceIds)].map((sourceId) => context.env.DB.prepare("INSERT INTO subscription_sources (subscription_id, source_id) VALUES (?, ?)").bind(id, sourceId)),
      );
    }
    await context.env.DB.batch(statements);
    const principal = context.get("principal");
    await writeAudit(context.env, { adminId: principal.adminId, action: "subscription.update", targetType: "subscription", targetId: id, requestId: context.get("requestId") });
    return context.json({ data: { id } });
  });

  app.delete("/api/subscriptions/:id", async (context) => {
    const id = context.req.param("id");
    const result = await context.env.DB.prepare("DELETE FROM subscriptions WHERE id = ?").bind(id).run();
    if (!result.meta.changes) throw new AppError(404, "订阅不存在", "subscription_not_found");
    const principal = context.get("principal");
    await writeAudit(context.env, { adminId: principal.adminId, action: "subscription.delete", targetType: "subscription", targetId: id, requestId: context.get("requestId") });
    return context.json({ data: { ok: true } });
  });

  app.post("/api/subscriptions/:id/preview", async (context) => {
    const input = await body(context, previewSchema);
    const preview = await subscriptionPreview(context.env, context.req.param("id"), input.target);
    return context.json({ data: { body: preview.rendered.body.slice(0, 200_000), contentType: preview.rendered.contentType, truncated: preview.rendered.body.length > 200_000, nodeCount: preview.count } });
  });

  app.post("/api/subscriptions/:id/rotate-token", async (context) => {
    const id = context.req.param("id");
    const exists = await context.env.DB.prepare("SELECT id FROM subscriptions WHERE id = ?").bind(id).first();
    if (!exists) throw new AppError(404, "订阅不存在", "subscription_not_found");
    const now = new Date().toISOString();
    await context.env.DB.batch([
      context.env.DB.prepare("UPDATE subscription_tokens SET enabled = 0 WHERE subscription_id = ?").bind(id),
      context.env.DB.prepare("UPDATE subscriptions SET revision = revision + 1, updated_at = ? WHERE id = ?").bind(now, id),
    ]);
    const token = await issueSubscriptionToken(context.env, id);
    const principal = context.get("principal");
    await writeAudit(context.env, { adminId: principal.adminId, action: "subscription.token.rotate", targetType: "subscription", targetId: id, requestId: context.get("requestId") });
    return context.json({ data: { token: token.token, tokenPrefix: token.prefix } });
  });

  app.post("/api/subscriptions/:id/invalidate-cache", async (context) => {
    const now = new Date().toISOString();
    const result = await context.env.DB.prepare("UPDATE subscriptions SET revision = revision + 1, updated_at = ? WHERE id = ?").bind(now, context.req.param("id")).run();
    if (!result.meta.changes) throw new AppError(404, "订阅不存在", "subscription_not_found");
    return context.json({ data: { ok: true } });
  });
}
