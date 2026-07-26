import type { Hono } from "hono";
import type { AppBindings } from "../env";
import { body, likePattern, pageParams, redactedUpstreamUrl } from "../http";
import { decryptJson, encryptJson } from "../security/crypto";
import { validateUpstreamUrl } from "../security/safe-fetch";
import { writeAudit } from "../services/audit";
import { refreshSource } from "../services/sources";
import { AppError } from "../shared/errors";
import { sourceCreateSchema, sourceUpdateSchema } from "../validation";

function sourceSizeLimit(value: string | undefined): number {
  return Math.max(1024, Math.min(Number(value) || 5_242_880, 10_485_760));
}

/** CRUD + refresh + fetch-log routes for upstream/manual data sources. */
export function registerSourceRoutes(app: Hono<AppBindings>): void {
  app.get("/api/sources", async (context) => {
    const { page, pageSize, offset } = pageParams(context);
    const search = (context.req.query("q") ?? "").slice(0, 100);
    const pattern = likePattern(search);
    const [items, total] = await Promise.all([
      context.env.DB.prepare("SELECT s.id, s.name, s.type, s.url, s.enabled, s.refresh_interval, s.timeout_ms, s.next_refresh_at, s.last_success_at, s.last_error, s.created_at, s.updated_at, SUM(CASE WHEN n.present = 1 THEN 1 ELSE 0 END) AS node_count FROM sources s LEFT JOIN nodes n ON n.source_id = s.id WHERE s.name LIKE ? ESCAPE '\\' GROUP BY s.id ORDER BY s.created_at DESC LIMIT ? OFFSET ?").bind(pattern, pageSize, offset).all(),
      context.env.DB.prepare("SELECT COUNT(*) AS count FROM sources WHERE name LIKE ? ESCAPE '\\'").bind(pattern).first<{ count: number }>(),
    ]);
    return context.json({ data: { items: items.results, page, pageSize, total: total?.count ?? 0 } });
  });

  app.post("/api/sources", async (context) => {
    const input = await body(context, sourceCreateSchema);
    if (!context.env.DATA_ENCRYPTION_KEY) throw new AppError(503, "尚未配置数据加密密钥", "missing_encryption_key");
    if (input.type === "url") {
      if (!input.url) throw new AppError(422, "URL 数据源必须提供地址", "missing_source_url");
      validateUpstreamUrl(input.url);
    } else {
      if (!input.content) throw new AppError(422, "手动数据源必须提供内容", "missing_source_content");
      if (new TextEncoder().encode(input.content).byteLength > sourceSizeLimit(context.env.MAX_SOURCE_SIZE)) throw new AppError(413, "数据源内容超过大小限制", "source_too_large");
    }
    if (Object.keys(input.headers ?? {}).length > 20) throw new AppError(422, "请求头数量不能超过 20", "too_many_headers");
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const payload = await encryptJson({ content: input.type === "manual" ? input.content : undefined, headers: input.headers, url: input.type === "url" ? input.url : undefined }, context.env.DATA_ENCRYPTION_KEY);
    await context.env.DB.prepare("INSERT INTO sources (id, name, type, url, payload_encrypted, user_agent, enabled, refresh_interval, timeout_ms, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(
      id, input.name, input.type, input.type === "url" ? redactedUpstreamUrl(input.url!) : null, payload, input.userAgent ?? null, input.enabled ? 1 : 0, input.refreshInterval, input.timeoutMs, now, now,
    ).run();
    let refresh: unknown;
    let refreshError: string | undefined;
    try { refresh = await refreshSource(context.env, id, { force: true }); } catch (error) { refreshError = error instanceof AppError ? error.message : "首次解析失败"; }
    const principal = context.get("principal");
    await writeAudit(context.env, { adminId: principal.adminId, action: "source.create", targetType: "source", targetId: id, details: { name: input.name, type: input.type }, requestId: context.get("requestId") });
    return context.json({ data: { id, refresh, refreshError } }, 201);
  });

  app.get("/api/sources/:id", async (context) => {
    const source = await context.env.DB.prepare("SELECT id, name, type, url, user_agent, enabled, refresh_interval, timeout_ms, next_refresh_at, last_attempt_at, last_success_at, last_error, created_at, updated_at FROM sources WHERE id = ?").bind(context.req.param("id")).first();
    if (!source) throw new AppError(404, "数据源不存在", "source_not_found");
    return context.json({ data: source });
  });

  app.put("/api/sources/:id", async (context) => {
    const input = await body(context, sourceUpdateSchema);
    const id = context.req.param("id");
    const current = await context.env.DB.prepare("SELECT * FROM sources WHERE id = ?").bind(id).first<any>();
    if (!current) throw new AppError(404, "数据源不存在", "source_not_found");
    if (!context.env.DATA_ENCRYPTION_KEY) throw new AppError(503, "尚未配置数据加密密钥", "missing_encryption_key");
    const payload = current.payload_encrypted ? await decryptJson<{ content?: string; headers?: Record<string, string>; url?: string }>(current.payload_encrypted, context.env.DATA_ENCRYPTION_KEY) : {};
    if (input.url !== undefined) validateUpstreamUrl(input.url);
    if (input.content !== undefined) {
      if (new TextEncoder().encode(input.content).byteLength > sourceSizeLimit(context.env.MAX_SOURCE_SIZE)) throw new AppError(413, "数据源内容超过大小限制", "source_too_large");
    }
    if (input.headers !== undefined && Object.keys(input.headers).length > 20) throw new AppError(422, "请求头数量不能超过 20", "too_many_headers");
    const encrypted = await encryptJson({ content: input.content ?? payload.content, headers: input.headers ?? payload.headers, url: input.url ?? payload.url }, context.env.DATA_ENCRYPTION_KEY);
    const now = new Date().toISOString();
    await context.env.DB.prepare("UPDATE sources SET name = ?, url = ?, payload_encrypted = ?, user_agent = ?, enabled = ?, refresh_interval = ?, timeout_ms = ?, updated_at = ? WHERE id = ?").bind(
      input.name ?? current.name, input.url === undefined ? current.url : redactedUpstreamUrl(input.url), encrypted, input.userAgent ?? current.user_agent, (input.enabled ?? Boolean(current.enabled)) ? 1 : 0, input.refreshInterval ?? current.refresh_interval, input.timeoutMs ?? current.timeout_ms, now, id,
    ).run();
    const principal = context.get("principal");
    await writeAudit(context.env, { adminId: principal.adminId, action: "source.update", targetType: "source", targetId: id, requestId: context.get("requestId") });
    return context.json({ data: { id } });
  });

  app.delete("/api/sources/:id", async (context) => {
    const id = context.req.param("id");
    const result = await context.env.DB.prepare("DELETE FROM sources WHERE id = ?").bind(id).run();
    if (!result.meta.changes) throw new AppError(404, "数据源不存在", "source_not_found");
    const principal = context.get("principal");
    await writeAudit(context.env, { adminId: principal.adminId, action: "source.delete", targetType: "source", targetId: id, requestId: context.get("requestId") });
    return context.json({ data: { ok: true } });
  });

  app.post("/api/sources/:id/refresh", async (context) => {
    const result = await refreshSource(context.env, context.req.param("id"));
    const principal = context.get("principal");
    await writeAudit(context.env, { adminId: principal.adminId, action: "source.refresh", targetType: "source", targetId: context.req.param("id"), details: result, requestId: context.get("requestId") });
    return context.json({ data: result });
  });

  app.get("/api/sources/:id/logs", async (context) => {
    const { page, pageSize, offset } = pageParams(context);
    const logs = await context.env.DB.prepare("SELECT id, status, node_count, bytes, duration_ms, error, created_at FROM source_fetch_logs WHERE source_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?").bind(context.req.param("id"), pageSize, offset).all();
    return context.json({ data: { items: logs.results, page, pageSize } });
  });
}
