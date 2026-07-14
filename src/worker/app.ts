import { Hono } from "hono";
import type { Context } from "hono";
import { z } from "zod";
import type { NormalizedNode, SubscriptionRules, SubscriptionTarget } from "../shared/types";
import { applySubscriptionRules, renderSubscription } from "./adapters/output";
import type { AppBindings, Env } from "./env";
import { requestMiddleware } from "./middleware/request";
import { constantTimeEqual, decryptJson, encryptJson, sha256Hex } from "./security/crypto";
import { hashPassword, verifyPassword } from "./security/password";
import { validateUpstreamUrl } from "./security/safe-fetch";
import { AppError } from "./shared/errors";
import { writeAudit } from "./services/audit";
import {
  clearLoginFailures as clearFailures,
  clearSessionCookies as clearCookies,
  createSession as startSession,
  loginRateLimit,
  recordLoginFailure,
  requireAuth,
  requireCsrf,
  setSessionCookies,
} from "./services/auth";
import { refreshSource } from "./services/sources";
import { generateSubscription, issueSubscriptionToken } from "./services/subscriptions";

const app = new Hono<AppBindings>();
app.use("*", requestMiddleware);

const setupSchema = z.object({
  username: z.string().trim().min(3).max(40).regex(/^[A-Za-z0-9_.-]+$/u),
  password: z.string().min(12).max(200),
  setupToken: z.string().max(500).optional(),
});
const loginSchema = z.object({ username: z.string().trim().min(1).max(40), password: z.string().min(1).max(200) });
const passwordSchema = z.object({ currentPassword: z.string().min(1).max(200), newPassword: z.string().min(12).max(200) });
const sourceCreateSchema = z.object({
  name: z.string().trim().min(1).max(100),
  type: z.enum(["url", "manual"]),
  url: z.string().trim().max(2_000).optional(),
  content: z.string().max(5_300_000).optional(),
  headers: z.record(z.string(), z.string().max(2_000)).optional(),
  userAgent: z.string().trim().max(200).optional(),
  enabled: z.boolean().default(true),
  refreshInterval: z.number().int().min(5).max(10_080).default(60),
  timeoutMs: z.number().int().min(1_000).max(30_000).default(15_000),
});
const sourceUpdateSchema = sourceCreateSchema.partial().omit({ type: true });
const nodeUpdateSchema = z.object({
  name: z.string().trim().min(1).max(200).optional(),
  enabled: z.boolean().optional(),
  tags: z.array(z.string().trim().min(1).max(40)).max(20).optional(),
});
const nodeBatchSchema = z.object({ ids: z.array(z.string().uuid()).min(1).max(100), enabled: z.boolean().optional(), tags: z.array(z.string().trim().min(1).max(40)).max(20).optional() });
const rulesSchema = z.object({
  protocols: z.array(z.string().trim().min(1).max(30)).max(20).optional(),
  tags: z.array(z.string().trim().min(1).max(40)).max(20).optional(),
  includeName: z.string().max(200).optional(),
  excludeName: z.string().max(200).optional(),
  sortBy: z.enum(["name", "protocol", "source"]).optional(),
  rename: z.array(z.object({ pattern: z.string().max(200), replacement: z.string().max(200) })).max(20).optional(),
});
const subscriptionCreateSchema = z.object({
  name: z.string().trim().min(1).max(100),
  sourceIds: z.array(z.string().uuid()).min(1).max(100),
  defaultTarget: z.enum(["raw", "mihomo", "json"]).default("mihomo"),
  enabled: z.boolean().default(true),
  cacheTtl: z.number().int().min(60).max(86_400).default(300),
  expiresAt: z.string().datetime().nullable().optional(),
  rules: rulesSchema.default({}),
});
const subscriptionUpdateSchema = subscriptionCreateSchema.partial();

async function body<T>(context: Context<AppBindings>, schema: z.ZodType<T>): Promise<T> {
  let value: unknown;
  try { value = await context.req.json(); } catch { throw new AppError(422, "请求正文必须是 JSON", "invalid_json"); }
  const result = schema.safeParse(value);
  if (!result.success) throw new AppError(422, "请求参数无效", "validation_failed", z.flattenError(result.error).fieldErrors);
  return result.data;
}

function pageParams(context: Context<AppBindings>): { page: number; pageSize: number; offset: number } {
  const page = Math.max(1, Math.floor(Number(context.req.query("page")) || 1));
  const pageSize = Math.max(1, Math.min(100, Math.floor(Number(context.req.query("pageSize")) || 25)));
  return { page, pageSize, offset: (page - 1) * pageSize };
}

function slugify(name: string): string {
  const slug = name.normalize("NFKD").toLowerCase().replace(/[^a-z0-9]+/gu, "-").replace(/^-|-$/gu, "").slice(0, 50);
  return slug || "subscription";
}

function maskServer(value: string): string {
  if (value.includes(":")) return value.slice(0, 4) + "…";
  const parts = value.split(".");
  if (parts.length === 4 && parts.every((part) => /^\d+$/u.test(part))) return parts[0] + ".***.***." + parts[3];
  if (parts.length > 1) return parts[0].slice(0, 3) + "***." + parts.at(-1);
  return value.slice(0, 3) + "***";
}

function redactedUpstreamUrl(value: string): string {
  const url = new URL(value);
  return url.origin + url.pathname + (url.search ? "?•••" : "");
}

app.get("/health", async (context) => {
  try {
    await context.env.DB.prepare("SELECT 1").first();
    return context.json({ status: "ok", service: context.env.APP_NAME || "CloudSub", time: new Date().toISOString() });
  } catch {
    return context.json({ status: "degraded", service: context.env.APP_NAME || "CloudSub" }, 503);
  }
});

app.get("/api/system/status", async (context) => {
  try {
    const admin = await context.env.DB.prepare("SELECT id FROM admins LIMIT 1").first<{ id: string }>();
    return context.json({ data: { initialized: Boolean(admin), migrationsReady: true, secretsConfigured: Boolean(context.env.APP_SECRET && context.env.DATA_ENCRYPTION_KEY), setupTokenRequired: Boolean(context.env.INITIAL_ADMIN_TOKEN) } });
  } catch {
    return context.json({ data: { initialized: false, migrationsReady: false, secretsConfigured: Boolean(context.env.APP_SECRET && context.env.DATA_ENCRYPTION_KEY), setupTokenRequired: Boolean(context.env.INITIAL_ADMIN_TOKEN) } });
  }
});

app.post("/api/system/initialize", async (context) => {
  const input = await body(context, setupSchema);
  if (!context.env.APP_SECRET || !context.env.DATA_ENCRYPTION_KEY) throw new AppError(503, "请先配置 APP_SECRET 和 DATA_ENCRYPTION_KEY", "missing_secrets");
  if (context.env.INITIAL_ADMIN_TOKEN && !constantTimeEqual(input.setupToken ?? "", context.env.INITIAL_ADMIN_TOKEN)) {
    throw new AppError(403, "初始化令牌无效", "invalid_setup_token");
  }
  const existing = await context.env.DB.prepare("SELECT id FROM admins LIMIT 1").first<{ id: string }>();
  if (existing) throw new AppError(409, "系统已经完成初始化", "already_initialized");
  const adminId = crypto.randomUUID();
  const now = new Date().toISOString();
  await context.env.DB.batch([
    context.env.DB.prepare("INSERT INTO admins (id, username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)").bind(adminId, input.username, await hashPassword(input.password), now, now),
    context.env.DB.prepare("INSERT INTO settings (key, value_json, updated_at) VALUES ('system', ?, ?)").bind(JSON.stringify({ timezone: "UTC", initializedAt: now }), now),
    context.env.DB.prepare("INSERT INTO templates (id, name, target, content, is_default, created_at, updated_at) VALUES (?, 'Mihomo 默认模板', 'mihomo', 'proxies: []', 1, ?, ?)").bind(crypto.randomUUID(), now, now),
  ]);
  const session = await startSession(context.env, adminId);
  setSessionCookies(context, session);
  await writeAudit(context.env, { adminId, action: "system.initialize", targetType: "system", requestId: context.get("requestId") });
  return context.json({ data: { username: input.username, csrfToken: session.csrfToken } }, 201);
});

app.post("/api/auth/login", async (context) => {
  const input = await body(context, loginSchema);
  const ip = context.req.header("cf-connecting-ip") ?? "unknown";
  const rateKey = ip + ":" + input.username.toLowerCase();
  const rate = await loginRateLimit(context.env, rateKey);
  if (!rate.allowed) {
    context.header("retry-after", String(rate.retryAfter));
    throw new AppError(429, "登录尝试过多，请稍后重试", "login_locked");
  }
  const admin = await context.env.DB.prepare("SELECT id, username, password_hash FROM admins WHERE username = ? LIMIT 1").bind(input.username).first<{ id: string; username: string; password_hash: string }>();
  if (!admin || !(await verifyPassword(input.password, admin.password_hash))) {
    await recordLoginFailure(context.env, rateKey);
    throw new AppError(401, "用户名或密码错误", "invalid_credentials");
  }
  await clearFailures(context.env, rateKey);
  const session = await startSession(context.env, admin.id);
  setSessionCookies(context, session);
  await writeAudit(context.env, { adminId: admin.id, action: "auth.login", targetType: "session", requestId: context.get("requestId") });
  return context.json({ data: { username: admin.username, csrfToken: session.csrfToken } });
});

app.get("/sub/:token", async (context) => {
  const token = context.req.param("token");
  const ip = context.req.header("cf-connecting-ip") ?? "unknown";
  const rateKey = "ratelimit:sub:" + await sha256Hex(ip);
  const hits = Number(await context.env.CACHE.get(rateKey)) || 0;
  if (hits >= 120) throw new AppError(429, "请求过于频繁", "subscription_rate_limited");
  await context.env.CACHE.put(rateKey, String(hits + 1), { expirationTtl: 60 });
  const result = await generateSubscription(context.env, token, context.req.query("target"));
  context.executionCtx.waitUntil(context.env.DB.prepare("UPDATE subscription_tokens SET last_access_at = ? WHERE id = ?").bind(new Date().toISOString(), result.tokenId).run());
  const headers = {
    "content-type": result.contentType,
    "etag": result.etag,
    "cache-control": "private, max-age=" + result.cacheTtl,
    "content-disposition": "attachment; filename=\"" + result.name.replace(/[^A-Za-z0-9_.-]/gu, "-") + "." + result.extension + "\"",
    "profile-update-interval": "6",
  };
  if (context.req.header("if-none-match") === result.etag) return context.body(null, 304, headers);
  return context.body(result.body, 200, headers);
});

app.use("/api/*", requireAuth);
app.use("/api/*", requireCsrf);

app.get("/api/auth/session", (context) => {
  const principal = context.get("principal");
  return context.json({ data: { username: principal.username, csrfToken: principal.csrfToken } });
});

app.post("/api/auth/logout", async (context) => {
  const principal = context.get("principal");
  await context.env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(principal.sessionId).run();
  clearCookies(context);
  await writeAudit(context.env, { adminId: principal.adminId, action: "auth.logout", targetType: "session", requestId: context.get("requestId") });
  return context.json({ data: { ok: true } });
});

app.put("/api/auth/password", async (context) => {
  const input = await body(context, passwordSchema);
  const principal = context.get("principal");
  const admin = await context.env.DB.prepare("SELECT password_hash FROM admins WHERE id = ?").bind(principal.adminId).first<{ password_hash: string }>();
  if (!admin || !(await verifyPassword(input.currentPassword, admin.password_hash))) throw new AppError(403, "当前密码错误", "invalid_current_password");
  const now = new Date().toISOString();
  await context.env.DB.batch([
    context.env.DB.prepare("UPDATE admins SET password_hash = ?, updated_at = ? WHERE id = ?").bind(await hashPassword(input.newPassword), now, principal.adminId),
    context.env.DB.prepare("DELETE FROM sessions WHERE admin_id = ? AND id <> ?").bind(principal.adminId, principal.sessionId),
  ]);
  await writeAudit(context.env, { adminId: principal.adminId, action: "auth.password.change", targetType: "admin", targetId: principal.adminId, requestId: context.get("requestId") });
  return context.json({ data: { ok: true } });
});

app.get("/api/dashboard", async (context) => {
  const [sources, nodes, subscriptions, recentErrors, lastAccess] = await Promise.all([
    context.env.DB.prepare("SELECT COUNT(*) AS count FROM sources WHERE enabled = 1").first<{ count: number }>(),
    context.env.DB.prepare("SELECT COUNT(*) AS count FROM nodes WHERE enabled = 1 AND present = 1").first<{ count: number }>(),
    context.env.DB.prepare("SELECT COUNT(*) AS count FROM subscriptions WHERE enabled = 1").first<{ count: number }>(),
    context.env.DB.prepare("SELECT s.name, l.error, l.created_at FROM source_fetch_logs l JOIN sources s ON s.id = l.source_id WHERE l.status = 'error' ORDER BY l.created_at DESC LIMIT 5").all(),
    context.env.DB.prepare("SELECT MAX(last_access_at) AS value FROM subscription_tokens").first<{ value: string | null }>(),
  ]);
  return context.json({ data: { counts: { sources: sources?.count ?? 0, nodes: nodes?.count ?? 0, subscriptions: subscriptions?.count ?? 0 }, recentErrors: recentErrors.results, lastSubscriptionAccess: lastAccess?.value ?? null } });
});

app.get("/api/sources", async (context) => {
  const { page, pageSize, offset } = pageParams(context);
  const search = (context.req.query("q") ?? "").slice(0, 100);
  const pattern = "%" + search.replaceAll("%", "\\%").replaceAll("_", "\\_") + "%";
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
    const maxBytes = Math.max(1024, Math.min(Number(context.env.MAX_SOURCE_SIZE) || 5_242_880, 10_485_760));
    if (new TextEncoder().encode(input.content).byteLength > maxBytes) throw new AppError(413, "数据源内容超过大小限制", "source_too_large");
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
    const maxBytes = Math.max(1024, Math.min(Number(context.env.MAX_SOURCE_SIZE) || 5_242_880, 10_485_760));
    if (new TextEncoder().encode(input.content).byteLength > maxBytes) throw new AppError(413, "数据源内容超过大小限制", "source_too_large");
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

app.get("/api/nodes", async (context) => {
  const { page, pageSize, offset } = pageParams(context);
  const conditions = ["n.present = 1"];
  const parameters: unknown[] = [];
  const query = (context.req.query("q") ?? "").slice(0, 100);
  const protocol = (context.req.query("protocol") ?? "").slice(0, 30);
  const sourceId = (context.req.query("sourceId") ?? "").slice(0, 50);
  if (query) {
    conditions.push("n.name LIKE ? ESCAPE '\\'");
    parameters.push("%" + query.replaceAll("%", "\\%").replaceAll("_", "\\_") + "%");
  }
  if (protocol) { conditions.push("n.protocol = ?"); parameters.push(protocol); }
  if (sourceId) { conditions.push("n.source_id = ?"); parameters.push(sourceId); }
  const where = conditions.join(" AND ");
  const [items, total] = await Promise.all([
    context.env.DB.prepare("SELECT n.id, n.source_id, s.name AS source_name, n.name, n.protocol, n.server, n.port, n.tags_json, n.enabled, n.updated_at FROM nodes n JOIN sources s ON s.id = n.source_id WHERE " + where + " ORDER BY n.name COLLATE NOCASE LIMIT ? OFFSET ?").bind(...parameters, pageSize, offset).all<any>(),
    context.env.DB.prepare("SELECT COUNT(*) AS count FROM nodes n WHERE " + where).bind(...parameters).first<{ count: number }>(),
  ]);
  return context.json({ data: { items: items.results.map((item) => ({ ...item, server: maskServer(item.server), tags: JSON.parse(item.tags_json), tags_json: undefined })), page, pageSize, total: total?.count ?? 0 } });
});

app.get("/api/nodes/:id", async (context) => {
  const node = await context.env.DB.prepare("SELECT n.id, n.source_id, s.name AS source_name, n.name, n.protocol, n.server, n.port, n.tags_json, n.enabled, n.created_at, n.updated_at FROM nodes n JOIN sources s ON s.id = n.source_id WHERE n.id = ? AND n.present = 1").bind(context.req.param("id")).first<any>();
  if (!node) throw new AppError(404, "节点不存在", "node_not_found");
  return context.json({ data: { ...node, server: maskServer(node.server), tags: JSON.parse(node.tags_json), tags_json: undefined } });
});

app.put("/api/nodes/:id", async (context) => {
  const input = await body(context, nodeUpdateSchema);
  const id = context.req.param("id");
  const current = await context.env.DB.prepare("SELECT id, source_id, name, enabled, tags_json FROM nodes WHERE id = ? AND present = 1").bind(id).first<any>();
  if (!current) throw new AppError(404, "节点不存在", "node_not_found");
  const now = new Date().toISOString();
  await context.env.DB.batch([
    context.env.DB.prepare("UPDATE nodes SET name = ?, enabled = ?, tags_json = ?, updated_at = ? WHERE id = ?").bind(input.name ?? current.name, (input.enabled ?? Boolean(current.enabled)) ? 1 : 0, JSON.stringify(input.tags ?? JSON.parse(current.tags_json)), now, id),
    context.env.DB.prepare("UPDATE subscriptions SET revision = revision + 1, updated_at = ? WHERE id IN (SELECT subscription_id FROM subscription_sources WHERE source_id = ?)").bind(now, current.source_id),
  ]);
  const principal = context.get("principal");
  await writeAudit(context.env, { adminId: principal.adminId, action: "node.update", targetType: "node", targetId: id, requestId: context.get("requestId") });
  return context.json({ data: { id } });
});

app.post("/api/nodes/batch", async (context) => {
  const input = await body(context, nodeBatchSchema);
  if (input.enabled === undefined && input.tags === undefined) throw new AppError(422, "没有可更新的字段", "empty_update");
  const placeholders = input.ids.map(() => "?").join(",");
  const nodes = await context.env.DB.prepare("SELECT id, source_id, enabled, tags_json FROM nodes WHERE id IN (" + placeholders + ")").bind(...input.ids).all<any>();
  const now = new Date().toISOString();
  await context.env.DB.batch(nodes.results.map((node) => context.env.DB.prepare("UPDATE nodes SET enabled = ?, tags_json = ?, updated_at = ? WHERE id = ?").bind(input.enabled === undefined ? node.enabled : input.enabled ? 1 : 0, JSON.stringify(input.tags ?? JSON.parse(node.tags_json)), now, node.id)));
  const sourceIds = [...new Set(nodes.results.map((node) => node.source_id as string))];
  if (sourceIds.length) {
    const sourcePlaceholders = sourceIds.map(() => "?").join(",");
    await context.env.DB.prepare("UPDATE subscriptions SET revision = revision + 1, updated_at = ? WHERE id IN (SELECT subscription_id FROM subscription_sources WHERE source_id IN (" + sourcePlaceholders + "))").bind(now, ...sourceIds).run();
  }
  const principal = context.get("principal");
  await writeAudit(context.env, { adminId: principal.adminId, action: "node.batch_update", targetType: "node", details: { count: nodes.results.length }, requestId: context.get("requestId") });
  return context.json({ data: { updated: nodes.results.length } });
});

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
  const token = await issueSubscriptionToken(context.env, id);
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
  await context.env.DB.prepare("UPDATE subscriptions SET name = ?, enabled = ?, default_target = ?, rules_json = ?, revision = revision + 1, expires_at = ?, cache_ttl = ?, updated_at = ? WHERE id = ?").bind(
    input.name ?? current.name,
    (input.enabled ?? Boolean(current.enabled)) ? 1 : 0,
    input.defaultTarget ?? current.default_target,
    JSON.stringify(input.rules ?? JSON.parse(current.rules_json)),
    input.expiresAt === undefined ? current.expires_at : input.expiresAt,
    input.cacheTtl ?? current.cache_ttl,
    now,
    id,
  ).run();
  if (input.sourceIds) {
    await context.env.DB.prepare("DELETE FROM subscription_sources WHERE subscription_id = ?").bind(id).run();
    await context.env.DB.batch([...new Set(input.sourceIds)].map((sourceId) => context.env.DB.prepare("INSERT INTO subscription_sources (subscription_id, source_id) VALUES (?, ?)").bind(id, sourceId)));
  }
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

async function subscriptionPreview(env: Env, id: string, targetOverride?: SubscriptionTarget): Promise<{ rendered: ReturnType<typeof renderSubscription>; count: number }> {
  const subscription = await env.DB.prepare("SELECT default_target, rules_json FROM subscriptions WHERE id = ?").bind(id).first<{ default_target: SubscriptionTarget; rules_json: string }>();
  if (!subscription) throw new AppError(404, "订阅不存在", "subscription_not_found");
  const result = await env.DB.prepare("SELECT n.* FROM nodes n JOIN subscription_sources ss ON ss.source_id = n.source_id WHERE ss.subscription_id = ? AND n.enabled = 1 AND n.present = 1").bind(id).all<any>();
  const nodes: NormalizedNode[] = result.results.map((row) => ({
    id: row.id, sourceId: row.source_id, fingerprint: row.fingerprint, name: row.name, protocol: row.protocol, server: row.server, port: row.port,
    config: JSON.parse(row.config_json), tags: JSON.parse(row.tags_json), rawUri: row.raw_uri ?? undefined, enabled: Boolean(row.enabled),
  }));
  const filtered = applySubscriptionRules(nodes, JSON.parse(subscription.rules_json) as SubscriptionRules);
  return { rendered: renderSubscription(filtered, targetOverride ?? subscription.default_target), count: filtered.length };
}

app.post("/api/subscriptions/:id/preview", async (context) => {
  const input = await body(context, z.object({ target: z.enum(["raw", "mihomo", "json"]).optional() }));
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

app.get("/api/settings", async (context) => {
  const setting = await context.env.DB.prepare("SELECT value_json, updated_at FROM settings WHERE key = 'system'").first<{ value_json: string; updated_at: string }>();
  return context.json({ data: { ...(setting ? JSON.parse(setting.value_json) : {}), updatedAt: setting?.updated_at ?? null, limits: { maxSourceBytes: Number(context.env.MAX_SOURCE_SIZE), sessionTtl: Number(context.env.SESSION_TTL), subscriptionCacheTtl: Number(context.env.SUB_CACHE_TTL) } } });
});

app.put("/api/settings", async (context) => {
  const input = await body(context, z.object({ timezone: z.string().trim().min(1).max(100) }));
  const current = await context.env.DB.prepare("SELECT value_json FROM settings WHERE key = 'system'").first<{ value_json: string }>();
  const now = new Date().toISOString();
  const value = { ...(current ? JSON.parse(current.value_json) : {}), timezone: input.timezone };
  await context.env.DB.prepare("INSERT INTO settings (key, value_json, updated_at) VALUES ('system', ?, ?) ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at").bind(JSON.stringify(value), now).run();
  const principal = context.get("principal");
  await writeAudit(context.env, { adminId: principal.adminId, action: "settings.update", targetType: "system", details: { timezone: input.timezone }, requestId: context.get("requestId") });
  return context.json({ data: value });
});

app.get("/api/audit-logs", async (context) => {
  const { page, pageSize, offset } = pageParams(context);
  const logs = await context.env.DB.prepare("SELECT l.id, l.action, l.target_type, l.target_id, l.details_json, l.request_id, l.created_at, a.username FROM audit_logs l LEFT JOIN admins a ON a.id = l.admin_id ORDER BY l.created_at DESC LIMIT ? OFFSET ?").bind(pageSize, offset).all<any>();
  return context.json({ data: { items: logs.results.map((entry) => ({ ...entry, details: JSON.parse(entry.details_json), details_json: undefined })), page, pageSize } });
});

app.all("/api/*", () => { throw new AppError(404, "接口不存在", "not_found"); });
app.all("/sub/*", () => { throw new AppError(404, "订阅不可用", "subscription_unavailable"); });
app.all("*", (context) => context.env.ASSETS.fetch(context.req.raw));

app.onError((error, context) => {
  const requestId = context.get("requestId") || crypto.randomUUID();
  if (error instanceof AppError) {
    return context.json({ error: { code: error.code, message: error.message, details: error.details, requestId } }, error.status);
  }
  console.error(JSON.stringify({ requestId, name: error.name, message: error.message }));
  return context.json({ error: { code: "internal_error", message: "服务器内部错误", requestId } }, 500);
});

export default app;
