import type { Hono } from "hono";
import type { AppBindings } from "../env";
import { body, pageParams } from "../http";
import { writeAudit } from "../services/audit";
import { settingsSchema } from "../validation";

/** Dashboard summary, system settings, and audit-log listing. */
export function registerSystemRoutes(app: Hono<AppBindings>): void {
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

  app.get("/api/settings", async (context) => {
    const setting = await context.env.DB.prepare("SELECT value_json, updated_at FROM settings WHERE key = 'system'").first<{ value_json: string; updated_at: string }>();
    return context.json({ data: { ...(setting ? JSON.parse(setting.value_json) : {}), updatedAt: setting?.updated_at ?? null, limits: { maxSourceBytes: Number(context.env.MAX_SOURCE_SIZE), sessionTtl: Number(context.env.SESSION_TTL), subscriptionCacheTtl: Number(context.env.SUB_CACHE_TTL) } } });
  });

  app.put("/api/settings", async (context) => {
    const input = await body(context, settingsSchema);
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
    const [logs, total] = await Promise.all([
      context.env.DB.prepare("SELECT l.id, l.action, l.target_type, l.target_id, l.details_json, l.request_id, l.created_at, a.username FROM audit_logs l LEFT JOIN admins a ON a.id = l.admin_id ORDER BY l.created_at DESC LIMIT ? OFFSET ?").bind(pageSize, offset).all<any>(),
      context.env.DB.prepare("SELECT COUNT(*) AS count FROM audit_logs").first<{ count: number }>(),
    ]);
    return context.json({ data: { items: logs.results.map((entry) => ({ ...entry, details: JSON.parse(entry.details_json), details_json: undefined })), page, pageSize, total: total?.count ?? 0 } });
  });
}
