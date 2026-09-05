import type { Hono } from "hono";
import type { AppBindings } from "../env";
import { body, maskServer, pageParams } from "../http";
import { writeAudit } from "../services/audit";
import { AppError } from "../shared/errors";
import { nodeBatchSchema, nodeUpdateSchema } from "../validation";

/** Read/update routes for parsed nodes (server addresses are masked). */
export function registerNodeRoutes(app: Hono<AppBindings>): void {
  app.get("/api/nodes", async (context) => {
    const { page, pageSize, offset } = pageParams(context);
    const conditions = ["n.present = 1"];
    const parameters: unknown[] = [];
    const query = (context.req.query("q") ?? "").slice(0, 100);
    const protocol = (context.req.query("protocol") ?? "").slice(0, 30);
    const sourceId = (context.req.query("sourceId") ?? "").slice(0, 50);
    const sourceKind = (context.req.query("sourceKind") ?? "").slice(0, 20);
    // sourceKind is an enum-valued filter (drives the per-group server-side
    // pagination in the dashboard); anything else is a client bug and must
    // be rejected instead of silently ignored.
    if (sourceKind && sourceKind !== "subscription" && sourceKind !== "standalone") {
      throw new AppError(422, "sourceKind 参数无效", "invalid_source_kind");
    }
    if (query) {
      conditions.push("n.name LIKE ? ESCAPE '\\'");
      parameters.push("%" + query.replaceAll("%", "\\%").replaceAll("_", "\\_") + "%");
    }
    if (protocol) { conditions.push("n.protocol = ?"); parameters.push(protocol); }
    if (sourceId) { conditions.push("n.source_id = ?"); parameters.push(sourceId); }
    if (sourceKind) { conditions.push("s.source_kind = ?"); parameters.push(sourceKind); }
    const where = conditions.join(" AND ");
    // Both the item query and the COUNT query join sources so the filters
    // (and totals) stay consistent — the count must never drift from the
    // filtered item set.
    const [items, total] = await Promise.all([
      context.env.DB.prepare("SELECT n.id, n.source_id, s.name AS source_name, s.source_kind, n.name, n.protocol, n.server, n.port, n.tags_json, n.enabled, n.updated_at FROM nodes n JOIN sources s ON s.id = n.source_id WHERE " + where + " ORDER BY n.name COLLATE NOCASE LIMIT ? OFFSET ?").bind(...parameters, pageSize, offset).all<any>(),
      context.env.DB.prepare("SELECT COUNT(*) AS count FROM nodes n JOIN sources s ON s.id = n.source_id WHERE " + where).bind(...parameters).first<{ count: number }>(),
    ]);
    return context.json({ data: { items: items.results.map((item) => ({ ...item, server: maskServer(item.server), tags: JSON.parse(item.tags_json), tags_json: undefined })), page, pageSize, total: total?.count ?? 0 } });
  });

  app.get("/api/nodes/:id", async (context) => {
    const node = await context.env.DB.prepare("SELECT n.id, n.source_id, s.name AS source_name, s.source_kind, n.name, n.protocol, n.server, n.port, n.tags_json, n.enabled, n.created_at, n.updated_at FROM nodes n JOIN sources s ON s.id = n.source_id WHERE n.id = ? AND n.present = 1").bind(context.req.param("id")).first<any>();
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
}
