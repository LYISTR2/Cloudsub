import type { Env } from "../env";

export async function writeAudit(env: Env, entry: {
  adminId?: string;
  action: string;
  targetType?: string;
  targetId?: string;
  details?: Record<string, unknown>;
  requestId?: string;
}): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO audit_logs (id, admin_id, action, target_type, target_id, details_json, request_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
  ).bind(
    crypto.randomUUID(),
    entry.adminId ?? null,
    entry.action,
    entry.targetType ?? null,
    entry.targetId ?? null,
    JSON.stringify(entry.details ?? {}),
    entry.requestId ?? null,
    new Date().toISOString(),
  ).run();
}
