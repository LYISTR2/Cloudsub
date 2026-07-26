import type { Context } from "hono";
import { z } from "zod";
import type { AppBindings } from "./env";
import { AppError } from "./shared/errors";

// ─── Shared request helpers ──────────────────────────────────────────
// Small utilities used across the route modules. Kept free of business
// logic so the individual route files stay focused on their resource.

export async function body<T>(context: Context<AppBindings>, schema: z.ZodType<T>): Promise<T> {
  let value: unknown;
  try { value = await context.req.json(); } catch { throw new AppError(422, "请求正文必须是 JSON", "invalid_json"); }
  const result = schema.safeParse(value);
  if (!result.success) throw new AppError(422, "请求参数无效", "validation_failed", z.flattenError(result.error).fieldErrors);
  return result.data;
}

export function pageParams(context: Context<AppBindings>): { page: number; pageSize: number; offset: number } {
  const page = Math.max(1, Math.floor(Number(context.req.query("page")) || 1));
  const pageSize = Math.max(1, Math.min(100, Math.floor(Number(context.req.query("pageSize")) || 25)));
  return { page, pageSize, offset: (page - 1) * pageSize };
}

/** Build a LIKE pattern that treats user input literally (escapes % and _). */
export function likePattern(search: string): string {
  return "%" + search.replaceAll("%", "\\%").replaceAll("_", "\\_") + "%";
}

export function slugify(name: string): string {
  // Preserve ASCII where possible; fall back to a time-based slug for names
  // that are entirely non-ASCII (e.g. Chinese) so the slug stays unique.
  const slug = name.normalize("NFKD").toLowerCase().replace(/[^a-z0-9]+/gu, "-").replace(/^-|-$/gu, "").slice(0, 50);
  if (slug) return slug;
  return "sub-" + Date.now().toString(36);
}

export function maskServer(value: string): string {
  if (value.includes(":")) return value.slice(0, 4) + "…";
  const parts = value.split(".");
  if (parts.length === 4 && parts.every((part) => /^\d+$/u.test(part))) return parts[0] + ".***.***." + parts[3];
  if (parts.length > 1) return parts[0].slice(0, 3) + "***." + parts.at(-1);
  return value.slice(0, 3) + "***";
}

export function redactedUpstreamUrl(value: string): string {
  const url = new URL(value);
  return url.origin + url.pathname + (url.search ? "?•••" : "");
}
