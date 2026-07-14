import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { createMiddleware } from "hono/factory";
import type { AppBindings, Env } from "../env";
import { constantTimeEqual, hmacSha256Hex, randomToken, sha256Hex } from "../security/crypto";
import { AppError } from "../shared/errors";

export const SESSION_COOKIE = "cloudsub_session";
export const CSRF_COOKIE = "cloudsub_csrf";

interface SessionRow {
  session_id: string;
  admin_id: string;
  username: string;
  csrf_token: string;
  expires_at: string;
}

export async function createSession(env: Env, adminId: string): Promise<{ token: string; csrfToken: string; expiresAt: string }> {
  if (!env.APP_SECRET) throw new AppError(503, "尚未配置应用密钥", "missing_app_secret");
  const token = randomToken(32);
  const csrfToken = randomToken(24);
  const now = new Date();
  const ttl = Math.max(900, Math.min(Number(env.SESSION_TTL) || 604_800, 2_592_000));
  const expiresAt = new Date(now.getTime() + ttl * 1000).toISOString();
  await env.DB.prepare(
    "INSERT INTO sessions (id, admin_id, token_hash, csrf_token, expires_at, last_seen_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
  ).bind(crypto.randomUUID(), adminId, await hmacSha256Hex(env.APP_SECRET, token), csrfToken, expiresAt, now.toISOString(), now.toISOString()).run();
  return { token, csrfToken, expiresAt };
}

export function setSessionCookies(context: Context<AppBindings>, session: { token: string; csrfToken: string; expiresAt: string }): void {
  const secure = new URL(context.req.url).protocol === "https:";
  const common = { path: "/", sameSite: "Strict" as const, secure, expires: new Date(session.expiresAt) };
  setCookie(context, SESSION_COOKIE, session.token, { ...common, httpOnly: true });
  setCookie(context, CSRF_COOKIE, session.csrfToken, { ...common, httpOnly: false });
}

export function clearSessionCookies(context: Context<AppBindings>): void {
  const secure = new URL(context.req.url).protocol === "https:";
  deleteCookie(context, SESSION_COOKIE, { path: "/", secure });
  deleteCookie(context, CSRF_COOKIE, { path: "/", secure });
}

export const requireAuth = createMiddleware<AppBindings>(async (context, next) => {
  const token = getCookie(context, SESSION_COOKIE);
  if (!token) throw new AppError(401, "请先登录", "authentication_required");
  if (!context.env.APP_SECRET) throw new AppError(503, "尚未配置应用密钥", "missing_app_secret");
  const now = new Date().toISOString();
  const session = await context.env.DB.prepare(
    "SELECT s.id AS session_id, s.csrf_token, s.expires_at, a.id AS admin_id, a.username FROM sessions s JOIN admins a ON a.id = s.admin_id WHERE s.token_hash = ? AND s.expires_at > ? LIMIT 1",
  ).bind(await hmacSha256Hex(context.env.APP_SECRET, token), now).first<SessionRow>();
  if (!session) {
    clearSessionCookies(context);
    throw new AppError(401, "会话已失效", "invalid_session");
  }
  context.set("principal", {
    adminId: session.admin_id,
    username: session.username,
    sessionId: session.session_id,
    csrfToken: session.csrf_token,
  });
  context.executionCtx.waitUntil(
    context.env.DB.prepare("UPDATE sessions SET last_seen_at = ? WHERE id = ?").bind(now, session.session_id).run(),
  );
  await next();
});

export const requireCsrf = createMiddleware<AppBindings>(async (context, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(context.req.method)) return next();
  const requestOrigin = context.req.header("origin");
  const expectedOrigin = context.env.APP_ORIGIN?.trim() || new URL(context.req.url).origin;
  if (requestOrigin && requestOrigin !== expectedOrigin) throw new AppError(403, "跨站请求已拒绝", "origin_mismatch");
  const header = context.req.header("x-csrf-token") ?? "";
  const cookie = getCookie(context, CSRF_COOKIE) ?? "";
  const expected = context.get("principal").csrfToken;
  if (!header || !cookie || !constantTimeEqual(header, cookie) || !constantTimeEqual(header, expected)) {
    throw new AppError(403, "CSRF 校验失败", "csrf_failed");
  }
  await next();
});

export async function loginRateLimit(env: Env, key: string): Promise<{ allowed: boolean; retryAfter: number }> {
  const cacheKey = "ratelimit:login:" + await sha256Hex(key);
  const state = await env.CACHE.get<{ attempts: number; blockedUntil?: number }>(cacheKey, "json");
  const now = Date.now();
  if (state?.blockedUntil && state.blockedUntil > now) return { allowed: false, retryAfter: Math.ceil((state.blockedUntil - now) / 1000) };
  return { allowed: true, retryAfter: 0 };
}

export async function recordLoginFailure(env: Env, key: string): Promise<void> {
  const cacheKey = "ratelimit:login:" + await sha256Hex(key);
  const current = await env.CACHE.get<{ attempts: number }>(cacheKey, "json");
  const attempts = (current?.attempts ?? 0) + 1;
  const blockedUntil = attempts >= 5 ? Date.now() + 15 * 60 * 1000 : undefined;
  await env.CACHE.put(cacheKey, JSON.stringify({ attempts, blockedUntil }), { expirationTtl: 900 });
}

export async function clearLoginFailures(env: Env, key: string): Promise<void> {
  await env.CACHE.delete("ratelimit:login:" + await sha256Hex(key));
}
