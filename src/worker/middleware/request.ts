import { createMiddleware } from "hono/factory";
import type { AppBindings } from "../env";

export const requestMiddleware = createMiddleware<AppBindings>(async (context, next) => {
  const requestId = context.req.header("x-request-id")?.slice(0, 100) || crypto.randomUUID();
  context.set("requestId", requestId);
  await next();
  context.header("x-request-id", requestId);
  context.header("x-content-type-options", "nosniff");
  context.header("x-frame-options", "DENY");
  context.header("referrer-policy", "no-referrer");
  context.header("permissions-policy", "camera=(), microphone=(), geolocation=()");
  if (new URL(context.req.url).protocol === "https:") context.header("strict-transport-security", "max-age=31536000; includeSubDomains");
  context.header("content-security-policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
});
