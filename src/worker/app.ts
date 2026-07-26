import { Hono } from "hono";
import type { AppBindings } from "./env";
import { requestMiddleware } from "./middleware/request";
import { requireAuth, requireCsrf } from "./services/auth";
import { AppError } from "./shared/errors";
import { registerAccountRoutes } from "./routes/account";
import { registerNodeRoutes } from "./routes/nodes";
import { registerPublicRoutes } from "./routes/public";
import { registerSourceRoutes } from "./routes/sources";
import { registerSubscriptionRoutes } from "./routes/subscriptions";
import { registerSystemRoutes } from "./routes/system";

const app = new Hono<AppBindings>();

// Security headers + request id on every request.
app.use("*", requestMiddleware);

// Public routes (health, first-run setup, login, subscription download).
// These are registered BEFORE the auth middleware so they stay reachable
// without a session — order here is load-bearing.
registerPublicRoutes(app);

// Everything registered from here on requires an authenticated admin
// session and a valid CSRF token.
app.use("/api/*", requireAuth);
app.use("/api/*", requireCsrf);

registerAccountRoutes(app);
registerSourceRoutes(app);
registerNodeRoutes(app);
registerSubscriptionRoutes(app);
registerSystemRoutes(app);

// Fallbacks: unknown API/subscription paths return typed errors; anything
// else is served from the static SPA assets.
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
