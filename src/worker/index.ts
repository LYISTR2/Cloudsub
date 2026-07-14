import app from "./app";
import type { Env } from "./env";
import { refreshDueSources } from "./services/sources";

export default {
  fetch: app.fetch,
  scheduled(_controller: ScheduledController, env: Env, context: ExecutionContext): void {
    context.waitUntil(refreshDueSources(env));
  },
} satisfies ExportedHandler<Env>;
