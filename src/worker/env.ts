export interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  ASSETS: Fetcher;
  APP_NAME: string;
  APP_ORIGIN: string;
  SESSION_TTL: string;
  SUB_CACHE_TTL: string;
  MAX_SOURCE_SIZE: string;
  APP_SECRET?: string;
  DATA_ENCRYPTION_KEY?: string;
  INITIAL_ADMIN_TOKEN?: string;
}

export interface SessionPrincipal {
  adminId: string;
  username: string;
  sessionId: string;
  csrfToken: string;
}

export type AppBindings = {
  Bindings: Env;
  Variables: {
    requestId: string;
    principal: SessionPrincipal;
  };
};
