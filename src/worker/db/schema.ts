import { index, integer, primaryKey, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

export const admins = sqliteTable("admins", {
  id: text("id").primaryKey(),
  username: text("username").notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
});

export const sessions = sqliteTable(
  "sessions",
  {
    id: text("id").primaryKey(),
    adminId: text("admin_id").notNull().references(() => admins.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull(),
    csrfToken: text("csrf_token").notNull(),
    expiresAt: text("expires_at").notNull(),
    lastSeenAt: text("last_seen_at").notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => [uniqueIndex("sessions_token_hash_unique").on(table.tokenHash), index("idx_sessions_expires_at").on(table.expiresAt)],
);

export const settings = sqliteTable("settings", {
  key: text("key").primaryKey(),
  valueJson: text("value_json").notNull(),
  updatedAt: text("updated_at").notNull(),
});

export const sources = sqliteTable(
  "sources",
  {
    id: text("id").primaryKey(),
    name: text("name").notNull(),
    type: text("type", { enum: ["url", "manual"] }).notNull(),
    url: text("url"),
    payloadEncrypted: text("payload_encrypted"),
    userAgent: text("user_agent"),
    enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
    refreshInterval: integer("refresh_interval").notNull().default(60),
    timeoutMs: integer("timeout_ms").notNull().default(15000),
    nextRefreshAt: text("next_refresh_at"),
    lastAttemptAt: text("last_attempt_at"),
    lastSuccessAt: text("last_success_at"),
    lastError: text("last_error"),
    contentHash: text("content_hash"),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
  },
  (table) => [index("idx_sources_next_refresh_at").on(table.enabled, table.nextRefreshAt)],
);

export const sourceFetchLogs = sqliteTable(
  "source_fetch_logs",
  {
    id: text("id").primaryKey(),
    sourceId: text("source_id").notNull().references(() => sources.id, { onDelete: "cascade" }),
    status: text("status", { enum: ["success", "error"] }).notNull(),
    nodeCount: integer("node_count").notNull().default(0),
    bytes: integer("bytes").notNull().default(0),
    durationMs: integer("duration_ms").notNull().default(0),
    error: text("error"),
    createdAt: text("created_at").notNull(),
  },
  (table) => [index("idx_source_logs_source_created").on(table.sourceId, table.createdAt)],
);

export const nodes = sqliteTable(
  "nodes",
  {
    id: text("id").primaryKey(),
    sourceId: text("source_id").notNull().references(() => sources.id, { onDelete: "cascade" }),
    fingerprint: text("fingerprint").notNull(),
    name: text("name").notNull(),
    protocol: text("protocol").notNull(),
    server: text("server").notNull(),
    port: integer("port").notNull(),
    configJson: text("config_json").notNull(),
    tagsJson: text("tags_json").notNull().default("[]"),
    rawUri: text("raw_uri"),
    enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
    present: integer("present", { mode: "boolean" }).notNull().default(true),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
  },
  (table) => [
    uniqueIndex("nodes_source_fingerprint_unique").on(table.sourceId, table.fingerprint),
    index("idx_nodes_source_present").on(table.sourceId, table.present),
    index("idx_nodes_protocol_enabled").on(table.protocol, table.enabled, table.present),
    index("idx_nodes_fingerprint").on(table.fingerprint),
  ],
);

export const templates = sqliteTable("templates", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  target: text("target").notNull(),
  content: text("content").notNull(),
  isDefault: integer("is_default", { mode: "boolean" }).notNull().default(false),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
});

export const subscriptions = sqliteTable("subscriptions", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  defaultTarget: text("default_target", { enum: ["raw", "mihomo", "json"] }).notNull().default("mihomo"),
  rulesJson: text("rules_json").notNull().default("{}"),
  templateId: text("template_id").references(() => templates.id, { onDelete: "set null" }),
  revision: integer("revision").notNull().default(1),
  expiresAt: text("expires_at"),
  cacheTtl: integer("cache_ttl").notNull().default(300),
  lastGeneratedAt: text("last_generated_at"),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
});

export const subscriptionSources = sqliteTable(
  "subscription_sources",
  {
    subscriptionId: text("subscription_id").notNull().references(() => subscriptions.id, { onDelete: "cascade" }),
    sourceId: text("source_id").notNull().references(() => sources.id, { onDelete: "cascade" }),
  },
  (table) => [primaryKey({ columns: [table.subscriptionId, table.sourceId] }), index("idx_subscription_sources_source").on(table.sourceId)],
);

export const subscriptionTokens = sqliteTable(
  "subscription_tokens",
  {
    id: text("id").primaryKey(),
    subscriptionId: text("subscription_id").notNull().references(() => subscriptions.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull(),
    tokenPrefix: text("token_prefix").notNull(),
    enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
    lastAccessAt: text("last_access_at"),
    expiresAt: text("expires_at"),
    createdAt: text("created_at").notNull(),
  },
  (table) => [uniqueIndex("subscription_tokens_hash_unique").on(table.tokenHash)],
);

export const auditLogs = sqliteTable(
  "audit_logs",
  {
    id: text("id").primaryKey(),
    adminId: text("admin_id").references(() => admins.id, { onDelete: "set null" }),
    action: text("action").notNull(),
    targetType: text("target_type"),
    targetId: text("target_id"),
    detailsJson: text("details_json").notNull().default("{}"),
    requestId: text("request_id"),
    createdAt: text("created_at").notNull(),
  },
  (table) => [index("idx_audit_logs_created_at").on(table.createdAt)],
);
