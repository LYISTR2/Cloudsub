import { z } from "zod";
import { validateSafePattern } from "./security/regex";

// ─── Centralised request-body schemas ────────────────────────────────
// Extracted from the route handlers so every module validates against a
// single, shared source of truth.

export const setupSchema = z.object({
  username: z.string().trim().min(3).max(40).regex(/^[A-Za-z0-9_.-]+$/u),
  password: z.string().min(12).max(200),
  setupToken: z.string().max(500).optional(),
});

export const loginSchema = z.object({
  username: z.string().trim().min(1).max(40),
  password: z.string().min(1).max(200),
});

export const passwordSchema = z.object({
  currentPassword: z.string().min(1).max(200),
  newPassword: z.string().min(12).max(200),
});

export const sourceCreateSchema = z.object({
  name: z.string().trim().min(1).max(100),
  type: z.enum(["url", "manual"]),
  sourceKind: z.enum(["subscription", "standalone"]).default("subscription"),
  url: z.string().trim().max(2_000).optional(),
  content: z.string().max(5_300_000).optional(),
  headers: z.record(z.string(), z.string().max(2_000)).optional(),
  userAgent: z.string().trim().max(200).optional(),
  enabled: z.boolean().default(true),
  refreshInterval: z.number().int().min(5).max(10_080).default(60),
  timeoutMs: z.number().int().min(1_000).max(30_000).default(15_000),
});

// source_kind is decided at creation time and cannot be changed afterwards.
export const sourceUpdateSchema = sourceCreateSchema.partial().omit({ type: true, sourceKind: true });

export const nodeUpdateSchema = z.object({
  name: z.string().trim().min(1).max(200).optional(),
  enabled: z.boolean().optional(),
  tags: z.array(z.string().trim().min(1).max(40)).max(20).optional(),
});

export const nodeBatchSchema = z.object({
  ids: z.array(z.string().uuid()).min(1).max(100),
  enabled: z.boolean().optional(),
  tags: z.array(z.string().trim().min(1).max(40)).max(20).optional(),
});

/**
 * Name-filter pattern validated against the linear-time safe subset
 * (security/regex.ts). Invalid or unsafe patterns are rejected at the API
 * with the engine's human-readable reason instead of being stored.
 */
const safeNamePattern = z.string().max(200).superRefine((value, context) => {
  const reason = validateSafePattern(value);
  if (reason !== null) context.addIssue({ code: "custom", message: reason });
});

export const rulesSchema = z.object({
  protocols: z.array(z.string().trim().min(1).max(30)).max(20).optional(),
  tags: z.array(z.string().trim().min(1).max(40)).max(20).optional(),
  includeName: safeNamePattern.optional(),
  excludeName: safeNamePattern.optional(),
  sortBy: z.enum(["name", "protocol", "source"]).optional(),
  rename: z.array(z.object({ pattern: safeNamePattern, replacement: z.string().max(200) })).max(20).optional(),
});

export const subscriptionCreateSchema = z.object({
  name: z.string().trim().min(1).max(100),
  sourceIds: z.array(z.string().uuid()).min(1).max(100),
  defaultTarget: z.enum(["raw", "mihomo", "singbox", "json"]).default("mihomo"),
  enabled: z.boolean().default(true),
  cacheTtl: z.number().int().min(60).max(86_400).default(300),
  expiresAt: z.string().datetime().nullable().optional(),
  rules: rulesSchema.default({}),
});

export const subscriptionUpdateSchema = subscriptionCreateSchema.partial();

export const previewSchema = z.object({ target: z.enum(["raw", "mihomo", "singbox", "json"]).optional() });

export const settingsSchema = z.object({ timezone: z.string().trim().min(1).max(100) });
