import type { NormalizedNode } from "../../../shared/types";
import { sha256Hex } from "../../security/crypto";

export function decodeBase64Text(value: string): string {
  const normalized = value.trim().replaceAll("-", "+").replaceAll("_", "/").replace(/\s+/gu, "");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return new TextDecoder().decode(Uint8Array.from(binary, (character) => character.charCodeAt(0)));
}

export function encodeBase64Text(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left.localeCompare(right)).map(([key, child]) => [key, sortValue(child)]));
  }
  return value;
}

export async function completeNode(input: Omit<NormalizedNode, "fingerprint" | "tags" | "enabled"> & Partial<Pick<NormalizedNode, "tags" | "enabled">>): Promise<NormalizedNode> {
  const identity = {
    protocol: input.protocol.toLowerCase(),
    server: input.server.toLowerCase(),
    port: input.port,
    config: sortValue(Object.fromEntries(Object.entries(input.config).filter(([key]) => key !== "name"))),
  };
  return {
    ...input,
    protocol: input.protocol.toLowerCase(),
    tags: input.tags ?? [],
    enabled: input.enabled ?? true,
    fingerprint: await sha256Hex(JSON.stringify(identity)),
  };
}

export function validPort(value: unknown): number | undefined {
  const port = typeof value === "number" ? value : Number(value);
  return Number.isInteger(port) && port > 0 && port <= 65_535 ? port : undefined;
}

export function hasSafeStructure(value: unknown, maxDepth = 32, maxEntries = 100_000): boolean {
  const pending: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  let entries = 0;
  while (pending.length) {
    const current = pending.pop()!;
    if (current.depth > maxDepth || entries > maxEntries) return false;
    if (!current.value || typeof current.value !== "object") continue;
    const children = Array.isArray(current.value) ? current.value : Object.values(current.value as Record<string, unknown>);
    entries += children.length;
    for (const child of children) pending.push({ value: child, depth: current.depth + 1 });
  }
  return entries <= maxEntries;
}
