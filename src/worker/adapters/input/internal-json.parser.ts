import type { NormalizedNode } from "../../../shared/types";
import { completeNode, hasSafeStructure, validPort } from "./shared";

export async function parseInternalJson(content: string): Promise<NormalizedNode[]> {
  let parsed: unknown;
  try { parsed = JSON.parse(content); } catch { return []; }
  if (!hasSafeStructure(parsed)) return [];
  const entries = Array.isArray(parsed) ? parsed : parsed && typeof parsed === "object" && Array.isArray((parsed as Record<string, unknown>).nodes) ? (parsed as Record<string, unknown>).nodes as unknown[] : [];
  const nodes: NormalizedNode[] = [];
  for (const value of entries.slice(0, 10_000)) {
    if (!value || typeof value !== "object") continue;
    const input = value as Record<string, unknown>;
    const name = typeof input.name === "string" ? input.name : "";
    const protocol = typeof input.protocol === "string" ? input.protocol : typeof input.type === "string" ? input.type : "";
    const server = typeof input.server === "string" ? input.server : "";
    const port = validPort(input.port);
    if (!name || !protocol || !server || !port) continue;
    const config = input.config && typeof input.config === "object" ? input.config as Record<string, unknown> : { ...input, type: protocol };
    nodes.push(await completeNode({ name, protocol, server, port, config, tags: Array.isArray(input.tags) ? input.tags.filter((tag): tag is string => typeof tag === "string") : [], rawUri: typeof input.rawUri === "string" ? input.rawUri : undefined }));
  }
  return nodes;
}
