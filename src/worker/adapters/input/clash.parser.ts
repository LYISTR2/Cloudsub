import { parse } from "yaml";
import type { NormalizedNode } from "../../../shared/types";
import { completeNode, hasSafeStructure, validPort } from "./shared";

export async function parseClashYaml(content: string): Promise<NormalizedNode[]> {
  const document = parse(content, { maxAliasCount: 20 }) as unknown;
  if (!document || typeof document !== "object") return [];
  if (!hasSafeStructure(document)) return [];
  const proxies = (document as Record<string, unknown>).proxies;
  if (!Array.isArray(proxies)) return [];
  const nodes: NormalizedNode[] = [];
  for (const proxy of proxies.slice(0, 10_000)) {
    if (!proxy || typeof proxy !== "object") continue;
    const config = proxy as Record<string, unknown>;
    const name = typeof config.name === "string" ? config.name.trim() : "";
    const protocol = typeof config.type === "string" ? config.type.toLowerCase() : "";
    const server = typeof config.server === "string" ? config.server.trim() : "";
    const port = validPort(config.port);
    if (!name || !protocol || !server || !port) continue;
    nodes.push(await completeNode({ name, protocol, server, port, config: { ...config, port }, rawUri: undefined }));
  }
  return nodes;
}
