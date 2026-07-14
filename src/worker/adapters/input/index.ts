import type { NormalizedNode } from "../../../shared/types";
import { AppError } from "../../shared/errors";
import { parseClashYaml } from "./clash.parser";
import { parseInternalJson } from "./internal-json.parser";
import { decodeBase64Text } from "./shared";
import { parseUriList } from "./uri-list.parser";

function deduplicate(nodes: NormalizedNode[]): NormalizedNode[] {
  return [...new Map(nodes.map((node) => [node.fingerprint, node])).values()];
}

export async function parseSubscriptionContent(input: string): Promise<NormalizedNode[]> {
  const content = input.replace(/^\uFEFF/u, "").trim();
  if (!content) throw new AppError(422, "数据源内容为空", "empty_source");
  let candidate = content;
  if (!content.includes("://") && /^[A-Za-z0-9+/_=\r\n-]+$/u.test(content)) {
    try {
      const decoded = decodeBase64Text(content);
      if (decoded.includes("://") || decoded.includes("proxies:") || decoded.startsWith("[") || decoded.startsWith("{")) candidate = decoded;
    } catch {
      // Continue with the original input.
    }
  }
  const adapters = [parseInternalJson, parseClashYaml, parseUriList];
  for (const adapter of adapters) {
    try {
      const nodes = deduplicate(await adapter(candidate));
      if (nodes.length > 0) return nodes;
    } catch {
      // A format mismatch should not prevent the next adapter from trying.
    }
  }
  throw new AppError(422, "未识别到受支持的节点配置", "unsupported_source_format");
}
