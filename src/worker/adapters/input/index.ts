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

/**
 * Strict parser for standalone (single-node) sources.
 *
 * A standalone source must contain exactly ONE supported node URI and
 * nothing else: multiple URIs, duplicate URIs, a "valid URI plus garbage"
 * mix, and YAML/JSON masquerading as a URI are all rejected. This is
 * enforced on create, update and refresh so the single-node invariant can
 * never be violated through any write path.
 *
 * A single base64-wrapped URI is accepted (the blob must decode to exactly
 * one URI line); base64 of YAML/JSON never passes because the decoded text
 * is not a URI.
 */
export async function parseStandaloneUri(input: string): Promise<NormalizedNode> {
  const content = input.replace(/^\uFEFF/u, "").trim();
  if (!content) throw new AppError(422, "单节点数据源内容为空", "empty_source");
  const lines = content.split(/\r?\n/gu).map((line) => line.trim()).filter(Boolean);
  if (lines.length !== 1) {
    throw new AppError(422, "单节点数据源必须恰好包含一个节点链接", "standalone_requires_single_node");
  }
  let line = lines[0];
  if (!line.includes("://")) {
    try {
      const decoded = decodeBase64Text(line).trim();
      if (decoded.includes("://") && !decoded.includes("\n")) line = decoded;
    } catch {
      // Not base64 — treated as a plain (invalid) line below.
    }
  }
  if (!/^[a-z][a-z0-9+.-]*:\/\//iu.test(line)) {
    throw new AppError(422, "单节点数据源必须是受支持的节点链接", "invalid_standalone_uri");
  }
  const nodes = await parseUriList(line);
  if (nodes.length !== 1) {
    throw new AppError(422, "单节点数据源必须是受支持的节点链接", "invalid_standalone_uri");
  }
  return nodes[0];
}
