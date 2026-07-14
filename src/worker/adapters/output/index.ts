import { stringify } from "yaml";
import type { NormalizedNode, SubscriptionRules, SubscriptionTarget } from "../../../shared/types";
import { encodeBase64Text } from "../input/shared";

function safeRegex(pattern: string): RegExp | undefined {
  if (pattern.length > 200) return undefined;
  try { return new RegExp(pattern, "iu"); } catch { return undefined; }
}

export function applySubscriptionRules(nodes: NormalizedNode[], rules: SubscriptionRules): NormalizedNode[] {
  const protocols = new Set(rules.protocols?.map((value) => value.toLowerCase()) ?? []);
  const include = rules.includeName ? safeRegex(rules.includeName) : undefined;
  const exclude = rules.excludeName ? safeRegex(rules.excludeName) : undefined;
  const requiredTags = new Set(rules.tags ?? []);
  const seen = new Set<string>();
  const output = nodes.filter((node) => {
    if (!node.enabled || seen.has(node.fingerprint)) return false;
    if (protocols.size > 0 && !protocols.has(node.protocol.toLowerCase())) return false;
    if (requiredTags.size > 0 && ![...requiredTags].every((tag) => node.tags.includes(tag))) return false;
    if (include && !include.test(node.name)) return false;
    if (exclude?.test(node.name)) return false;
    seen.add(node.fingerprint);
    return true;
  }).map((node) => {
    let name = node.name;
    for (const rule of rules.rename ?? []) {
      const pattern = safeRegex(rule.pattern);
      if (pattern) name = name.replace(pattern, rule.replacement.slice(0, 200));
    }
    return { ...node, name, config: { ...node.config, name } };
  });
  const sortBy = rules.sortBy ?? "name";
  output.sort((left, right) => {
    if (sortBy === "protocol") return left.protocol.localeCompare(right.protocol) || left.name.localeCompare(right.name);
    if (sortBy === "source") return (left.sourceId ?? "").localeCompare(right.sourceId ?? "") || left.name.localeCompare(right.name);
    return left.name.localeCompare(right.name, "zh-CN");
  });
  return output;
}

function uriForNode(node: NormalizedNode): string | undefined {
  if (node.rawUri) return node.rawUri;
  const config = node.config;
  const name = encodeURIComponent(node.name);
  if (node.protocol === "ss" && typeof config.cipher === "string" && typeof config.password === "string") {
    const credentials = encodeBase64Text(config.cipher + ":" + config.password).replace(/=+$/u, "");
    return "ss://" + credentials + "@" + node.server + ":" + node.port + "#" + name;
  }
  if (node.protocol === "vmess" && typeof config.uuid === "string") {
    const payload = { v: "2", ps: node.name, add: node.server, port: String(node.port), id: config.uuid, aid: String(config.alterId ?? 0), net: config.network ?? "tcp", tls: config.tls ? "tls" : "", sni: config.servername ?? "" };
    return "vmess://" + encodeBase64Text(JSON.stringify(payload)).replace(/=+$/u, "");
  }
  const credential = node.protocol === "vless" || node.protocol === "tuic" ? config.uuid : config.password;
  if (typeof credential !== "string") return undefined;
  const query = new URLSearchParams();
  if (config.tls) query.set("security", "tls");
  if (typeof config.sni === "string") query.set("sni", config.sni);
  const password = node.protocol === "tuic" && typeof config.password === "string" ? ":" + encodeURIComponent(config.password) : "";
  return node.protocol + "://" + encodeURIComponent(credential) + password + "@" + node.server + ":" + node.port + (query.size ? "?" + query.toString() : "") + "#" + name;
}

export function renderSubscription(nodes: NormalizedNode[], target: SubscriptionTarget): { body: string; contentType: string; extension: string } {
  if (target === "json") {
    return { body: JSON.stringify({ version: 1, nodes }, null, 2), contentType: "application/json; charset=utf-8", extension: "json" };
  }
  if (target === "mihomo") {
    const proxies = nodes.map((node) => ({ ...node.config, name: node.name, type: node.protocol, server: node.server, port: node.port }));
    return { body: stringify({ proxies }, { lineWidth: 0 }), contentType: "application/yaml; charset=utf-8", extension: "yaml" };
  }
  const uris = nodes.map(uriForNode).filter((value): value is string => Boolean(value));
  return { body: encodeBase64Text(uris.join("\n")), contentType: "text/plain; charset=utf-8", extension: "txt" };
}
