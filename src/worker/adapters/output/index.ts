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

// ─── Raw URI generation ──────────────────────────────────────────────

function uriForNode(node: NormalizedNode): string | undefined {
  if (node.rawUri) return node.rawUri;
  const config = node.config;
  const name = encodeURIComponent(node.name);

  if (node.protocol === "ss" && typeof config.cipher === "string" && typeof config.password === "string") {
    const credentials = encodeBase64Text(config.cipher + ":" + config.password).replace(/=+$/u, "");
    let uri = "ss://" + credentials + "@" + node.server + ":" + node.port;
    const query = new URLSearchParams();
    if (typeof config.plugin === "string") query.set("plugin", config.plugin);
    if (query.size) uri += "?" + query.toString();
    return uri + "#" + name;
  }

  if (node.protocol === "vmess" && typeof config.uuid === "string") {
    const payload: Record<string, string> = {
      v: "2", ps: node.name, add: node.server, port: String(node.port),
      id: config.uuid, aid: String(config.alterId ?? 0),
      net: typeof config.network === "string" ? config.network : "tcp",
      tls: config.tls ? "tls" : "",
      sni: typeof config.servername === "string" ? config.servername : "",
    };
    if (config["ws-opts"] && typeof config["ws-opts"] === "object") {
      const wsOpts = config["ws-opts"] as Record<string, unknown>;
      if (typeof wsOpts.path === "string") payload.path = wsOpts.path;
      if (wsOpts.headers && typeof wsOpts.headers === "object") {
        const headers = wsOpts.headers as Record<string, string>;
        if (headers.Host) payload.host = headers.Host;
      }
    }
    if (typeof config.flow === "string") payload.flow = config.flow;
    if (Array.isArray(config.alpn)) payload.alpn = (config.alpn as string[]).join(",");
    return "vmess://" + encodeBase64Text(JSON.stringify(payload)).replace(/=+$/u, "");
  }

  const credential = node.protocol === "vless" || node.protocol === "tuic" ? config.uuid : config.password;
  if (typeof credential !== "string") return undefined;

  const query = new URLSearchParams();
  if (config.tls) query.set("security", "tls");
  if (typeof config.sni === "string") query.set("sni", config.sni);
  if (typeof config.network === "string" && config.network !== "tcp") query.set("type", config.network);
  if (typeof config.flow === "string") query.set("flow", config.flow);
  if (Array.isArray(config.alpn)) query.set("alpn", (config.alpn as string[]).join(","));
  if (config["skip-cert-verify"]) query.set("allowInsecure", "1");
  if (config["ws-opts"] && typeof config["ws-opts"] === "object") {
    const wsOpts = config["ws-opts"] as Record<string, unknown>;
    if (typeof wsOpts.path === "string") query.set("path", wsOpts.path);
    if (wsOpts.headers && typeof wsOpts.headers === "object") {
      const headers = wsOpts.headers as Record<string, string>;
      if (headers.Host) query.set("host", headers.Host);
    }
  }
  // Hysteria2 obfs
  if (node.protocol === "hysteria2") {
    if (typeof config.obfs === "string") query.set("obfs", config.obfs);
    if (typeof config["obfs-password"] === "string") query.set("obfs-password", config["obfs-password"]);
    if (typeof config.up === "string") query.set("up", config.up);
    if (typeof config.down === "string") query.set("down", config.down);
  }
  // TUIC specific
  if (node.protocol === "tuic" && typeof config["congestion-controller"] === "string") {
    query.set("congestion_control", config["congestion-controller"]);
  }

  const password = node.protocol === "tuic" && typeof config.password === "string" ? ":" + encodeURIComponent(config.password) : "";
  return node.protocol + "://" + encodeURIComponent(credential) + password + "@" + node.server + ":" + node.port + (query.size ? "?" + query.toString() : "") + "#" + name;
}

// ─── Mihomo / Clash Meta full config ─────────────────────────────────

function buildMihomoConfig(nodes: NormalizedNode[]): Record<string, unknown> {
  const proxies = nodes.map((node) => ({ ...node.config, name: node.name, type: node.protocol, server: node.server, port: node.port }));
  const proxyNames = proxies.map((p) => p.name as string);

  const proxyGroups = [
    { name: "🚀 节点选择", type: "select", proxies: ["♻️ 自动选择", ...proxyNames] },
    { name: "♻️ 自动选择", type: "url-test", proxies: proxyNames, url: "https://www.gstatic.com/generate_204", interval: 300, tolerance: 50 },
    { name: "🌍 国外媒体", type: "select", proxies: ["🚀 节点选择", "♻️ 自动选择", ...proxyNames] },
    { name: "📲 Telegram", type: "select", proxies: ["🚀 节点选择", "♻️ 自动选择", ...proxyNames] },
    { name: "🍎 Apple", type: "select", proxies: ["🚀 节点选择", "DIRECT"] },
    { name: "🤖 AI", type: "select", proxies: ["🚀 节点选择", "♻️ 自动选择", ...proxyNames] },
    { name: "🐟 漏网之鱼", type: "select", proxies: ["🚀 节点选择", "DIRECT"] },
  ];

  const rules = [
    "DOMAIN-SUFFIX,openai.com,🤖 AI",
    "DOMAIN-SUFFIX,anthropic.com,🤖 AI",
    "DOMAIN-SUFFIX,claude.ai,🤖 AI",
    "DOMAIN-SUFFIX,gemini.google.com,🤖 AI",
    "DOMAIN-SUFFIX,copilot.microsoft.com,🤖 AI",
    "DOMAIN-KEYword,telegram,📲 Telegram",
    "DOMAIN-SUFFIX,t.me,📲 Telegram",
    "DOMAIN-SUFFIX,telegra.ph,📲 Telegram",
    "DOMAIN-SUFFIX,netflix.com,🌍 国外媒体",
    "DOMAIN-SUFFIX,nflxvideo.net,🌍 国外媒体",
    "DOMAIN-SUFFIX,youtube.com,🌍 国外媒体",
    "DOMAIN-SUFFIX,googlevideo.com,🌍 国外媒体",
    "DOMAIN-SUFFIX,ggpht.com,🌍 国外媒体",
    "DOMAIN-SUFFIX,apple.com,🍎 Apple",
    "DOMAIN-SUFFIX,icloud.com,🍎 Apple",
    "GEOIP,CN,DIRECT",
    "MATCH,🐟 漏网之鱼",
  ];

  return { proxies, "proxy-groups": proxyGroups, rules };
}

// ─── Sing-box JSON ───────────────────────────────────────────────────

function buildSingboxConfig(nodes: NormalizedNode[]): Record<string, unknown> {
  const outbounds: Record<string, unknown>[] = [];
  const tagMap: Record<string, string>[] = [];

  for (const node of nodes) {
    const tag = node.name;
    const config = node.config;
    const outbound: Record<string, unknown> = { tag, server: node.server, server_port: node.port };

    if (node.protocol === "ss") {
      outbound.type = "shadowsocks";
      outbound.method = config.cipher;
      outbound.password = config.password;
    } else if (node.protocol === "vmess") {
      outbound.type = "vmess";
      outbound.uuid = config.uuid;
      outbound.security = config.cipher ?? "auto";
      if (config.alterId) outbound.alter_id = Number(config.alterId);
    } else if (node.protocol === "vless") {
      outbound.type = "vless";
      outbound.uuid = config.uuid;
      if (config.flow) outbound.flow = config.flow;
    } else if (node.protocol === "trojan") {
      outbound.type = "trojan";
      outbound.password = config.password;
    } else if (node.protocol === "hysteria2") {
      outbound.type = "hysteria2";
      outbound.password = config.password;
      if (config.obfs) outbound.obfs = config.obfs;
      if (config["obfs-password"]) outbound.obfs_password = config["obfs-password"];
      if (config.up) outbound.up_mbps = Number(config.up);
      if (config.down) outbound.down_mbps = Number(config.down);
    } else if (node.protocol === "tuic") {
      outbound.type = "tuic";
      outbound.uuid = config.uuid;
      outbound.password = config.password;
      if (config["congestion-controller"]) outbound.congestion_control = config["congestion-controller"];
    } else {
      continue;
    }

    if (config.tls) {
      outbound.tls = {
        enabled: true,
        server_name: config.sni ?? config.servername,
        insecure: Boolean(config["skip-cert-verify"]),
        alpn: Array.isArray(config.alpn) ? config.alpn : undefined,
      };
    }
    if (config.network === "ws" && config["ws-opts"]) {
      const wsOpts = config["ws-opts"] as Record<string, unknown>;
      outbound.transport = {
        type: "ws",
        path: wsOpts.path ?? "/",
        headers: wsOpts.headers ?? {},
      };
    } else if (config.network === "grpc" && config["grpc-opts"]) {
      const grpcOpts = config["grpc-opts"] as Record<string, unknown>;
      outbound.transport = { type: "grpc", service_name: grpcOpts["grpc-service-name"] ?? "" };
    }

    tagMap.push({ tag, protocol: node.protocol });
    outbounds.push(outbound);
  }

  const proxyTags = tagMap.map((t) => t.tag);

  outbounds.push({ type: "selector", tag: "🚀 节点选择", outbounds: ["♻️ 自动选择", ...proxyTags], default: "♻️ 自动选择" });
  outbounds.push({ type: "urltest", tag: "♻️ 自动选择", outbounds: proxyTags, url: "https://www.gstatic.com/generate_204", interval: "5m", tolerance: 50 });
  outbounds.push({ type: "direct", tag: "DIRECT" });
  outbounds.push({ type: "dns", tag: "dns-out" });

  const routeRules = [
    { domain_suffix: ["openai.com", "anthropic.com", "claude.ai", "gemini.google.com"], outbound: "🚀 节点选择" },
    { domain_suffix: ["t.me", "telegram.org"], outbound: "🚀 节点选择" },
    { domain_suffix: ["netflix.com", "nflxvideo.net", "youtube.com", "googlevideo.com"], outbound: "🚀 节点选择" },
    { geoip: "cn", outbound: "DIRECT" },
  ];

  return {
    log: { level: "info" },
    dns: {
      servers: [
        { tag: "google", address: "https://dns.google/dns-query", detour: "🚀 节点选择" },
        { tag: "local", address: "223.5.5.5", detour: "DIRECT" },
      ],
      rules: [{ geoip: "cn", server: "local" }],
    },
    outbounds,
    route: { rules: routeRules, final: "🚀 节点选择" },
  };
}

// ─── Main renderer ───────────────────────────────────────────────────

export function renderSubscription(nodes: NormalizedNode[], target: SubscriptionTarget): { body: string; contentType: string; extension: string } {
  if (target === "json") {
    return { body: JSON.stringify({ version: 1, nodes }, null, 2), contentType: "application/json; charset=utf-8", extension: "json" };
  }
  if (target === "mihomo") {
    return { body: stringify(buildMihomoConfig(nodes), { lineWidth: 0 }), contentType: "application/yaml; charset=utf-8", extension: "yaml" };
  }
  if (target === "singbox") {
    return { body: JSON.stringify(buildSingboxConfig(nodes), null, 2), contentType: "application/json; charset=utf-8", extension: "json" };
  }
  // raw
  const uris = nodes.map(uriForNode).filter((value): value is string => Boolean(value));
  return { body: encodeBase64Text(uris.join("\n")), contentType: "text/plain; charset=utf-8", extension: "txt" };
}
