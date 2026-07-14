import type { NormalizedNode } from "../../../shared/types";
import { completeNode, decodeBase64Text, validPort } from "./shared";

function decodedName(fragment: string, fallback: string): string {
  if (!fragment) return fallback;
  try {
    return decodeURIComponent(fragment);
  } catch {
    return fragment;
  }
}

function hostAndPort(value: string): { server: string; port: number } | undefined {
  try {
    const parsed = new URL("https://" + value);
    const port = validPort(parsed.port);
    if (!parsed.hostname || !port) return undefined;
    return { server: parsed.hostname, port };
  } catch {
    return undefined;
  }
}

async function parseShadowsocks(uri: string): Promise<NormalizedNode | undefined> {
  const [withoutFragment, fragment = ""] = uri.slice(5).split("#", 2);
  const [main, query = ""] = withoutFragment.split("?", 2);
  let credentials: string;
  let endpoint: string;
  if (main.includes("@")) {
    const separator = main.lastIndexOf("@");
    credentials = main.slice(0, separator);
    endpoint = main.slice(separator + 1);
    if (!credentials.includes(":")) {
      try { credentials = decodeBase64Text(credentials); } catch { return undefined; }
    }
  } else {
    let decoded: string;
    try { decoded = decodeBase64Text(main); } catch { return undefined; }
    const separator = decoded.lastIndexOf("@");
    if (separator < 1) return undefined;
    credentials = decoded.slice(0, separator);
    endpoint = decoded.slice(separator + 1);
  }
  const credentialSeparator = credentials.indexOf(":");
  const target = hostAndPort(endpoint);
  if (credentialSeparator < 1 || !target) return undefined;
  const cipher = credentials.slice(0, credentialSeparator);
  const password = credentials.slice(credentialSeparator + 1);
  const name = decodedName(fragment, "SS · " + target.server);
  const config: Record<string, unknown> = { name, type: "ss", ...target, cipher, password };
  const plugin = new URLSearchParams(query).get("plugin");
  if (plugin) config.plugin = plugin;
  return completeNode({ name, protocol: "ss", ...target, config, rawUri: uri });
}

async function parseVmess(uri: string): Promise<NormalizedNode | undefined> {
  let payload: Record<string, unknown>;
  try { payload = JSON.parse(decodeBase64Text(uri.slice(8))) as Record<string, unknown>; } catch { return undefined; }
  const server = typeof payload.add === "string" ? payload.add : "";
  const port = validPort(payload.port);
  if (!server || !port || typeof payload.id !== "string") return undefined;
  const name = typeof payload.ps === "string" && payload.ps ? payload.ps : "VMess · " + server;
  const config: Record<string, unknown> = {
    name,
    type: "vmess",
    server,
    port,
    uuid: payload.id,
    alterId: Number(payload.aid ?? 0),
    cipher: typeof payload.scy === "string" ? payload.scy : "auto",
    udp: true,
  };
  if (payload.net && payload.net !== "tcp") config.network = payload.net;
  if (payload.tls === "tls") config.tls = true;
  if (payload.sni) config.servername = payload.sni;
  if (payload.host || payload.path) config["ws-opts"] = { headers: payload.host ? { Host: payload.host } : undefined, path: payload.path };
  return completeNode({ name, protocol: "vmess", server, port, config, rawUri: uri });
}

async function parseUrlNode(uri: string): Promise<NormalizedNode | undefined> {
  let url: URL;
  try { url = new URL(uri); } catch { return undefined; }
  const protocol = url.protocol.slice(0, -1).toLowerCase();
  if (!["vless", "trojan", "hysteria2", "hy2", "tuic"].includes(protocol)) return undefined;
  const port = validPort(url.port);
  if (!url.hostname || !port) return undefined;
  const normalizedProtocol = protocol === "hy2" ? "hysteria2" : protocol;
  const name = decodedName(url.hash.slice(1), normalizedProtocol.toUpperCase() + " · " + url.hostname);
  const config: Record<string, unknown> = { name, type: normalizedProtocol, server: url.hostname, port, udp: true };
  const username = decodeURIComponent(url.username);
  const password = decodeURIComponent(url.password);
  if (normalizedProtocol === "vless") config.uuid = username;
  if (normalizedProtocol === "trojan" || normalizedProtocol === "hysteria2") config.password = username || password;
  if (normalizedProtocol === "tuic") {
    config.uuid = username;
    config.password = password;
  }
  const query = url.searchParams;
  if (query.get("security") === "tls" || normalizedProtocol === "trojan" || normalizedProtocol === "hysteria2") config.tls = true;
  if (query.get("sni")) config.sni = query.get("sni");
  if (query.get("type") && query.get("type") !== "tcp") config.network = query.get("type");
  if (query.get("flow")) config.flow = query.get("flow");
  if (query.get("alpn")) config.alpn = query.get("alpn")?.split(",");
  if (query.get("allowInsecure") === "1") config["skip-cert-verify"] = true;
  if (query.get("path")) config["ws-opts"] = { path: query.get("path"), headers: query.get("host") ? { Host: query.get("host") } : undefined };
  // Hysteria2 obfs
  if (normalizedProtocol === "hysteria2") {
    if (query.get("obfs")) config.obfs = query.get("obfs");
    if (query.get("obfs-password")) config["obfs-password"] = query.get("obfs-password");
    if (query.get("up")) config.up = query.get("up");
    if (query.get("down")) config.down = query.get("down");
  }
  // TUIC congestion control
  if (normalizedProtocol === "tuic") {
    if (query.get("congestion_control")) config["congestion-controller"] = query.get("congestion_control");
  }
  return completeNode({ name, protocol: normalizedProtocol, server: url.hostname, port, config, rawUri: uri });
}

export async function parseUriList(content: string): Promise<NormalizedNode[]> {
  const nodes: NormalizedNode[] = [];
  const lines = content.split(/\r?\n/gu).map((line) => line.trim()).filter(Boolean).slice(0, 10_000);
  for (const line of lines) {
    let node: NormalizedNode | undefined;
    if (line.startsWith("ss://")) node = await parseShadowsocks(line);
    else if (line.startsWith("vmess://")) node = await parseVmess(line);
    else node = await parseUrlNode(line);
    if (node) nodes.push(node);
  }
  return nodes;
}
