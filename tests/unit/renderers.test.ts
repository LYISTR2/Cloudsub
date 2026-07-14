import { describe, expect, it } from "vitest";
import type { NormalizedNode } from "../../src/shared/types";
import { applySubscriptionRules, renderSubscription } from "../../src/worker/adapters/output";
import { decodeBase64Text } from "../../src/worker/adapters/input/shared";

const nodes: NormalizedNode[] = [
  { name: "Tokyo 01", protocol: "vless", server: "jp.example.com", port: 443, config: { type: "vless", uuid: "id-1", tls: true }, tags: ["premium"], enabled: true, fingerprint: "a" },
  { name: "Blocked", protocol: "ss", server: "us.example.com", port: 443, config: { type: "ss", cipher: "aes-128-gcm", password: "secret" }, tags: [], enabled: false, fingerprint: "b" },
  { name: "Tokyo 01 duplicate", protocol: "vless", server: "jp.example.com", port: 443, config: { type: "vless", uuid: "id-1", tls: true }, tags: ["premium"], enabled: true, fingerprint: "a" },
];

describe("subscription rules and renderers", () => {
  it("filters, deduplicates and renames in a stable order", () => {
    const output = applySubscriptionRules(nodes, { protocols: ["vless"], tags: ["premium"], rename: [{ pattern: "Tokyo", replacement: "JP" }] });
    expect(output).toHaveLength(1);
    expect(output[0].name).toBe("JP 01");
  });

  it("renders Mihomo YAML with proxy-groups and rules", () => {
    const enabled = applySubscriptionRules(nodes, {});
    const body = renderSubscription(enabled, "mihomo").body;
    expect(body).toContain("proxies:");
    expect(body).toContain("proxy-groups:");
    expect(body).toContain("rules:");
    expect(body).toContain("url-test");
  });

  it("renders Sing-box JSON config", () => {
    const enabled = applySubscriptionRules(nodes, {});
    const body = renderSubscription(enabled, "singbox").body;
    const parsed = JSON.parse(body);
    expect(parsed.outbounds).toBeDefined();
    expect(parsed.route).toBeDefined();
    expect(parsed.dns).toBeDefined();
    expect(parsed.outbounds.some((o: Record<string, unknown>) => o.type === "selector")).toBe(true);
  });

  it("renders JSON output through adapters", () => {
    const enabled = applySubscriptionRules(nodes, {});
    expect(JSON.parse(renderSubscription(enabled, "json").body).nodes).toHaveLength(1);
  });

  it("renders standard Base64 raw subscriptions with transport params", () => {
    const testNodes: NormalizedNode[] = [
      { name: "WS Node", protocol: "vless", server: "ws.example.com", port: 443, config: { type: "vless", uuid: "id-ws", tls: true, network: "ws", "ws-opts": { path: "/ray", headers: { Host: "cdn.example.com" } } }, tags: [], enabled: true, fingerprint: "ws1" },
    ];
    const body = renderSubscription(testNodes, "raw").body;
    const decoded = decodeBase64Text(body);
    expect(decoded).toContain("vless://");
    expect(decoded).toContain("type=ws");
    expect(decoded).toContain("path=%2Fray");
    expect(decoded).toContain("host=cdn.example.com");
  });

  it("preserves hysteria2 obfs params in raw output", () => {
    const testNodes: NormalizedNode[] = [
      { name: "Hy2 Node", protocol: "hysteria2", server: "hy2.example.com", port: 443, config: { type: "hysteria2", password: "pass123", obfs: "salamander", "obfs-password": "obfspass", up: "100", down: "200" }, tags: [], enabled: true, fingerprint: "hy1" },
    ];
    const body = renderSubscription(testNodes, "raw").body;
    const decoded = decodeBase64Text(body);
    expect(decoded).toContain("obfs=salamander");
    expect(decoded).toContain("obfs-password=obfspass");
  });
});
