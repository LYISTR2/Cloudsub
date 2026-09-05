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

  it("skips legacy patterns that no longer compile instead of breaking output", () => {
    const output = applySubscriptionRules(nodes, { includeName: "(?=Tokyo)" });
    // The lookahead pattern is rejected by the safe engine; the rule is
    // silently skipped (legacy data tolerance) so the subscription still
    // renders.
    expect(output).toHaveLength(1);
  });

  it("renders Mihomo YAML with proxy-groups and rules", () => {
    const enabled = applySubscriptionRules(nodes, {});
    const body = renderSubscription(enabled, "mihomo").body;
    expect(body).toContain("proxies:");
    expect(body).toContain("proxy-groups:");
    expect(body).toContain("rules:");
    expect(body).toContain("url-test");
  });

  it("renders a sing-box 1.14 config: no geoip, no dns-out, explicit domain resolver", () => {
    const enabled = applySubscriptionRules(nodes, {});
    const body = renderSubscription(enabled, "singbox").body;
    const parsed = JSON.parse(body);
    expect(parsed.outbounds).toBeDefined();
    expect(parsed.route).toBeDefined();
    expect(parsed.dns).toBeDefined();
    expect(parsed.outbounds.some((o: Record<string, unknown>) => o.type === "selector")).toBe(true);
    // Constructs removed from sing-box must never be emitted.
    expect(parsed.outbounds.some((o: Record<string, unknown>) => o.type === "dns")).toBe(false);
    expect(JSON.stringify(parsed)).not.toContain("geoip");
    expect(JSON.stringify(parsed)).not.toContain("dns-out");
    expect(JSON.stringify(parsed)).not.toContain('"address"'); // legacy DNS server format
    // 1.14 requires an explicit domain resolver.
    expect(parsed.route.default_domain_resolver).toEqual({ server: "google" });
    // DNS servers use the new typed format.
    expect(parsed.dns.servers[0]).toMatchObject({ type: "https", server: "dns.google", server_port: 443 });
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

  it("reflects renames in raw output while preserving the original URI when unnamed", () => {
    const original = "vless://550e8400-e29b-41d4-a716-446655440000@ws.example.com:443?security=tls&sni=ws.example.com&type=ws&path=%2Fray&host=cdn.example.com#Tokyo%2001";
    const testNodes: NormalizedNode[] = [
      { name: "Tokyo 01", protocol: "vless", server: "ws.example.com", port: 443, config: { type: "vless", uuid: "550e8400-e29b-41d4-a716-446655440000", tls: true, sni: "ws.example.com", network: "ws", "ws-opts": { path: "/ray", headers: { Host: "cdn.example.com" } } }, tags: [], enabled: true, fingerprint: "ws1", rawUri: original },
    ];
    // Unchanged name → the exact original URI (params + credentials) is kept.
    const unchanged = decodeBase64Text(renderSubscription(testNodes, "raw").body);
    expect(unchanged).toBe(original);
    // Renamed via rules → regenerated from config with the new name.
    const renamed = applySubscriptionRules(testNodes, { rename: [{ pattern: "Tokyo", replacement: "JP" }] });
    const regenerated = decodeBase64Text(renderSubscription(renamed, "raw").body);
    expect(regenerated).toContain("#JP%2001");
    expect(regenerated).toContain("type=ws");
    expect(regenerated).toContain("host=cdn.example.com");
    expect(regenerated).toContain("sni=ws.example.com");
  });

  it("preserves hysteria2 obfs params in raw output", () => {
    const testNodes: NormalizedNode[] = [
      { name: "Hy2 Node", protocol: "hysteria2", server: "hy2.example.com", port: 443, config: { type: "hysteria2", password: "pass123", obfs: "salamander", "obfs-password": "obfspass", up: "100", down: "200" }, tags: [], enabled: true, fingerprint: "hy1" },
    ];
    const body = renderSubscription(testNodes, "raw").body;
    const decoded = decodeBase64Text(body);
    expect(decoded).toContain("obfs=salamander");
    expect(decoded).toContain("obfs-password=obfspass");
    expect(decoded).toContain("up=100");
    expect(decoded).toContain("down=200");
  });

  it("renders AnyTLS raw URIs preserving full options without a security param", () => {
    const testNodes: NormalizedNode[] = [
      { name: "AnyTLS Node", protocol: "anytls", server: "any.example.com", port: 443, config: { type: "anytls", password: "pass123", tls: true, sni: "any.example.com", alpn: ["h2", "http/1.1"], "skip-cert-verify": true, "client-fingerprint": "chrome", "idle-session-check-interval": "30s", "idle-session-timeout": "60s", "min-idle-session": 2 }, tags: [], enabled: true, fingerprint: "at1" },
    ];
    const body = renderSubscription(testNodes, "raw").body;
    const decoded = decodeBase64Text(body);
    expect(decoded).toContain("anytls://pass123@any.example.com:443");
    expect(decoded).not.toContain("security=");
    expect(decoded).toContain("sni=any.example.com");
    expect(decoded).toContain("alpn=h2%2Chttp%2F1.1");
    expect(decoded).toContain("allowInsecure=1");
    expect(decoded).toContain("client-fingerprint=chrome");
    expect(decoded).toContain("idle-session-check-interval=30s");
    expect(decoded).toContain("idle-session-timeout=60s");
    expect(decoded).toContain("min-idle-session=2");
  });

  it("renders AnyTLS proxies in Mihomo YAML with integer-second idle timings", () => {
    const testNodes: NormalizedNode[] = [
      { name: "AnyTLS Node", protocol: "anytls", server: "any.example.com", port: 443, config: { type: "anytls", password: "pass123", tls: true, sni: "any.example.com", alpn: ["h2", "http/1.1"], "skip-cert-verify": true, "client-fingerprint": "chrome", "idle-session-check-interval": "30s", "idle-session-timeout": "60s", "min-idle-session": 2 }, tags: [], enabled: true, fingerprint: "at1" },
    ];
    const body = renderSubscription(testNodes, "mihomo").body;
    expect(body).toContain("type: anytls");
    expect(body).toContain("password: pass123");
    expect(body).toContain("tls: true");
    expect(body).toContain("client-fingerprint: chrome");
    expect(body).toContain("min-idle-session: 2");
    // Mihomo parses these fields as int seconds — "30s" would fail `mihomo -t`.
    expect(body).toContain("idle-session-check-interval: 30");
    expect(body).toContain("idle-session-timeout: 60");
    expect(body).not.toContain("idle-session-check-interval: 30s");
  });

  it("renders AnyTLS outbounds in Sing-box JSON with duration strings and required TLS", () => {
    const testNodes: NormalizedNode[] = [
      { name: "AnyTLS Node", protocol: "anytls", server: "any.example.com", port: 443, config: { type: "anytls", password: "pass123", tls: true, sni: "any.example.com", alpn: ["h2", "http/1.1"], "skip-cert-verify": true, "client-fingerprint": "chrome", "idle-session-check-interval": "30s", "idle-session-timeout": "60s", "min-idle-session": 2 }, tags: [], enabled: true, fingerprint: "at1" },
    ];
    const body = renderSubscription(testNodes, "singbox").body;
    const parsed = JSON.parse(body);
    const outbound = parsed.outbounds.find((o: Record<string, unknown>) => o.type === "anytls");
    expect(outbound).toBeDefined();
    expect(outbound).toMatchObject({
      password: "pass123",
      server: "any.example.com",
      server_port: 443,
      idle_session_check_interval: "30s",
      idle_session_timeout: "60s",
      min_idle_session: 2,
      tls: { enabled: true, server_name: "any.example.com", insecure: true, alpn: ["h2", "http/1.1"], utls: { enabled: true, fingerprint: "chrome" } },
    });
  });

  it("emits TLS for TLS-only protocols even when the YAML omits the flag", () => {
    const testNodes: NormalizedNode[] = [
      { name: "Hy2", protocol: "hysteria2", server: "hy2.example.com", port: 443, config: { type: "hysteria2", password: "pass123" }, tags: [], enabled: true, fingerprint: "hy1" },
      { name: "Tuic", protocol: "tuic", server: "tuic.example.com", port: 443, config: { type: "tuic", uuid: "550e8400-e29b-41d4-a716-446655440000", password: "p" }, tags: [], enabled: true, fingerprint: "tu1" },
      { name: "Trojan", protocol: "trojan", server: "tr.example.com", port: 443, config: { type: "trojan", password: "p" }, tags: [], enabled: true, fingerprint: "tr1" },
    ];
    const parsed = JSON.parse(renderSubscription(testNodes, "singbox").body);
    for (const outbound of parsed.outbounds as Array<Record<string, unknown>>) {
      if (["hysteria2", "tuic", "trojan"].includes(outbound.type as string)) {
        expect(outbound.tls).toMatchObject({ enabled: true });
      }
    }
    // Hysteria2 obfs uses the sing-box object form.
    const withObfs = JSON.parse(renderSubscription([{ ...testNodes[0], config: { ...testNodes[0].config, obfs: "salamander", "obfs-password": "obfspass" } }], "singbox").body);
    expect(withObfs.outbounds[0].obfs).toEqual({ type: "salamander", password: "obfspass" });
    expect(withObfs.outbounds[0].obfs_password).toBeUndefined();
  });

  it("renders a valid minimal sing-box config when there are no nodes", () => {
    const body = renderSubscription([], "singbox").body;
    const parsed = JSON.parse(body);
    expect(parsed.outbounds).toEqual([{ type: "direct", tag: "DIRECT" }]);
    expect(parsed.route.final).toBe("DIRECT");
    expect(parsed.route.default_domain_resolver).toEqual({ server: "local" });
    expect(parsed.dns.servers[0]).toMatchObject({ type: "udp", server: "223.5.5.5" });
  });
});
