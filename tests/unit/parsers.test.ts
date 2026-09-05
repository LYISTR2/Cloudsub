import { describe, expect, it } from "vitest";
import { parseStandaloneUri, parseSubscriptionContent } from "../../src/worker/adapters/input";
import { encodeBase64Text } from "../../src/worker/adapters/input/shared";

describe("subscription input adapters", () => {
  it("parses and deduplicates Mihomo YAML proxies", async () => {
    const input = [
      "proxies:",
      "  - name: Tokyo 01",
      "    type: ss",
      "    server: edge.example.com",
      "    port: 443",
      "    cipher: aes-128-gcm",
      "    password: secret",
      "  - name: Duplicate display name",
      "    type: ss",
      "    server: edge.example.com",
      "    port: 443",
      "    cipher: aes-128-gcm",
      "    password: secret",
    ].join("\n");
    const nodes = await parseSubscriptionContent(input);
    expect(nodes).toHaveLength(1);
    expect(nodes[0]).toMatchObject({ protocol: "ss", server: "edge.example.com", port: 443 });
  });

  it("decodes a Base64 URI subscription", async () => {
    const uri = "vless://550e8400-e29b-41d4-a716-446655440000@edge.example.com:443?security=tls&sni=edge.example.com#Tokyo";
    const nodes = await parseSubscriptionContent(encodeBase64Text(uri));
    expect(nodes).toHaveLength(1);
    expect(nodes[0]).toMatchObject({ name: "Tokyo", protocol: "vless", server: "edge.example.com", port: 443 });
    expect(nodes[0].config).toMatchObject({ tls: true, sni: "edge.example.com" });
  });

  it("parses VMess JSON URIs", async () => {
    const payload = { v: "2", ps: "Singapore", add: "sg.example.com", port: "8443", id: "550e8400-e29b-41d4-a716-446655440000", aid: "0", net: "ws", tls: "tls", path: "/ws" };
    const nodes = await parseSubscriptionContent("vmess://" + encodeBase64Text(JSON.stringify(payload)));
    expect(nodes[0]).toMatchObject({ name: "Singapore", protocol: "vmess", port: 8443 });
    expect(nodes[0].config).toMatchObject({ network: "ws", tls: true });
  });

  it("parses AnyTLS URIs with default TLS and full options", async () => {
    const uri = "anytls://secret-pass@edge.example.com:8443?sni=edge.example.com&alpn=h2,http/1.1&allowInsecure=1&client-fingerprint=chrome&idle-session-check-interval=30s&idle-session-timeout=60s&min-idle-session=2#Tokyo";
    const nodes = await parseSubscriptionContent(uri);
    expect(nodes).toHaveLength(1);
    expect(nodes[0]).toMatchObject({ name: "Tokyo", protocol: "anytls", server: "edge.example.com", port: 8443 });
    expect(nodes[0].config).toMatchObject({
      type: "anytls",
      password: "secret-pass",
      tls: true,
      sni: "edge.example.com",
      alpn: ["h2", "http/1.1"],
      "skip-cert-verify": true,
      "client-fingerprint": "chrome",
      "idle-session-check-interval": "30s",
      "idle-session-timeout": "60s",
      "min-idle-session": 2,
    });
  });

  it("accepts the insecure alias for AnyTLS URIs", async () => {
    const nodes = await parseSubscriptionContent("anytls://secret-pass@edge.example.com:443?insecure=1#Node");
    expect(nodes[0].config).toMatchObject({ "skip-cert-verify": true, tls: true });
  });

  it("rejects excessively deep structured input", async () => {
    let value: unknown = { name: "leaf" };
    for (let index = 0; index < 40; index += 1) value = { child: value };
    await expect(parseSubscriptionContent(JSON.stringify(value))).rejects.toMatchObject({ code: "unsupported_source_format" });
  });
});

describe("standalone single-node parsing", () => {
  const vmessUri = "vmess://" + encodeBase64Text(JSON.stringify({ v: "2", ps: "Standalone", add: "edge.example.com", port: "8443", id: "550e8400-e29b-41d4-a716-446655440000", aid: "0", net: "ws", tls: "tls", path: "/ws" }));

  it("accepts exactly one supported URI", async () => {
    const node = await parseStandaloneUri(vmessUri);
    expect(node).toMatchObject({ name: "Standalone", protocol: "vmess" });
    expect(await parseStandaloneUri("vless://550e8400-e29b-41d4-a716-446655440000@edge.example.com:443#Tokyo")).toMatchObject({ protocol: "vless" });
    expect(await parseStandaloneUri("ss://YWVzLTEyOC1nY206c2VjcmV0@edge.example.com:8388#SS")).toMatchObject({ protocol: "ss" });
    expect(await parseStandaloneUri("trojan://token@edge.example.com:443?sni=edge.example.com#Tr")).toMatchObject({ protocol: "trojan" });
    expect(await parseStandaloneUri("hysteria2://pass@edge.example.com:443#Hy")).toMatchObject({ protocol: "hysteria2" });
    expect(await parseStandaloneUri("tuic://uuid:pass@edge.example.com:443#Tu")).toMatchObject({ protocol: "tuic" });
    expect(await parseStandaloneUri("anytls://pass@edge.example.com:443#Any")).toMatchObject({ protocol: "anytls" });
  });

  it("accepts a base64-wrapped single URI", async () => {
    const node = await parseStandaloneUri(encodeBase64Text(vmessUri));
    expect(node).toMatchObject({ protocol: "vmess", name: "Standalone" });
  });

  it("rejects multiple URIs, duplicates and valid+garbage mixes", async () => {
    const single = "vless://550e8400-e29b-41d4-a716-446655440000@a.example.com:443#A";
    await expect(parseStandaloneUri(single + "\n" + single)).rejects.toMatchObject({ code: "standalone_requires_single_node" });
    await expect(parseStandaloneUri(single + "\ndefinitely not a node")).rejects.toMatchObject({ code: "standalone_requires_single_node" });
    await expect(parseStandaloneUri(single + "\nvless://550e8400-e29b-41d4-a716-446655440001@b.example.com:443#B")).rejects.toMatchObject({ code: "standalone_requires_single_node" });
  });

  it("rejects YAML/JSON masquerading as a URI", async () => {
    const yaml = ["proxies:", "  - name: Sneaky", "    type: ss", "    server: edge.example.com", "    port: 443", "    cipher: aes-128-gcm", "    password: secret"].join("\n");
    // Multi-line YAML is rejected because a standalone source must be a
    // single line (code depends on the line count; either rejection is fine).
    await expect(parseStandaloneUri(yaml)).rejects.toMatchObject({ code: expect.stringMatching(/^(invalid_standalone_uri|standalone_requires_single_node)$/u) });
    // Single-line YAML masquerading as a URI is rejected as invalid.
    await expect(parseStandaloneUri("proxies: [{name: Sneaky, type: ss, server: e.example.com, port: 443}]")).rejects.toMatchObject({ code: "invalid_standalone_uri" });
    // Base64 of a YAML document must also be rejected.
    await expect(parseStandaloneUri(encodeBase64Text(yaml))).rejects.toMatchObject({ code: expect.stringMatching(/^(invalid_standalone_uri|standalone_requires_single_node)$/u) });
  });

  it("rejects empty, garbage and unsupported schemes", async () => {
    await expect(parseStandaloneUri("")).rejects.toMatchObject({ code: "empty_source" });
    await expect(parseStandaloneUri("definitely not a node")).rejects.toMatchObject({ code: "invalid_standalone_uri" });
    await expect(parseStandaloneUri("http://example.com/sub")).rejects.toMatchObject({ code: "invalid_standalone_uri" });
    await expect(parseStandaloneUri("socks5://user@edge.example.com:1080#S")).rejects.toMatchObject({ code: "invalid_standalone_uri" });
  });
});
