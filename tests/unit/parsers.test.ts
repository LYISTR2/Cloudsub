import { describe, expect, it } from "vitest";
import { parseSubscriptionContent } from "../../src/worker/adapters/input";
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

  it("rejects excessively deep structured input", async () => {
    let value: unknown = { name: "leaf" };
    for (let index = 0; index < 40; index += 1) value = { child: value };
    await expect(parseSubscriptionContent(JSON.stringify(value))).rejects.toMatchObject({ code: "unsupported_source_format" });
  });
});
