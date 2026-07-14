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

  it("renders Mihomo and JSON output through adapters", () => {
    const enabled = applySubscriptionRules(nodes, {});
    expect(renderSubscription(enabled, "mihomo").body).toContain("proxies:");
    expect(JSON.parse(renderSubscription(enabled, "json").body).nodes).toHaveLength(1);
  });

  it("renders standard Base64 raw subscriptions", () => {
    const body = renderSubscription(applySubscriptionRules(nodes, {}), "raw").body;
    expect(decodeBase64Text(body)).toContain("vless://");
  });
});
