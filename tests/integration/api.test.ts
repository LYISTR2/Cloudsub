import { env } from "cloudflare:workers";
import { applyD1Migrations, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import type { Env } from "../../src/worker/env";
import worker from "../../src/worker/index";
import { encodeBase64Text } from "../../src/worker/adapters/input/shared";

interface TestEnv extends Env {
  TEST_MIGRATIONS: Array<{ name: string; queries: string[] }>;
}

const testEnv = env as unknown as TestEnv;

async function workerRequest(path: string, init?: RequestInit): Promise<Response> {
  const context = createExecutionContext();
  const response = await worker.fetch(new Request("https://cloudsub.test" + path, init), testEnv, context);
  await waitOnExecutionContext(context);
  return response;
}

function cookies(response: Response): { cookie: string; csrf: string } {
  const header = response.headers.get("set-cookie") ?? "";
  const session = /cloudsub_session=([^;]+)/u.exec(header)?.[1];
  const csrf = /cloudsub_csrf=([^;]+)/u.exec(header)?.[1];
  if (!session || !csrf) throw new Error("Session cookies were not returned");
  return { cookie: "cloudsub_session=" + session + "; cloudsub_csrf=" + csrf, csrf };
}

describe("CloudSub API lifecycle", () => {
  beforeAll(async () => {
    await applyD1Migrations(testEnv.DB, testEnv.TEST_MIGRATIONS);
  });

  it("initializes, imports nodes, creates a token and serves a subscription", async () => {
    const before = await workerRequest("/api/system/status");
    expect(await before.json()).toMatchObject({ data: { initialized: false, migrationsReady: true } });

    const initialized = await workerRequest("/api/system/initialize", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: "admin", password: "correct horse battery staple" }),
    });
    expect(initialized.status).toBe(201);
    const auth = cookies(initialized);

    const source = await workerRequest("/api/sources", {
      method: "POST",
      headers: { "content-type": "application/json", cookie: auth.cookie, "x-csrf-token": auth.csrf },
      body: JSON.stringify({
        name: "Integration fixture",
        type: "manual",
        content: "proxies:\n  - name: Edge Test\n    type: ss\n    server: edge.example.com\n    port: 443\n    cipher: aes-128-gcm\n    password: fixture-secret",
        enabled: true,
        refreshInterval: 60,
        timeoutMs: 15000,
      }),
    });
    expect(source.status).toBe(201);
    const sourcePayload = await source.json() as { data: { id: string; refresh: { nodeCount: number }; refreshError?: string } };
    expect(sourcePayload.data.refreshError).toBeUndefined();
    expect(sourcePayload.data.refresh.nodeCount).toBe(1);

    const subscription = await workerRequest("/api/subscriptions", {
      method: "POST",
      headers: { "content-type": "application/json", cookie: auth.cookie, "x-csrf-token": auth.csrf },
      body: JSON.stringify({ name: "Integration", sourceIds: [sourcePayload.data.id], defaultTarget: "mihomo", enabled: true, cacheTtl: 300, rules: {} }),
    });
    expect(subscription.status).toBe(201);
    const subscriptionPayload = await subscription.json() as { data: { token: string } };

    const publicResponse = await workerRequest("/sub/" + subscriptionPayload.data.token + "?target=mihomo");
    expect(publicResponse.status).toBe(200);
    expect(publicResponse.headers.get("etag")).toMatch(/^"[a-f0-9]{64}"$/u);
    expect(new TextDecoder().decode(await publicResponse.arrayBuffer())).toContain("Edge Test");

    const invalid = await workerRequest("/sub/not-a-real-token");
    expect(invalid.status).toBe(404);
    expect(await invalid.json()).toMatchObject({ error: { code: "subscription_unavailable" } });

    const subscriptionPayloadWithId = subscriptionPayload as { data: { id: string; token: string } };
    const deleted = await workerRequest("/api/subscriptions/" + subscriptionPayloadWithId.data.id, {
      method: "DELETE",
      headers: { cookie: auth.cookie, "x-csrf-token": auth.csrf },
    });
    expect(deleted.status).toBe(200);
    expect(await deleted.json()).toMatchObject({ data: { ok: true } });

    const deletedToken = await workerRequest("/sub/" + subscriptionPayloadWithId.data.token);
    expect(deletedToken.status).toBe(404);
    expect(await deletedToken.json()).toMatchObject({ error: { code: "subscription_unavailable" } });
  });

  it("supports standalone sources with exactly one node and exposes source_kind", async () => {
    const login = await workerRequest("/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: "admin", password: "correct horse battery staple" }),
    });
    expect(login.status).toBe(200);
    const auth = cookies(login);
    const headers = { "content-type": "application/json", cookie: auth.cookie, "x-csrf-token": auth.csrf };

    // A standalone source accepts a single node URI (manual + standalone).
    const vmessUri = "vmess://" + encodeBase64Text(JSON.stringify({ v: "2", ps: "Standalone Edge", add: "edge.example.com", port: "8443", id: "550e8400-e29b-41d4-a716-446655440000", aid: "0", net: "ws", tls: "tls", path: "/ws" }));
    const created = await workerRequest("/api/sources", {
      method: "POST",
      headers,
      body: JSON.stringify({ name: "Standalone fixture", type: "manual", sourceKind: "standalone", content: vmessUri, enabled: true, refreshInterval: 60, timeoutMs: 15000 }),
    });
    expect(created.status).toBe(201);
    const createdPayload = await created.json() as { data: { id: string; sourceKind: string; refresh: { nodeCount: number }; refreshError?: string } };
    expect(createdPayload.data.sourceKind).toBe("standalone");
    expect(createdPayload.data.refreshError).toBeUndefined();
    expect(createdPayload.data.refresh.nodeCount).toBe(1);

    // The detail endpoint persists and returns source_kind.
    const detail = await workerRequest("/api/sources/" + createdPayload.data.id, { headers: { cookie: auth.cookie } });
    expect(detail.status).toBe(200);
    expect(await detail.json()).toMatchObject({ data: { source_kind: "standalone", type: "manual" } });

    // Nodes expose the source_kind of their owning source.
    const nodes = await workerRequest("/api/nodes?q=Standalone&pageSize=100", { headers: { cookie: auth.cookie } });
    expect(nodes.status).toBe(200);
    const nodesPayload = await nodes.json() as { data: { items: Array<{ name: string; source_kind: string }> } };
    expect(nodesPayload.data.items).toHaveLength(1);
    expect(nodesPayload.data.items[0]).toMatchObject({ name: "Standalone Edge", source_kind: "standalone" });

    // Subscription sources default to source_kind = subscription.
    const sources = await workerRequest("/api/sources?pageSize=100", { headers: { cookie: auth.cookie } });
    const sourcesPayload = await sources.json() as { data: { items: Array<{ name: string; source_kind: string }> } };
    const subscriptionSource = sourcesPayload.data.items.find((item) => item.name === "Integration fixture");
    expect(subscriptionSource?.source_kind).toBe("subscription");
  });

  it("rejects invalid standalone payloads with 422", async () => {
    const login = await workerRequest("/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: "admin", password: "correct horse battery staple" }),
    });
    const auth = cookies(login);
    const headers = { "content-type": "application/json", cookie: auth.cookie, "x-csrf-token": auth.csrf };
    const request = (body: Record<string, unknown>) => workerRequest("/api/sources", { method: "POST", headers, body: JSON.stringify(body) });

    // More than one node URI must be rejected.
    const multiple = await request({ name: "Too many nodes", type: "manual", sourceKind: "standalone", content: "vless://550e8400-e29b-41d4-a716-446655440000@a.example.com:443#A\nvless://550e8400-e29b-41d4-a716-446655440001@b.example.com:443#B", enabled: true });
    expect(multiple.status).toBe(422);
    expect(await multiple.json()).toMatchObject({ error: { code: "standalone_requires_single_node" } });

    // Standalone sources must be manual.
    const wrongType = await request({ name: "URL standalone", type: "url", sourceKind: "standalone", url: "https://example.com/sub", enabled: true });
    expect(wrongType.status).toBe(422);
    expect(await wrongType.json()).toMatchObject({ error: { code: "standalone_requires_manual" } });

    // Unparseable content must be rejected without creating a source.
    const garbage = await request({ name: "Garbage standalone", type: "manual", sourceKind: "standalone", content: "definitely not a node", enabled: true });
    expect(garbage.status).toBe(422);
    expect(await garbage.json()).toMatchObject({ error: { code: "invalid_standalone_uri" } });
  });
});
