import { env } from "cloudflare:workers";
import { applyD1Migrations, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import type { Env } from "../../src/worker/env";
import worker from "../../src/worker/index";

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
  });
});
