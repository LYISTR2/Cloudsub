import { env } from "cloudflare:workers";
import { applyD1Migrations, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import type { Env } from "../../src/worker/env";
import worker from "../../src/worker/index";
import { refreshSource } from "../../src/worker/services/sources";

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

function authHeaders(auth: { cookie: string; csrf: string }): Record<string, string> {
  return { "content-type": "application/json", cookie: auth.cookie, "x-csrf-token": auth.csrf };
}

interface ApiErrorBody { error: { code?: string; message?: string } }

async function json<T>(response: Response): Promise<T> {
  return (await response.json()) as T;
}

const YAML = (names: string[]) => "proxies:\n" + names.map((name) =>
  "  - name: " + name + "\n    type: ss\n    server: " + name.toLowerCase().replace(/\s+/gu, "") + ".example.com\n    port: 443\n    cipher: aes-128-gcm\n    password: secret",
).join("\n");

describe("refresh safety, lease and invalidation", () => {
  let auth: { cookie: string; csrf: string };

  beforeAll(async () => {
    await applyD1Migrations(testEnv.DB, testEnv.TEST_MIGRATIONS);
    const initialized = await workerRequest("/api/system/initialize", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: "admin", password: "correct horse battery staple" }),
    });
    expect(initialized.status).toBe(201);
    auth = cookies(initialized);
  });

  async function createSource(body: Record<string, unknown>): Promise<{ id: string; refresh: { nodeCount: number; changed: boolean }; refreshError?: string }> {
    const response = await workerRequest("/api/sources", { method: "POST", headers: authHeaders(auth), body: JSON.stringify({ enabled: true, refreshInterval: 60, timeoutMs: 15000, ...body }) });
    expect(response.status, JSON.stringify(body)).toBe(201);
    const payload = (await response.json()) as { data: { id: string; refresh: { nodeCount: number; changed: boolean }; refreshError?: string } };
    return payload.data;
  }

  async function createSubscription(sourceId: string, name = "Test sub"): Promise<{ id: string; token: string }> {
    const response = await workerRequest("/api/subscriptions", {
      method: "POST",
      headers: authHeaders(auth),
      body: JSON.stringify({ name, sourceIds: [sourceId], defaultTarget: "mihomo", enabled: true, cacheTtl: 300, rules: {} }),
    });
    expect(response.status).toBe(201);
    const payload = (await response.json()) as { data: { id: string; token: string } };
    return payload.data;
  }

  async function fetchSub(token: string): Promise<string> {
    const response = await workerRequest("/sub/" + token + "?target=raw");
    expect(response.status).toBe(200);
    const encoded = new TextDecoder().decode(await response.arrayBuffer());
    // raw subscriptions are base64-encoded URI lists
    return atob(encoded);
  }

  it("skips node writes and revision bumps when content is unchanged (no-op refresh)", async () => {
    const source = await createSource({ name: "Noop", type: "manual", content: YAML(["Noop"]) });
    const subscription = await createSubscription(source.id, "Noop sub");
    const first = await fetchSub(subscription.token);
    expect(first).toContain("noop.example.com");

    const [revisionBefore, nodeRowsBefore] = await Promise.all([
      testEnv.DB.prepare("SELECT revision FROM subscriptions WHERE id = ?").bind(subscription.id).first<{ revision: number }>(),
      testEnv.DB.prepare("SELECT id, present FROM nodes WHERE source_id = ?").bind(source.id).all(),
    ]);

    const refresh = await workerRequest("/api/sources/" + source.id + "/refresh", { method: "POST", headers: authHeaders(auth) });
    expect(refresh.status).toBe(200);
    expect(await json<{ data: { changed: boolean } }>(refresh)).toMatchObject({ data: { changed: false } });

    const [revisionAfter, nodeRowsAfter, subResponse] = await Promise.all([
      testEnv.DB.prepare("SELECT revision FROM subscriptions WHERE id = ?").bind(subscription.id).first<{ revision: number }>(),
      testEnv.DB.prepare("SELECT id, present FROM nodes WHERE source_id = ?").bind(source.id).all(),
      fetchSub(subscription.token),
    ]);
    // Revision and node rows are untouched — the cached output stays valid.
    expect(revisionAfter?.revision).toBe(revisionBefore?.revision);
    expect(nodeRowsAfter.results.map((row) => row.id).sort()).toEqual(nodeRowsBefore.results.map((row) => row.id).sort());
    expect(nodeRowsAfter.results.every((row) => row.present === 1)).toBe(true);
    expect(subResponse).toContain("noop.example.com");
  });

  it("preserves the complete last-good node set when a refresh fails", async () => {
    const source = await createSource({ name: "LastGood", type: "manual", content: YAML(["LastGood"]) });
    const subscription = await createSubscription(source.id, "LastGood sub");
    const first = await fetchSub(subscription.token);
    expect(first).toContain("lastgood.example.com");

    // Corrupt the encrypted payload directly — the next refresh fails at
    // decryption, before anything is staged or promoted.
    await testEnv.DB.prepare("UPDATE sources SET payload_encrypted = 'corrupted' WHERE id = ?").bind(source.id).run();
    const refresh = await workerRequest("/api/sources/" + source.id + "/refresh", { method: "POST", headers: authHeaders(auth) });
    expect(refresh.status).toBe(500);

    // Last-good nodes still present and still served.
    const [nodes, served, sourceRow] = await Promise.all([
      testEnv.DB.prepare("SELECT id, name, present FROM nodes WHERE source_id = ?").bind(source.id).all(),
      fetchSub(subscription.token),
      testEnv.DB.prepare("SELECT last_error, last_success_at FROM sources WHERE id = ?").bind(source.id).first<{ last_error: string | null; last_success_at: string | null }>(),
    ]);
    expect(nodes.results.length).toBe(1);
    expect(nodes.results[0]).toMatchObject({ name: "LastGood", present: 1 });
    expect(served).toContain("lastgood.example.com");
    expect(sourceRow?.last_error).not.toBeNull();
    expect(sourceRow?.last_success_at).not.toBeNull();
  });

  it("atomically promotes a changed node set and bumps revisions", async () => {
    const source = await createSource({ name: "Promote", type: "manual", content: YAML(["Promote A"]) });
    const subscription = await createSubscription(source.id, "Promote sub");
    const before = await fetchSub(subscription.token);
    expect(before).toContain("promotea.example.com");
    const revisionBefore = (await testEnv.DB.prepare("SELECT revision FROM subscriptions WHERE id = ?").bind(subscription.id).first<{ revision: number }>())?.revision;

    const update = await workerRequest("/api/sources/" + source.id, {
      method: "PUT",
      headers: authHeaders(auth),
      body: JSON.stringify({ content: YAML(["Promote A", "Promote B"]) }),
    });
    expect(update.status).toBe(200);
    const refresh = await workerRequest("/api/sources/" + source.id + "/refresh", { method: "POST", headers: authHeaders(auth) });
    expect(refresh.status).toBe(200);
    expect(await json<{ data: { changed: boolean; nodeCount: number } }>(refresh)).toMatchObject({ data: { changed: true, nodeCount: 2 } });

    const [nodes, served, revisionAfter] = await Promise.all([
      testEnv.DB.prepare("SELECT name, present FROM nodes WHERE source_id = ? ORDER BY name").bind(source.id).all(),
      fetchSub(subscription.token),
      testEnv.DB.prepare("SELECT revision FROM subscriptions WHERE id = ?").bind(subscription.id).first<{ revision: number }>(),
    ]);
    expect(nodes.results).toEqual([{ name: "Promote A", present: 1 }, { name: "Promote B", present: 1 }]);
    expect(served).toContain("promotea.example.com");
    expect(served).toContain("promoteb.example.com");
    expect(revisionAfter?.revision).toBe((revisionBefore ?? 0) + 2); // content edit + refresh promotion
  });

  it("preserves node enable/name edits across refreshes", async () => {
    const source = await createSource({ name: "EditKeep", type: "manual", content: YAML(["EditKeep A", "EditKeep B"]) });
    const nodes = await testEnv.DB.prepare("SELECT id, name FROM nodes WHERE source_id = ? ORDER BY name").bind(source.id).all<{ id: string; name: string }>();
    const nodeA = nodes.results.find((row) => row.name === "EditKeep A");
    expect(nodeA).toBeDefined();
    const disable = await workerRequest("/api/nodes/" + nodeA!.id, { method: "PUT", headers: authHeaders(auth), body: JSON.stringify({ enabled: false, name: "EditKeep A (kept)" }) });
    expect(disable.status).toBe(200);

    // Refresh with identical content (no-op) — must NOT reset the edits.
    await workerRequest("/api/sources/" + source.id + "/refresh", { method: "POST", headers: authHeaders(auth) });
    let after = await testEnv.DB.prepare("SELECT name, enabled FROM nodes WHERE id = ?").bind(nodeA!.id).first<{ name: string; enabled: number }>();
    expect(after).toMatchObject({ name: "EditKeep A (kept)", enabled: 0 });

    // Refresh with changed content — promotion preserves edits on matching
    // fingerprints too.
    const update = await workerRequest("/api/sources/" + source.id, { method: "PUT", headers: authHeaders(auth), body: JSON.stringify({ content: YAML(["EditKeep A", "EditKeep B", "EditKeep C"]) }) });
    expect(update.status).toBe(200);
    await workerRequest("/api/sources/" + source.id + "/refresh", { method: "POST", headers: authHeaders(auth) });
    after = await testEnv.DB.prepare("SELECT name, enabled FROM nodes WHERE id = ?").bind(nodeA!.id).first<{ name: string; enabled: number }>();
    expect(after).toMatchObject({ name: "EditKeep A (kept)", enabled: 0 });
    // And the new node arrived.
    const all = await testEnv.DB.prepare("SELECT name FROM nodes WHERE source_id = ? AND present = 1").bind(source.id).all<{ name: string }>();
    expect(all.results.some((row) => row.name === "EditKeep C")).toBe(true);
  });

  it("serializes concurrent refreshes with an atomic lease and rejects a held lease", async () => {
    const source = await createSource({ name: "Lease", type: "manual", content: YAML(["Lease"]) });
    // Simulate an in-flight refresh by holding the lease with a far-future expiry.
    await testEnv.DB.prepare("UPDATE sources SET refresh_lease = ?, last_attempt_at = ? WHERE id = ?").bind("held-lease:9999-12-31T00:00:00.000Z", "2000-01-01T00:00:00.000Z", source.id).run();
    // A held lease still blocks a direct scheduler-style refresh.
    await expect(refreshSource(testEnv, source.id)).rejects.toMatchObject({ code: "refresh_in_progress" });

    // An expired lease is re-acquirable for the scheduler.
    await testEnv.DB.prepare("UPDATE sources SET refresh_lease = ? WHERE id = ?").bind("stale-lease:2000-01-01T00:00:00.000Z", source.id).run();
    await expect(refreshSource(testEnv, source.id)).resolves.toMatchObject({ changed: false });
    // The refresh recorded the attempt and released its own lease afterwards.
    const sourceAfterRefresh = await testEnv.DB.prepare("SELECT refresh_lease, last_attempt_at FROM sources WHERE id = ?").bind(source.id).first<{ refresh_lease: string | null; last_attempt_at: string | null }>();
    expect(sourceAfterRefresh?.refresh_lease).toBeNull();
    expect(sourceAfterRefresh?.last_attempt_at).not.toBeNull();

    // A second non-forced scheduler refresh within 30 seconds is rate limited.
    await expect(refreshSource(testEnv, source.id)).rejects.toMatchObject({ code: "refresh_cooldown" });
  });

  it("stops serving a deleted source's nodes even from a warmed KV cache", async () => {
    const source = await createSource({ name: "CacheKill", type: "manual", content: YAML(["CacheKill"]) });
    const subscription = await createSubscription(source.id, "CacheKill sub");
    // Warm the KV cache at the current revision.
    const warmed = await fetchSub(subscription.token);
    expect(warmed).toContain("cachekill.example.com");

    const deleted = await workerRequest("/api/sources/" + source.id, { method: "DELETE", headers: authHeaders(auth) });
    expect(deleted.status).toBe(200);

    const after = await fetchSub(subscription.token);
    // The deleted source's node must not appear anywhere in the output.
    expect(after).not.toContain("cachekill.example.com");
    // Revision was bumped so the warmed KV entry is unreachable.
    const revision = (await testEnv.DB.prepare("SELECT revision FROM subscriptions WHERE id = ?").bind(subscription.id).first<{ revision: number }>())?.revision;
    expect(revision ?? 0).toBeGreaterThan(1);
    // Nodes and staging rows are gone.
    const orphanNodes = await testEnv.DB.prepare("SELECT COUNT(*) AS count FROM nodes WHERE source_id = ?").bind(source.id).first<{ count: number }>();
    const orphanStaging = await testEnv.DB.prepare("SELECT COUNT(*) AS count FROM nodes_staging WHERE source_id = ?").bind(source.id).first<{ count: number }>();
    expect(orphanNodes?.count).toBe(0);
    expect(orphanStaging?.count).toBe(0);
  });

  it("stops distributing a disabled source immediately (prefer-disable semantics)", async () => {
    const source = await createSource({ name: "DisableMe", type: "manual", content: YAML(["DisableMe"]) });
    const subscription = await createSubscription(source.id, "DisableMe sub");
    const warmed = await fetchSub(subscription.token);
    expect(warmed).toContain("disableme.example.com");

    const disable = await workerRequest("/api/sources/" + source.id, { method: "PUT", headers: authHeaders(auth), body: JSON.stringify({ enabled: false }) });
    expect(disable.status).toBe(200);

    const after = await fetchSub(subscription.token);
    expect(after).not.toContain("disableme.example.com");

    // Re-enabling restores distribution from the same node set.
    const enable = await workerRequest("/api/sources/" + source.id, { method: "PUT", headers: authHeaders(auth), body: JSON.stringify({ enabled: true }) });
    expect(enable.status).toBe(200);
    const restored = await fetchSub(subscription.token);
    expect(restored).toContain("disableme.example.com");
  });

  it("enforces prefer-disable on the preview path too", async () => {
    const source = await createSource({ name: "PreviewDisable", type: "manual", content: YAML(["PreviewDisable"]) });
    const subscription = await createSubscription(source.id, "PreviewDisable sub");
    const preview = async () => {
      const response = await workerRequest("/api/subscriptions/" + subscription.id + "/preview", { method: "POST", headers: authHeaders(auth), body: JSON.stringify({ target: "raw" }) });
      expect(response.status).toBe(200);
      const payload = await json<{ data: { body: string } }>(response);
      return atob(payload.data.body);
    };
    expect(await preview()).toContain("previewdisable.example.com");
    await workerRequest("/api/sources/" + source.id, { method: "PUT", headers: authHeaders(auth), body: JSON.stringify({ enabled: false }) });
    expect(await preview()).not.toContain("previewdisable.example.com");
  });

  it("validates standalone sources strictly on create (duplicates, valid+garbage, YAML)", async () => {
    const single = "vless://550e8400-e29b-41d4-a716-446655440000@a.example.com:443#A";
    const request = (content: string) => workerRequest("/api/sources", {
      method: "POST",
      headers: authHeaders(auth),
      body: JSON.stringify({ name: "Strict", type: "manual", sourceKind: "standalone", content, enabled: true }),
    });
    expect((await request(single + "\n" + single)).status).toBe(422);
    expect((await request(single + "\ngarbage")).status).toBe(422);
    expect((await request("proxies:\n  - name: Sneaky\n    type: ss\n    server: e.example.com\n    port: 443\n    cipher: aes-128-gcm\n    password: x")).status).toBe(422);
    // A valid single URI still passes.
    expect((await request(single)).status).toBe(201);
  });

  it("rejects invalid regex rules at the API with a safe-engine reason", async () => {
    const source = await createSource({ name: "RegexSrc", type: "manual", content: YAML(["RegexSrc"]) });
    const bad = await workerRequest("/api/subscriptions", {
      method: "POST",
      headers: authHeaders(auth),
      body: JSON.stringify({ name: "Bad regex", sourceIds: [source.id], enabled: true, rules: { includeName: "(?=lookahead)" } }),
    });
    expect(bad.status).toBe(422);
    const body = await json<ApiErrorBody>(bad);
    expect(body.error.code).toBe("validation_failed");
    // The reason is the engine's own message, not a generic error.
    expect(JSON.stringify(body.error)).toContain("环视");

    // Valid patterns (including ReDoS classics — they are linear-time) pass.
    const good = await workerRequest("/api/subscriptions", {
      method: "POST",
      headers: authHeaders(auth),
      body: JSON.stringify({ name: "Good regex", sourceIds: [source.id], enabled: true, rules: { includeName: "(a+)+$", rename: [{ pattern: "RegexSrc", replacement: "Renamed" }] } }),
    });
    expect(good.status).toBe(201);
  });

  it("supports subscription edits: rename rules, filters, enable toggle and source changes", async () => {
    const sourceA = await createSource({ name: "EditA", type: "manual", content: YAML(["EditA"]) });
    const sourceB = await createSource({ name: "EditB", type: "manual", content: YAML(["EditB"]) });
    const subscription = await createSubscription(sourceA.id, "Editable");

    const update = await workerRequest("/api/subscriptions/" + subscription.id, {
      method: "PUT",
      headers: authHeaders(auth),
      body: JSON.stringify({
        name: "Editable v2",
        enabled: true,
        sourceIds: [sourceA.id, sourceB.id],
        defaultTarget: "singbox",
        expiresAt: null,
        rules: { protocols: ["ss"], excludeName: "EditB", sortBy: "name", rename: [{ pattern: "EditA", replacement: "Alpha" }] },
      }),
    });
    expect(update.status).toBe(200);

    const preview = await workerRequest("/api/subscriptions/" + subscription.id + "/preview", { method: "POST", headers: authHeaders(auth), body: JSON.stringify({ target: "singbox" }) });
    const previewBody = (await json<{ data: { body: string; nodeCount: number } }>(preview)).data;
    expect(previewBody.nodeCount).toBe(1);
    expect(previewBody.body).toContain("Alpha");
    expect(previewBody.body).not.toContain("EditB");

    // Disabling the subscription makes the token unavailable.
    await workerRequest("/api/subscriptions/" + subscription.id, { method: "PUT", headers: authHeaders(auth), body: JSON.stringify({ enabled: false }) });
    const unavailable = await workerRequest("/sub/" + subscription.token);
    expect(unavailable.status).toBe(404);
    await workerRequest("/api/subscriptions/" + subscription.id, { method: "PUT", headers: authHeaders(auth), body: JSON.stringify({ enabled: true }) });
    expect((await workerRequest("/sub/" + subscription.token)).status).toBe(200);
  });
});

describe("list APIs: sourceKind filters, count JOINs and pagination totals", () => {
  let auth: { cookie: string; csrf: string };

  beforeAll(async () => {
    const login = await workerRequest("/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: "admin", password: "correct horse battery staple" }),
    });
    auth = cookies(login);
  });

  it("filters nodes by sourceKind with consistent totals", async () => {
    const [subResponse, stdResponse] = await Promise.all([
      workerRequest("/api/nodes?sourceKind=subscription&pageSize=100", { headers: { cookie: auth.cookie } }),
      workerRequest("/api/nodes?sourceKind=standalone&pageSize=100", { headers: { cookie: auth.cookie } }),
    ]);
    const sub = await json<{ data: { items: Array<{ source_kind: string }>; total: number } }>(subResponse);
    const std = await json<{ data: { items: Array<{ source_kind: string }>; total: number } }>(stdResponse);
    expect(sub.data.total).toBe(sub.data.items.length);
    expect(sub.data.items.every((item) => item.source_kind === "subscription")).toBe(true);
    expect(std.data.items.every((item) => item.source_kind === "standalone")).toBe(true);
    // The two groups together match the unfiltered total.
    const all = await json<{ data: { total: number } }>(await workerRequest("/api/nodes?pageSize=100", { headers: { cookie: auth.cookie } }));
    expect(sub.data.total + std.data.total).toBe(all.data.total);
  });

  it("rejects an invalid sourceKind value", async () => {
    const response = await workerRequest("/api/nodes?sourceKind=bogus", { headers: { cookie: auth.cookie } });
    expect(response.status).toBe(422);
    expect(await json<ApiErrorBody>(response)).toMatchObject({ error: { code: "invalid_source_kind" } });
  });

  it("paginates sources with accurate totals", async () => {
    const pageOne = await json<{ data: { items: Array<{ id: string }>; total: number; page: number } }>(await workerRequest("/api/sources?page=1&pageSize=2", { headers: { cookie: auth.cookie } }));
    expect(pageOne.data.items.length).toBe(2);
    const pageTwo = await json<{ data: { items: Array<{ id: string }>; total: number; page: number } }>(await workerRequest("/api/sources?page=2&pageSize=2", { headers: { cookie: auth.cookie } }));
    expect(pageOne.data.total).toBeGreaterThan(2);
    expect(pageOne.data.total).toBe(pageTwo.data.total);
    expect(pageOne.data.items[0].id).not.toBe(pageTwo.data.items[0].id);
  });

  it("paginates subscriptions with accurate totals", async () => {
    const response = await json<{ data: { items: unknown[]; total: number } }>(await workerRequest("/api/subscriptions?page=1&pageSize=2", { headers: { cookie: auth.cookie } }));
    expect(response.data.items.length).toBeGreaterThan(0);
    expect(response.data.total).toBeGreaterThanOrEqual(response.data.items.length);
  });

  it("paginates audit logs with accurate totals", async () => {
    const response = await json<{ data: { items: unknown[]; total: number } }>(await workerRequest("/api/audit-logs?page=1&pageSize=5", { headers: { cookie: auth.cookie } }));
    expect(response.data.total).toBeGreaterThan(0);
    expect(response.data.items.length).toBeLessThanOrEqual(5);
  });

  it("exposes every source through the options endpoint (no first-100 limit)", async () => {
    const response = await json<{ data: { items: unknown[] } }>(await workerRequest("/api/sources/options", { headers: { cookie: auth.cookie } }));
    const sources = await json<{ data: { total: number } }>(await workerRequest("/api/sources?pageSize=100", { headers: { cookie: auth.cookie } }));
    expect(response.data.items.length).toBe(sources.data.total);
  });

  it("paginates source fetch logs with totals", async () => {
    const sources = await json<{ data: { items: Array<{ id: string }> } }>(await workerRequest("/api/sources?pageSize=100", { headers: { cookie: auth.cookie } }));
    const sourceId = sources.data.items[0].id;
    const response = await json<{ data: { items: unknown[]; total: number } }>(await workerRequest("/api/sources/" + sourceId + "/logs?page=1&pageSize=2", { headers: { cookie: auth.cookie } }));
    expect(response.data.total).toBeGreaterThan(0);
  });
});
