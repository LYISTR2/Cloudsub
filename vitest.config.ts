import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [cloudflareTest(async () => ({
    wrangler: { configPath: "./wrangler.jsonc" },
    miniflare: {
      bindings: {
        APP_SECRET: "integration-app-secret",
        DATA_ENCRYPTION_KEY: "integration-data-secret",
        TEST_MIGRATIONS: await readD1Migrations(new URL("./migrations", import.meta.url).pathname),
      },
    },
  }))],
  test: {
    include: ["tests/**/*.test.ts"],
  },
});
