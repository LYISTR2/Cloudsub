/**
 * Validate rendered subscription output against the REAL sing-box and
 * mihomo binaries (not mocked): the complete sing-box JSON must pass
 * `sing-box check`, and the complete Mihomo YAML must pass `mihomo -t`.
 *
 * Usage:
 *   SING_BOX_BIN=/path/to/sing-box MIHOMO_BIN=/path/to/mihomo npx tsx scripts/validate-rendered.ts
 *
 * If the env vars are unset, the script probes the usual download location
 * used by the repository's verification workflow (/tmp/cloudsub-tools).
 *
 * Version compatibility (see docs/upgrade-notes.md):
 *   - sing-box 1.14.x (removed constructs: dns outbound, legacy DNS server
 *     format, geoip rules; requires route.default_domain_resolver)
 *   - Mihomo 1.19.x (anytls idle-session fields are integer seconds)
 */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { readFileSync, writeFileSync } from "node:fs";
import { renderSubscription } from "../src/worker/adapters/output";
import type { NormalizedNode } from "../src/shared/types";

function resolveBinary(envName: string, probe: string): string | null {
  const explicit = process.env[envName];
  if (explicit && existsSync(explicit)) return explicit;
  return existsSync(probe) ? probe : null;
}

function main(): void {
  const singBox = resolveBinary("SING_BOX_BIN", "/tmp/cloudsub-tools/sing-box-1.14.0-linux-amd64/sing-box");
  const mihomo = resolveBinary("MIHOMO_BIN", "/tmp/cloudsub-tools/mihomo");
  if (!singBox || !mihomo) {
    console.error("SKIP: sing-box and/or mihomo binaries not found. Set SING_BOX_BIN and MIHOMO_BIN.");
    process.exit(0);
  }

  const fixture = JSON.parse(readFileSync(new URL("../tests/fixtures/nodes.json", import.meta.url).pathname, "utf8")) as NormalizedNode[];
  const singboxFile = "/tmp/cloudsub-rendered-singbox.json";
  const mihomoFile = "/tmp/cloudsub-rendered-mihomo.yaml";

  const singbox = renderSubscription(fixture, "singbox");
  const mihomoYaml = renderSubscription(fixture, "mihomo");
  const raw = renderSubscription(fixture, "raw");
  writeFileSync(singboxFile, singbox.body);
  writeFileSync(mihomoFile, mihomoYaml.body);
  writeFileSync("/tmp/cloudsub-rendered-raw.txt", raw.body);

  try {
    execFileSync(singBox, ["check", "-c", singboxFile], { stdio: "pipe" });
    console.log("sing-box check: PASS (sing-box " + execFileSync(singBox, ["version"]).toString().split("\n")[0] + ")");
  } catch (error) {
    const message = String((error as { stderr?: Buffer }).stderr ?? error).split("\n").filter(Boolean).slice(-2).join(" | ");
    console.error("sing-box check: FAIL — " + message);
    process.exitCode = 1;
  }

  try {
    execFileSync(mihomo, ["-t", "-f", mihomoFile], { stdio: "pipe" });
    console.log("mihomo -t: PASS (" + execFileSync(mihomo, ["-v"]).toString().split("\n")[0] + ")");
  } catch (error) {
    const message = String((error as { stderr?: Buffer }).stderr ?? error).split("\n").filter(Boolean).slice(-2).join(" | ");
    console.error("mihomo -t: FAIL — " + message);
    process.exitCode = 1;
  }
}

main();
