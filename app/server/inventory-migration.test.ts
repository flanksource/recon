import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { migrateLegacyInventory } from "./inventory-migration.ts";
import { createInventoryStore } from "./inventory-store.ts";

const TEST_ROOT = resolve(import.meta.dirname, "..", ".tmp", "inventory-migration-test");

describe("legacy inventory migration", () => {
  beforeEach(() => {
    rmSync(TEST_ROOT, { recursive: true, force: true });
    mkdirSync(TEST_ROOT, { recursive: true });
  });
  afterEach(() => rmSync(TEST_ROOT, { recursive: true, force: true }));

  it("preserves curated fields and projects state plus discovery into canonical JSON", () => {
    const targetsPath = resolve(TEST_ROOT, "targets.yaml");
    const statePath = resolve(TEST_ROOT, "state.json");
    const observationPath = resolve(TEST_ROOT, "discovered.json");
    const inventoryDir = resolve(TEST_ROOT, "inventory");
    writeFileSync(
      targetsPath,
      [
        "zones:",
        "  - example.com",
        "targets:",
        "  prod:",
        "    - host: api.example.com",
        "      app: api",
        "      profiles: [safe, full]",
        "      tags: [api]",
        "",
      ].join("\n"),
      "utf8",
    );
    writeFileSync(
      statePath,
      `${JSON.stringify({
        "api.example.com": {
          first_observed: "2026-08-01T00:00:00Z",
          last_seen: "2026-08-02T00:00:00Z",
          last_status: 200,
          last_title: "API",
          last_tech: ["Go"],
          last_scan: "2026-08-03T00:00:00Z",
          last_findings: 2,
        },
      })}\n`,
      "utf8",
    );
    writeFileSync(
      observationPath,
      `${JSON.stringify({
        timestamp: "2026-08-02T00:00:00Z",
        input: "api.example.com",
        url: "https://api.example.com",
        status_code: 200,
        title: "API",
        host_ip: "192.0.2.1",
        a: ["192.0.2.1"],
      })}\n`,
      "utf8",
    );

    expect(
      migrateLegacyInventory({ targetsPath, statePath, observationPath, inventoryDir }),
    ).toEqual({ targets: 1, zones: 1, stateEntries: 1, missingState: [] });
    expect(createInventoryStore({ inventoryDir }).get("api.example.com")).toEqual(
      expect.objectContaining({
        app: "api",
        observed: {
          first_observed: "2026-08-01T00:00:00Z",
          last_seen: "2026-08-02T00:00:00.000Z",
          last_attempt: "2026-08-02T00:00:00.000Z",
        },
        network: { ip: "192.0.2.1", ipv4: ["192.0.2.1"] },
        scan: { last_scan: "2026-08-03T00:00:00Z", last_findings: 2 },
      }),
    );
    expect(readFileSync(resolve(inventoryDir, "inventory.json"), "utf8")).toMatch(/\n$/);
  });
});
