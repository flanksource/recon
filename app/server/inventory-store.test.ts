import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createInventoryStore } from "./inventory-store.ts";

const TEST_ROOT = resolve(import.meta.dirname, "..", ".tmp", "inventory-store-test");
const INVENTORY_DIR = resolve(TEST_ROOT, "inventory");

function writeJson(path: string, value: unknown): void {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function writeInventory(target: Record<string, unknown>): void {
  mkdirSync(resolve(INVENTORY_DIR, "targets"), { recursive: true });
  writeJson(resolve(INVENTORY_DIR, "inventory.json"), {
    $schema: "./inventory.schema.json",
    version: 3,
    zones: ["example.com"],
  });
  const id = String(target.id ?? target.host);
  const profiles = (target.profiles as string[]).map((profile) =>
    profile.startsWith("scan:") ? profile : `scan:nuclei:${profile}`,
  );
  writeJson(resolve(INVENTORY_DIR, "targets", `${id}.json`), {
    ...target,
    version: 3,
    id,
    profiles,
  });
}

describe("inventory store", () => {
  beforeEach(() => rmSync(TEST_ROOT, { recursive: true, force: true }));
  afterEach(() => rmSync(TEST_ROOT, { recursive: true, force: true }));

  it("keys targets by stable id while network operations use only host addresses", () => {
    mkdirSync(resolve(INVENTORY_DIR, "targets"), { recursive: true });
    writeJson(resolve(INVENTORY_DIR, "inventory.json"), {
      $schema: "./inventory.schema.json",
      version: 3,
      zones: ["example.com"],
    });
    writeJson(resolve(INVENTORY_DIR, "targets", "web-production.json"), {
      $schema: "../target.schema.json",
      version: 3,
      id: "web-production",
      host: "api.example.com",
      class: "prod",
      profiles: ["scan:nuclei:safe"],
      tags: ["api"],
    });
    writeJson(resolve(INVENTORY_DIR, "targets", "gcp-production.json"), {
      $schema: "../target.schema.json",
      version: 3,
      id: "gcp-production",
      kind: "provider-context",
      provider: "gcp",
      credentialMode: "ambient",
      arguments: { "project-ids": ["example-prod"] },
      class: "prod",
      profiles: ["scan:prowler:gcp-cis-5-0"],
      tags: ["cloud"],
    });
    const store = createInventoryStore({
      inventoryDir: INVENTORY_DIR,
      now: () => new Date("2026-08-09T09:00:00.000Z"),
    });
    const outputDir = resolve(TEST_ROOT, ".gen");
    const resultPath = resolve(TEST_ROOT, "result.jsonl");
    writeFileSync(
      resultPath,
      `${JSON.stringify({ host: "https://api.example.com", "template-id": "headers" })}\n`,
      "utf8",
    );

    expect(store.list().rows.map((target) => target.id)).toEqual([
      "gcp-production",
      "web-production",
    ]);
    expect(store.get("web-production").host).toBe("api.example.com");

    store.render({ outputDir });
    store.recordScan({ hosts: ["api.example.com"], resultPath });

    expect(readFileSync(resolve(outputDir, "all.txt"), "utf8")).toBe(
      "api.example.com\n",
    );
    expect(store.get("web-production").scan).toEqual({
      last_scan: "2026-08-09T09:00:00.000Z",
      last_findings: 1,
    });
  });

  it("validates and lists canonical target documents", () => {
    writeInventory({
      $schema: "../target.schema.json",
      version: 1,
      host: "api.example.com",
      class: "prod",
      profiles: ["safe"],
      tags: ["api"],
    });

    const inventory = createInventoryStore({ inventoryDir: INVENTORY_DIR }).list();

    expect(inventory).toEqual({
      version: 3,
      zones: ["example.com"],
      tagVocabulary: ["api"],
      rows: [expect.objectContaining({ host: "api.example.com", class: "prod" })],
    });
  });

  it("rejects unknown fields with the target filename", () => {
    writeInventory({
      $schema: "../target.schema.json",
      version: 1,
      host: "api.example.com",
      class: "prod",
      profiles: ["safe"],
      tags: [],
      typo: true,
    });

    expect(() => createInventoryStore({ inventoryDir: INVENTORY_DIR }).list()).toThrow(
      /api\.example\.com\.json.*additional properties/i,
    );
  });

  it("requires deactivation reasons and preserves network address families", () => {
    writeInventory({
      $schema: "../target.schema.json",
      version: 1,
      host: "api.example.com",
      class: "deactivated",
      profiles: ["safe"],
      tags: [],
      network: { ipv4: ["2001:db8::1"] },
    });

    expect(() => createInventoryStore({ inventoryDir: INVENTORY_DIR }).list()).toThrow(
      /reason.*ipv4/i,
    );
  });

  it("updates curated fields without changing machine-owned observations", () => {
    writeInventory({
      $schema: "../target.schema.json",
      version: 1,
      host: "api.example.com",
      class: "prod",
      profiles: ["safe"],
      tags: ["api"],
      notes: "remove me",
      observed: { first_observed: "2026-08-01T00:00:00.000Z" },
      http: { status_code: 200, title: "API" },
    });
    const store = createInventoryStore({ inventoryDir: INVENTORY_DIR });

    const updated = store.updateCurated({
      id: "api.example.com",
      curated: {
        class: "prod",
        profiles: ["scan:nuclei:safe", "scan:nuclei:full"],
        tags: ["api", "external"],
      },
    });

    expect(updated).toEqual(
      expect.objectContaining({
        host: "api.example.com",
        profiles: ["scan:nuclei:safe", "scan:nuclei:full"],
        tags: ["api", "external"],
        observed: { first_observed: "2026-08-01T00:00:00.000Z" },
        http: { status_code: 200, title: "API" },
      }),
    );
    expect(updated).not.toHaveProperty("notes");
  });

  it("redacts inline credentials and applies preserve, replace, and clear updates", () => {
    writeInventory({
      $schema: "../target.schema.json",
      id: "cloudflare-production",
      kind: "provider-context",
      provider: "cloudflare",
      credentialMode: "configured",
      class: "prod",
      profiles: ["scan:prowler:cloudflare-production"],
      tags: [],
      credentials: {
        envVars: [{ name: "API_TOKEN", value: "stored-secret" }],
      },
    });
    const store = createInventoryStore({ inventoryDir: INVENTORY_DIR });

    expect(store.get("cloudflare-production").credentials).toEqual({
      envVars: [{ name: "API_TOKEN", configured: true }],
    });
    store.updateCurated({
      id: "cloudflare-production",
      curated: {
        class: "prod",
        profiles: ["scan:prowler:cloudflare-production"],
        tags: [],
      },
    });
    expect(
      JSON.parse(
        readFileSync(resolve(INVENTORY_DIR, "targets", "cloudflare-production.json"), "utf8"),
      ),
    ).toHaveProperty("credentials.envVars.0.value", "stored-secret");

    const replaced = store.updateCurated({
      id: "cloudflare-production",
      curated: {
        class: "prod",
        profiles: ["scan:prowler:cloudflare-production"],
        tags: [],
        credentials: {
          envVars: [
            {
              name: "API_TOKEN",
              valueFrom: { secretKeyRef: { name: "scanner", key: "token" } },
            },
          ],
        },
      },
    });
    expect(replaced.credentials).toEqual({
      envVars: [
        {
          name: "API_TOKEN",
          valueFrom: { secretKeyRef: { name: "scanner", key: "token" } },
        },
      ],
    });

    const cleared = store.updateCurated({
      id: "cloudflare-production",
      curated: {
        class: "prod",
        profiles: ["scan:prowler:cloudflare-production"],
        tags: [],
        credentials: null,
      },
    });
    expect(cleared).not.toHaveProperty("credentials");
  });

  it("normalizes a successful httpx observation into typed machine fields", () => {
    writeInventory({
      $schema: "../target.schema.json",
      version: 1,
      host: "api.example.com",
      class: "prod",
      profiles: ["safe"],
      tags: [],
    });
    const store = createInventoryStore({
      inventoryDir: INVENTORY_DIR,
      now: () => new Date("2026-08-09T08:00:00.000Z"),
    });

    store.mergeDiscovery([
      {
        input: "api.example.com",
        url: "https://api.example.com",
        scheme: "https",
        port: "443",
        status_code: 200,
        title: "API",
        time: "125ms",
        open_ports: [8443, 443, 8443],
        known_paths: ["/login", "/"],
        login_methods: ["Web login", "Basic"],
        host_ip: "192.0.2.10",
        a: ["192.0.2.10"],
        tech: ["Go"],
        cpe: [{ product: "go", vendor: "golang", cpe: "cpe:2.3:a:golang:go:*" }],
        tls: { tls_version: "tls13", subject_cn: "api.example.com", expired: false },
      },
    ]);

    expect(store.get("api.example.com")).toEqual(
      expect.objectContaining({
        observed: {
          first_observed: "2026-08-09T08:00:00.000Z",
          last_seen: "2026-08-09T08:00:00.000Z",
          last_attempt: "2026-08-09T08:00:00.000Z",
        },
        network: {
          ip: "192.0.2.10",
          ipv4: ["192.0.2.10"],
          open_ports: [443, 8443],
        },
        http: {
          url: "https://api.example.com",
          scheme: "https",
          port: 443,
          status_code: 200,
          title: "API",
          response_time: "125ms",
          known_paths: ["/", "/login"],
          login_methods: ["Basic", "Web login"],
        },
        tech: {
          names: ["Go"],
          cpe: [{ product: "go", vendor: "golang", cpe: "cpe:2.3:a:golang:go:*" }],
        },
        tls: { tls_version: "tls13", subject_cn: "api.example.com", expired: false },
      }),
    );
  });

  it("rejects target-id traversal and identity edits", () => {
    writeInventory({
      $schema: "../target.schema.json",
      version: 1,
      host: "api.example.com",
      class: "prod",
      profiles: ["safe"],
      tags: [],
    });
    const store = createInventoryStore({ inventoryDir: INVENTORY_DIR });

    expect(() => store.get("../state")).toThrow(/invalid target id/i);
    expect(() =>
      store.updateCurated({
        id: "api.example.com",
        curated: {
          host: "renamed.example.com",
          class: "prod",
          profiles: ["scan:nuclei:safe"],
          tags: [],
        } as never,
      }),
    ).toThrow(/host is immutable/i);
    expect(() =>
      store.updateCurated({
        id: "api.example.com",
        curated: {
          id: "renamed",
          class: "prod",
          profiles: ["scan:nuclei:safe"],
          tags: [],
        } as never,
      }),
    ).toThrow(/id is immutable/i);
  });

  it("renders deterministic scan lists and records per-host findings", () => {
    writeInventory({
      $schema: "../target.schema.json",
      version: 1,
      host: "api.example.com",
      class: "non-prod",
      profiles: ["safe", "full"],
      tags: [],
    });
    const store = createInventoryStore({
      inventoryDir: INVENTORY_DIR,
      now: () => new Date("2026-08-09T09:00:00.000Z"),
    });
    const outputDir = resolve(TEST_ROOT, ".gen");
    const resultPath = resolve(TEST_ROOT, "result.jsonl");
    writeFileSync(
      resultPath,
      `${JSON.stringify({ host: "https://api.example.com", "template-id": "headers" })}\n`,
      "utf8",
    );

    store.render({ outputDir });
    store.recordScan({ hosts: ["api.example.com"], resultPath });

    expect(readFileSync(resolve(outputDir, "default.safe.txt"), "utf8")).toBe(
      "api.example.com\n",
    );
    expect(store.get("api.example.com").scan).toEqual({
      last_scan: "2026-08-09T09:00:00.000Z",
      last_findings: 1,
    });
  });
});
