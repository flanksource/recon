import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createApiHandler } from "../vite-plugin-targets.ts";

const TEST_ROOT = resolve(import.meta.dirname, "..", ".tmp", "inventory-api-test");
const INVENTORY_DIR = resolve(TEST_ROOT, "inventory");
const CONFIG_DIR = resolve(TEST_ROOT, "config");
let server: Server;
let baseUrl: string;

function writeJson(path: string, value: unknown): void {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

beforeEach(async () => {
  rmSync(TEST_ROOT, { recursive: true, force: true });
  mkdirSync(resolve(INVENTORY_DIR, "targets"), { recursive: true });
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeJson(resolve(INVENTORY_DIR, "inventory.json"), {
    $schema: "./inventory.schema.json",
    version: 1,
    zones: ["example.com"],
  });
  writeJson(resolve(INVENTORY_DIR, "targets", "api.example.com.json"), {
    $schema: "../target.schema.json",
    version: 1,
    host: "api.example.com",
    class: "prod",
    profiles: ["safe"],
    tags: ["api"],
    http: { status_code: 200 },
  });
  writeFileSync(
    resolve(CONFIG_DIR, "discovery.naabu.yaml"),
    "top-ports: \"100\"\nrate: 250\n",
    "utf8",
  );
  const handler = createApiHandler({
    inventoryDir: INVENTORY_DIR,
    profileConfigDir: CONFIG_DIR,
  });
  server = createServer((req, res) => handler(req, res, () => {
    res.statusCode = 404;
    res.end("not found");
  }));
  await new Promise<void>((resolvePromise) => server.listen(0, "127.0.0.1", resolvePromise));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test server did not bind a TCP port");
  baseUrl = `http://127.0.0.1:${address.port}`;
});

afterEach(async () => {
  await new Promise<void>((resolvePromise, reject) =>
    server.close((error) => (error ? reject(error) : resolvePromise())),
  );
  rmSync(TEST_ROOT, { recursive: true, force: true });
});

describe("inventory API", () => {
  it("serves the list, target schema, and deep-linked target", async () => {
    const [inventory, schema, target] = await Promise.all([
      fetch(`${baseUrl}/api/inventory`).then((response) => response.json()),
      fetch(`${baseUrl}/api/inventory/schema/target`).then((response) => response.json()),
      fetch(`${baseUrl}/api/inventory/api.example.com`).then((response) => response.json()),
    ]);

    expect(inventory).toEqual(expect.objectContaining({ version: 1, rows: [expect.any(Object)] }));
    expect(schema).toEqual(expect.objectContaining({ $schema: expect.stringContaining("2020-12") }));
    expect(target).toEqual(expect.objectContaining({ host: "api.example.com", class: "prod" }));
  });

  it("updates only curated fields and removes the legacy bulk endpoint", async () => {
    const update = await fetch(`${baseUrl}/api/inventory/api.example.com`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ class: "prod", profiles: ["safe", "full"], tags: ["api"] }),
    });
    const legacy = await fetch(`${baseUrl}/api/targets`, { method: "PUT", body: "{}" });

    expect(update.status).toBe(200);
    expect(await update.json()).toEqual(
      expect.objectContaining({ profiles: ["safe", "full"], http: { status_code: 200 } }),
    );
    expect(legacy.status).toBe(404);
  });

  it("rejects attempts to write machine-owned fields", async () => {
    const response = await fetch(`${baseUrl}/api/inventory/api.example.com`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        class: "prod",
        profiles: ["safe"],
        tags: ["api"],
        http: { status_code: 500 },
      }),
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "field is not editable: http" });
  });

  it("rejects a scan config that is not an object at the HTTP boundary", async () => {
    const response = await fetch(`${baseUrl}/api/scan`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        hosts: ["api.example.com"],
        profile: "missing",
        config: [],
      }),
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: "expected config to be an object",
    });
  });

  it("serves and updates the Naabu discovery profile", async () => {
    const listed = await fetch(`${baseUrl}/api/profiles`).then((response) =>
      response.json(),
    );
    const response = await fetch(`${baseUrl}/api/profiles/naabu/discovery`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ config: { "top-ports": "100", rate: 300 } }),
    });

    expect(listed.profiles).toEqual([
      expect.objectContaining({ id: "naabu:discovery" }),
    ]);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      profile: expect.objectContaining({
        engine: "naabu",
        name: "discovery",
        config: { "top-ports": "100", rate: 300 },
      }),
    });
  });

  it("streams the current scan status as an SSE event", async () => {
    const controller = new AbortController();
    const response = await fetch(`${baseUrl}/api/scan/events`, {
      signal: controller.signal,
    });
    const first = await response.body?.getReader().read();
    controller.abort();

    expect(response.headers.get("content-type")).toBe("text/event-stream");
    expect(new TextDecoder().decode(first?.value)).toContain(
      'data: {"phase":"idle"',
    );
  });
});
