// Serve contract/snapshot/ through the real TypeScript API and record the
// responses as contract/golden/subset/ — the committed reference the Go
// contract suite replays after the TypeScript backend is gone.
//
//   pnpm --dir app exec tsx hack/capture-subset.ts
//
// This uses createApiHandler({inventoryDir, profileConfigDir}), the same seam
// server/inventory-api.test.ts drives, so the captured bytes are exactly what
// the current implementation produces for this input.
//
// Only the endpoints whose data source is redirectable are captured. listScans()
// resolves results/ from the module's own NUCLEI_DIR with no override, so a
// /api/scans capture here would describe the real estate rather than the
// snapshot; scan-side expectations are asserted directly in the Go tests
// against contract/snapshot/results/ instead.
import { mkdirSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { resolve } from "node:path";
import { createApiHandler } from "../vite-plugin-targets.ts";

const NUCLEI_DIR = resolve(import.meta.dirname, "..", "..");
const SNAPSHOT = resolve(NUCLEI_DIR, "contract/snapshot");
const OUT = resolve(NUCLEI_DIR, "contract/golden/subset");

const handler = createApiHandler({
  inventoryDir: resolve(SNAPSHOT, "inventory"),
  profileConfigDir: resolve(SNAPSHOT, "config"),
});
const server = createServer((req, res) => {
  handler(req, res, () => {
    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not found" }));
  });
});

await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
const address = server.address();
if (address === null || typeof address === "string") throw new Error("failed to bind");
const base = `http://127.0.0.1:${address.port}`;

mkdirSync(resolve(OUT, "targets"), { recursive: true });

const captured: Array<{ path: string; status: number; file: string }> = [];
const capture = async (path: string, file: string): Promise<any> => {
  const response = await fetch(`${base}${path}`);
  const body = await response.json();
  writeFileSync(resolve(OUT, file), `${JSON.stringify(body, null, 2)}\n`);
  captured.push({ path, status: response.status, file });
  return body;
};

const inventory = await capture("/api/inventory", "inventory.json");
await capture("/api/inventory/schema/target", "target-schema.json");
await capture("/api/profiles", "profiles.json");

for (const row of inventory.rows as Array<{ host: string }>) {
  await capture(`/api/inventory/${row.host}`, `targets/${row.host}.json`);
}

// Error shapes are contract too — the Go port has to reproduce the message text
// and the (quirky) status codes exactly, since the UI renders body.error.
const first = (inventory.rows as Array<{ host: string }>)[0].host;
const captureError = async (path: string, init: RequestInit, file: string) => {
  const response = await fetch(`${base}${path}`, init);
  const body = await response.json();
  writeFileSync(resolve(OUT, file), `${JSON.stringify({ status: response.status, body }, null, 2)}\n`);
  captured.push({ path, status: response.status, file });
};
const json = (body: unknown): RequestInit => ({
  method: "PUT",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(body),
});

await captureError(`/api/inventory/${first}`, json({ class: "prod", profiles: ["safe"], tags: [], http: { status_code: 1 } }), "err-not-editable.json");
await captureError(`/api/inventory/${first}`, json({ class: "prod", profiles: ["safe"], tags: [], host: "other.example.com" }), "err-host-immutable.json");
await captureError(`/api/inventory/${first}`, json({ class: "deactivated", profiles: ["safe"], tags: [] }), "err-deactivated-needs-reason.json");
await captureError(`/api/inventory/${first}`, json({ class: "prod", profiles: ["safe"], tags: [], reason: "no" }), "err-reason-without-deactivated.json");
await captureError("/api/inventory/no-such-host.example.test", {}, "err-target-404.json");
await captureError("/api/profiles/nuclei/safe/extra", json({ config: {} }), "err-profile-path.json");
await captureError("/api/profiles/bogus/safe", json({ config: {} }), "err-profile-engine.json");

server.close();

writeFileSync(resolve(OUT, "index.json"), `${JSON.stringify(captured, null, 2)}\n`);
console.log(JSON.stringify({ captured: captured.length, targets: inventory.rows.length, statuses: [...new Set(captured.map((c) => c.status))].sort() }, null, 2));
