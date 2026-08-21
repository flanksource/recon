import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { Plugin, Connect } from "vite";
import { listScans, readScan } from "./server/scans-io.ts";
import { runDiscovery, readCachedDiscovery } from "./server/discover-io.ts";
import { listProfiles, writeProfile } from "./server/profile-io.ts";
import type { ProfileEngine } from "./profile-schema/index.ts";
import {
  createInventoryStore,
  type CuratedTarget,
  type InventoryStoreOptions,
} from "./server/inventory-store.ts";
import {
  cancelScan,
  getScanStatus,
  startScan,
  subscribeScan,
  type ScanProfile,
} from "./server/scan-io.ts";

function json(
  res: Parameters<Connect.NextHandleFunction>[1],
  code: number,
  body: unknown,
) {
  res.statusCode = code;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(body));
}

function readBody(
  req: Parameters<Connect.NextHandleFunction>[0],
): Promise<string> {
  return new Promise((resolvePromise, reject) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => resolvePromise(data));
    req.on("error", reject);
  });
}

function bodyObject(source: string): Record<string, unknown> {
  const value = JSON.parse(source) as unknown;
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("request body must be a JSON object");
  }
  return value as Record<string, unknown>;
}

function scanEvents(
  req: Parameters<Connect.NextHandleFunction>[0],
  res: Parameters<Connect.NextHandleFunction>[1],
): void {
  res.statusCode = 200;
  res.setHeader("content-type", "text/event-stream");
  res.setHeader("cache-control", "no-cache, no-transform");
  res.setHeader("connection", "keep-alive");
  res.flushHeaders();

  const unsubscribe = subscribeScan((status) => {
    if (!res.writableEnded) res.write(`data: ${JSON.stringify(status)}\n\n`);
  });
  const keepAlive = setInterval(() => {
    if (!res.writableEnded) res.write(": keep-alive\n\n");
  }, 15_000);
  req.on("close", () => {
    clearInterval(keepAlive);
    unsubscribe();
  });
}

export function createApiHandler(
  options: InventoryStoreOptions & { profileConfigDir?: string } = {},
): Connect.NextHandleFunction {
  const { profileConfigDir, ...inventoryOptions } = options;
  const store = createInventoryStore(inventoryOptions);
  const schemaPath = resolve(
    import.meta.dirname,
    "..",
    "internal",
    "schema",
    "target.schema.json",
  );
  return async (req, res, next) => {
    if (!req.url?.startsWith("/api/")) return next();
    const pathname = new URL(req.url, "http://localhost").pathname;
    try {
      if (pathname === "/api/inventory" && req.method === "GET") {
        return json(res, 200, store.list());
      }
      if (pathname === "/api/inventory/schema/target" && req.method === "GET") {
        return json(res, 200, JSON.parse(readFileSync(schemaPath, "utf8")) as unknown);
      }
      if (pathname.startsWith("/api/inventory/") && req.method === "GET") {
        const id = decodeURIComponent(pathname.slice("/api/inventory/".length));
        try {
          return json(res, 200, store.get(id));
        } catch (error) {
          if ((error as Error).message.startsWith("target not found:")) {
            return json(res, 404, { error: (error as Error).message });
          }
          throw error;
        }
      }
      if (pathname.startsWith("/api/inventory/") && req.method === "PUT") {
        const id = decodeURIComponent(pathname.slice("/api/inventory/".length));
        try {
          const curated = bodyObject(await readBody(req));
          return json(
            res,
            200,
            store.updateCurated({ id, curated: curated as CuratedTarget }),
          );
        } catch (error) {
          return json(res, 400, { error: (error as Error).message });
        }
      }
      if (pathname === "/api/profiles" && req.method === "GET") {
        return json(res, 200, {
          profiles: listProfiles({ configDir: profileConfigDir }),
        });
      }
      if (pathname.startsWith("/api/profiles/") && req.method === "PUT") {
        const [engine, name, extra] = pathname
          .slice("/api/profiles/".length)
          .split("/");
        if (
          extra ||
          (engine !== "nuclei" && engine !== "httpx" && engine !== "naabu") ||
          !name
        ) {
          return json(res, 400, {
            error: "expected /api/profiles/{nuclei|httpx|naabu}/{name}",
          });
        }
        const payload = JSON.parse(await readBody(req)) as { config?: unknown };
        if (
          payload.config === null ||
          typeof payload.config !== "object" ||
          Array.isArray(payload.config)
        ) {
          return json(res, 400, { error: "expected { config: object }" });
        }
        return json(res, 200, {
          profile: writeProfile(
            engine as ProfileEngine,
            decodeURIComponent(name),
            payload.config as Record<string, unknown>,
            { configDir: profileConfigDir },
          ),
        });
      }
      if (pathname === "/api/scans" && req.method === "GET") {
        return json(res, 200, { scans: listScans() });
      }
      if (pathname.startsWith("/api/scans/") && req.method === "GET") {
        const file = decodeURIComponent(pathname.slice("/api/scans/".length));
        return json(res, 200, readScan(file));
      }
      if (pathname === "/api/discover" && req.method === "GET") {
        // Cached prior results — instant, no subprocess.
        return json(res, 200, readCachedDiscovery());
      }
      if (pathname === "/api/discover" && req.method === "POST") {
        // Explicit refresh — runs DNS enumeration + httpx and re-caches.
        return json(res, 200, await runDiscovery());
      }
      if (pathname === "/api/scan/events" && req.method === "GET") {
        return scanEvents(req, res);
      }
      if (pathname === "/api/scan" && req.method === "GET") {
        return json(res, 200, getScanStatus());
      }
      if (pathname === "/api/scan" && req.method === "POST") {
        const payload = JSON.parse(await readBody(req)) as {
          hosts?: string[];
          profile?: ScanProfile;
          confirm?: boolean;
          config?: unknown;
        };
        if (!Array.isArray(payload.hosts) || !payload.profile) {
          return json(res, 400, {
            error: "expected { hosts: string[], profile }",
          });
        }
        if (
          payload.config !== undefined &&
          (payload.config === null ||
            typeof payload.config !== "object" ||
            Array.isArray(payload.config))
        ) {
          return json(res, 400, {
            error: "expected config to be an object",
          });
        }
        return json(
          res,
          200,
          startScan({
            hosts: payload.hosts,
            profile: payload.profile,
            confirm: payload.confirm,
            config: payload.config as Record<string, unknown> | undefined,
          }),
        );
      }
      if (pathname === "/api/scan" && req.method === "DELETE") {
        return json(res, 200, cancelScan());
      }
      return json(res, 404, { error: "not found" });
    } catch (err) {
      return json(res, 500, { error: (err as Error).message });
    }
  };
}

export function targetsApi(): Plugin {
  const handler = createApiHandler();
  return {
    name: "nuclei-targets-api",
    configureServer(server) {
      server.middlewares.use(handler);
    },
    configurePreviewServer(server) {
      server.middlewares.use(handler);
    },
  };
}
