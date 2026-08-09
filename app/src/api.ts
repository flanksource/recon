import type {
  DiscoverResult,
  Finding,
  Inventory,
  ProfileDocument,
  ProfileEngine,
  ScanProfile,
  ScanRun,
  ScanStatus,
  CuratedTarget,
  TargetDocument,
} from "./types";

async function responseJson<T>(res: Response, request: string): Promise<T> {
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(body.error ?? `${request} failed: ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export async function fetchInventory(): Promise<Inventory> {
  const res = await fetch("/api/inventory");
  if (!res.ok) throw new Error(`GET /api/inventory failed: ${res.status}`);
  return res.json();
}

export async function fetchTarget(host: string): Promise<TargetDocument> {
  const path = `/api/inventory/${encodeURIComponent(host)}`;
  return responseJson<TargetDocument>(await fetch(path), `GET ${path}`);
}

export async function fetchTargetSchema(): Promise<Record<string, unknown>> {
  const path = "/api/inventory/schema/target";
  return responseJson<Record<string, unknown>>(await fetch(path), `GET ${path}`);
}

export async function saveTarget(host: string, curated: CuratedTarget): Promise<TargetDocument> {
  const path = `/api/inventory/${encodeURIComponent(host)}`;
  return responseJson<TargetDocument>(
    await fetch(path, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(curated),
    }),
    `PUT ${path}`,
  );
}

export async function fetchProfiles(): Promise<ProfileDocument[]> {
  const res = await fetch("/api/profiles");
  return (
    await responseJson<{ profiles: ProfileDocument[] }>(
      res,
      "GET /api/profiles",
    )
  ).profiles;
}

export async function saveProfile(
  engine: ProfileEngine,
  name: string,
  config: Record<string, unknown>,
): Promise<ProfileDocument> {
  const path = `/api/profiles/${encodeURIComponent(engine)}/${encodeURIComponent(name)}`;
  const res = await fetch(path, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ config }),
  });
  return (await responseJson<{ profile: ProfileDocument }>(res, `PUT ${path}`))
    .profile;
}

export async function saveTargets(rows: TargetDocument[]): Promise<Inventory> {
  let saved = 0;
  for (const row of rows) {
    try {
      await saveTarget(row.host, {
        class: row.class,
        app: row.app,
        cluster: row.cluster,
        source: row.source,
        profiles: row.profiles,
        ports: row.ports,
        tags: row.tags,
        notes: row.notes,
        reason: row.reason,
      });
      saved += 1;
    } catch (error) {
      throw new Error(`saved ${saved} target(s); ${row.host} failed: ${(error as Error).message}`);
    }
  }
  return fetchInventory();
}

export async function fetchScans(): Promise<ScanRun[]> {
  const res = await fetch("/api/scans");
  if (!res.ok) throw new Error(`GET /api/scans failed: ${res.status}`);
  return (await res.json()).scans;
}

export async function fetchScanFindings(file: string): Promise<Finding[]> {
  const res = await fetch(`/api/scans/${encodeURIComponent(file)}`);
  if (!res.ok) throw new Error(`GET /api/scans/${file} failed: ${res.status}`);
  return (await res.json()).findings;
}

// Returns the last cached discovery instantly (empty if none has run yet).
export async function fetchDiscoveryCache(): Promise<DiscoverResult> {
  const res = await fetch("/api/discover");
  if (!res.ok) throw new Error(`GET /api/discover failed: ${res.status}`);
  return res.json();
}

// Re-runs static, NS/MX, subfinder, Naabu, and httpx discovery and re-caches.
export async function runDiscovery(): Promise<DiscoverResult> {
  const res = await fetch("/api/discover", { method: "POST" });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error ?? `POST /api/discover failed: ${res.status}`);
  }
  return res.json();
}

async function scanRequest(init?: RequestInit): Promise<ScanStatus> {
  const res = await fetch("/api/scan", init);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(
      body.error ?? `${init?.method ?? "GET"} /api/scan failed: ${res.status}`,
    );
  }
  return res.json();
}

// Current (or last) scan on the server — stats, live findings, log tail.
export function fetchScanStatus(): Promise<ScanStatus> {
  return scanRequest();
}

// Starts the selected scanner over the given hosts. `confirm` authorises a
// full/DAST scan of prod/public hosts; the server refuses without it.
export function startScan(args: {
  hosts: string[];
  profile: ScanProfile;
  confirm?: boolean;
  config?: Record<string, unknown>;
}): Promise<ScanStatus> {
  return scanRequest({
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(args),
  });
}

export function cancelScan(): Promise<ScanStatus> {
  return scanRequest({ method: "DELETE" });
}
