import { spawn } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { writeFileSync, mkdirSync } from "node:fs";
import { getObservationHost } from "./inventory-observation.ts";
import { createInventoryStore } from "./inventory-store.ts";

const NUCLEI_DIR = resolve(import.meta.dirname, "..", "..");
const GEN_DIR = resolve(NUCLEI_DIR, ".gen");
const DISCOVERED_JSON = resolve(NUCLEI_DIR, ".gen/discovered.json");
const DISCOVERED_HOSTS = resolve(NUCLEI_DIR, ".gen/discovered-hosts.txt");
// Persisted result of the last run so the dialog can show prior results instantly
// and only re-run on explicit refresh. Lives in .gen/ (gitignored, interim).
const CACHE_PATH = resolve(NUCLEI_DIR, ".gen/discovered-cache.json");
const inventoryStore = createInventoryStore();

// Probe fields for one host, without the inventory-derived `isKnown` (that is
// recomputed against the current inventory every time a result is served).
export type ProbedHost = {
  host: string;
  status?: number;
  responseTime?: string;
  openPorts?: number[];
  knownPaths?: string[];
  loginMethods?: string[];
  title?: string;
  tech?: string[];
  live: boolean;
};

export type DiscoveredHost = ProbedHost & { isKnown: boolean };

export type DiscoverResult = {
  hosts: DiscoveredHost[];
  newCount: number;
  ranAt: string | null;
  cached: boolean;
  log: string;
};

type DiscoverCache = { ranAt: string; log: string; hosts: ProbedHost[] };

export function parseDiscoveryJsonLines(source: string): unknown[] {
  return source
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line, index) => {
      try {
        return JSON.parse(line) as unknown;
      } catch (error) {
        throw new Error(
          `invalid discovery JSON on line ${index + 1}: ${(error as Error).message}`,
        );
      }
    });
}

export function parseDiscoveryRecords(source: string): ProbedHost[] {
  return parseDiscoveryJsonLines(source).map((value, index) => {
    let host: string;
    try {
      host = getObservationHost(value);
    } catch (error) {
      throw new Error(
        `discovery line ${index + 1} is missing host: ${(error as Error).message}`,
      );
    }
    const record = value as Record<string, unknown>;
    const status =
      typeof record.status_code === "number" ? record.status_code : undefined;
    const openPorts = Array.isArray(record.open_ports)
      ? record.open_ports.filter(
          (item): item is number => typeof item === "number",
        )
      : undefined;
    return {
      host,
      status,
      responseTime:
        typeof record.time === "string" ? record.time : undefined,
      openPorts,
      knownPaths: Array.isArray(record.known_paths)
        ? record.known_paths.filter(
            (item): item is string => typeof item === "string",
          )
        : undefined,
      loginMethods: Array.isArray(record.login_methods)
        ? record.login_methods.filter(
            (item): item is string => typeof item === "string",
          )
        : undefined,
      title: typeof record.title === "string" ? record.title : undefined,
      tech: Array.isArray(record.tech)
        ? record.tech.filter((item): item is string => typeof item === "string")
        : undefined,
      live:
        (status !== undefined || (openPorts?.length ?? 0) > 0) &&
        record.failed !== true,
    };
  });
}

export function discoveryExitError({
  code,
  timedOut,
}: {
  code: number | null;
  timedOut: boolean;
}): Error | null {
  if (timedOut) return new Error("discovery timed out after 220s");
  if (code === 0 || code === 3) return null;
  if (code === null) {
    return new Error("discovery terminated without an exit code");
  }
  return new Error(`discovery exited with code ${code}`);
}

function runScript(): Promise<string> {
  return new Promise((resolvePromise, reject) => {
    // detached:true puts the child in its own process group so we can signal the whole
    // tree (bash + DNS helper + subfinder + httpx) on timeout — killing just bash orphans the rest.
    const child = spawn("bash", ["hack/discover-targets.sh"], {
      cwd: NUCLEI_DIR,
      detached: true,
      // Close stdin: subfinder/httpx read stdin when it's an open pipe (no TTY) and
      // block waiting for EOF even with -dL/-l. 'ignore' gives them immediate EOF.
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        // The app runs the fast path: static scrape + NS/MX + subfinder + Naabu/httpx, no
        // gcloud/kubectl cluster enumeration (which needs auth/VPN and can hang).
        DISCOVER_NO_CLUSTER: "1",
        SUBFINDER_MAX_TIME: "1",
        PATH: `${process.env.HOME}/go/bin:${process.env.HOME}/.local/bin:${process.env.PATH}`,
      },
    });
    let out = "";
    const collect = (b: Buffer) => (out += b.toString());
    child.stdout?.on("data", collect);
    child.stderr?.on("data", collect);

    const killTree = (signal: NodeJS.Signals) => {
      // Negative pid targets the whole process group.
      try {
        if (child.pid) process.kill(-child.pid, signal);
      } catch {
        /* already gone */
      }
    };
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      out += "\n[!] discovery timed out after 220s — killing process group\n";
      killTree("SIGKILL");
    }, 220_000);

    child.on("close", (code) => {
      clearTimeout(timer);
      const error = discoveryExitError({ code, timedOut });
      if (error) {
        reject(new Error(out ? `${error.message}\n${out.slice(-4000)}` : error.message));
        return;
      }
      resolvePromise(out);
    });
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(new Error(`failed to spawn discovery: ${e.message}`));
    });
  });
}

// Single-flight: concurrent POST /api/discover calls share one run instead of stacking
// competing subfinder/httpx processes that truncate each other's output.
let inFlight: Promise<DiscoverResult> | null = null;

function parseProbed(): Map<string, ProbedHost> {
  const byHost = new Map<string, ProbedHost>();
  if (!existsSync(DISCOVERED_JSON)) return byHost;
  for (const host of parseDiscoveryRecords(
    readFileSync(DISCOVERED_JSON, "utf8"),
  )) {
    byHost.set(host.host, host);
  }
  return byHost;
}

function allCandidateHosts(): string[] {
  if (!existsSync(DISCOVERED_HOSTS)) return [];
  return readFileSync(DISCOVERED_HOSTS, "utf8")
    .split("\n")
    .map((l) => l.trim().toLowerCase())
    .filter(Boolean);
}

// Stamps isKnown against the CURRENT inventory (so hosts added since the run show as
// known) and derives newCount. Used for both fresh runs and cached reads.
function enrich(
  base: ProbedHost[],
  ranAt: string | null,
  log: string,
  cached: boolean,
): DiscoverResult {
  const known = new Set(
    inventoryStore.list().rows.map((target) => target.host),
  );
  const hosts: DiscoveredHost[] = base.map((h) => ({
    ...h,
    isKnown: known.has(h.host),
  }));
  return {
    hosts,
    newCount: hosts.filter((h) => !h.isKnown).length,
    ranAt,
    cached,
    log,
  };
}

// Returns the last cached discovery (re-stamped against current inventory), or an empty
// result when nothing has been discovered yet. Cheap — no subprocess.
export function readCachedDiscovery(): DiscoverResult {
  if (!existsSync(CACHE_PATH)) {
    return { hosts: [], newCount: 0, ranAt: null, cached: true, log: "" };
  }
  const cache = JSON.parse(readFileSync(CACHE_PATH, "utf8")) as DiscoverCache;
  return enrich(cache.hosts, cache.ranAt, cache.log, true);
}

export function runDiscovery(): Promise<DiscoverResult> {
  if (inFlight) return inFlight;
  inFlight = runDiscoveryOnce().finally(() => {
    inFlight = null;
  });
  return inFlight;
}

async function runDiscoveryOnce(): Promise<DiscoverResult> {
  const log = await runScript();
  const records = existsSync(DISCOVERED_JSON)
    ? parseDiscoveryJsonLines(readFileSync(DISCOVERED_JSON, "utf8"))
    : [];
  inventoryStore.mergeDiscovery(records);
  const probed = parseProbed();

  // Union of every candidate host and every probed host.
  const hostSet = new Set<string>([...allCandidateHosts(), ...probed.keys()]);
  const base: ProbedHost[] = [...hostSet].sort().map((host) => {
    const p = probed.get(host);
    return {
      host,
      status: p?.status,
      responseTime: p?.responseTime,
      openPorts: p?.openPorts,
      knownPaths: p?.knownPaths,
      loginMethods: p?.loginMethods,
      title: p?.title || undefined,
      tech: p?.tech,
      live: p?.live ?? false,
    };
  });

  const ranAt = new Date().toISOString();
  const trimmedLog = log.slice(-4000);
  // Persist for the next dialog open.
  mkdirSync(GEN_DIR, { recursive: true });
  const cache: DiscoverCache = { ranAt, log: trimmedLog, hosts: base };
  writeFileSync(CACHE_PATH, JSON.stringify(cache), "utf8");

  return enrich(base, ranAt, trimmedLog, false);
}
