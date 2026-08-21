// Runs an ad-hoc Nuclei scan or targeted Naabu/httpx discovery rescan over a chosen set
// of inventory hosts. Nuclei runs retain the same result naming and inventory
// update behavior as the Taskfile scans.
//
// One scanner runs at a time. Nuclei progress comes from `-stats -stats-json`
// output; discovery refreshes inventory directly from httpx JSONL output.
import { spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { stringify } from "yaml";
import {
  validateProfileConfig,
  type ProfileDocument,
} from "../profile-schema/index.ts";
import { parseDiscoveryJsonLines } from "./discover-io.ts";
import { createInventoryStore } from "./inventory-store.ts";
import { listProfiles } from "./profile-io.ts";
import { parseFindings } from "./scans-io.ts";
import {
  appendScanOutput,
  createScanOutputState,
  flushScanOutput,
  type ScanOutputState,
  type ScanPhase,
  type ScanStatus,
} from "./scan-runtime.ts";

export type { ScanStatus } from "./scan-runtime.ts";

const NUCLEI_DIR = resolve(import.meta.dirname, "..", "..");
const GEN_DIR = resolve(NUCLEI_DIR, ".gen");
const RESULTS_DIR = resolve(NUCLEI_DIR, "results");
const HOST_LIST_RELATIVE = ".gen/app-scan.txt";
const HOST_LIST = resolve(NUCLEI_DIR, HOST_LIST_RELATIVE);
const RUN_CONFIG_RELATIVE = ".gen/app-scan-profile.yaml";
const RUN_CONFIG = resolve(NUCLEI_DIR, RUN_CONFIG_RELATIVE);
const inventoryStore = createInventoryStore();

// Shared excludes from Taskfile.yaml's EXCLUDE var — applied to every profile.
const EXCLUDE_TAGS = "dos,fuzz,bruteforce,intrusive,azure";
const STATS_INTERVAL_SECONDS = 2;
const MAX_RUNTIME_MS = 30 * 60_000;

export const SCAN_PROFILES = ["safe", "full", "discovery"] as const;
export type ScanProfile = string;

// Classes where a DAST/fuzzing run would send malicious payloads at something real.
// Mirrors the CONFIRM=yes gate on `task scan:full`. A host missing from the inventory
// gets the same treatment: an unverifiable class is not a safe one.
const CONFIRM_CLASSES = new Set(["prod", "public", "unknown"]);

type Run = ScanOutputState & {
  phase: ScanPhase;
  profile: ScanProfile;
  group: string;
  hosts: string[];
  file: string | null;
  path: string | null;
  startedAt: string;
  finishedAt: string | null;
  error: string | null;
  command: string[];
  exitCode: number | null;
  observations: number | null;
  child: ChildProcess | null;
  cancelling: boolean;
  discoveryJsonl: string;
};

let current: Run | null = null;
const listeners = new Set<(status: ScanStatus) => void>();

function publishScan(): void {
  const status = getScanStatus();
  for (const listener of listeners) listener(status);
}

export function subscribeScan(listener: (status: ScanStatus) => void): () => void {
  listeners.add(listener);
  listener(getScanStatus());
  return () => listeners.delete(listener);
}

const IDLE: ScanStatus = {
  phase: "idle",
  profile: null,
  group: null,
  hosts: [],
  file: null,
  startedAt: null,
  finishedAt: null,
  stats: null,
  findings: [],
  log: "",
  error: null,
  command: null,
  exitCode: null,
  observations: null,
  output: [],
};

// Hosts are interpolated into an argv-adjacent host list file; anything outside the
// FQDN/port character set is a bug or an injection attempt, so reject it loudly.
const HOST_RE = /^[a-z0-9][a-z0-9._*-]*(:\d{1,5})?$/;

function normalizeHost(raw: string): string {
  return raw
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .toLowerCase();
}

// results/<profile>-<group>-<ts>.jsonl — scans-io parses profile/group back out of it.
function timestamp(): string {
  const d = new Date();
  const p = (n: number, w = 2) => String(n).padStart(w, "0");
  return (
    `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}` +
    `-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`
  );
}

// Names the run after the classes it covers, so the Scans tab reads like the CLI runs.
function groupFor(hosts: string[], classByHost: Map<string, string>): string {
  const classes = [
    ...new Set(hosts.map((h) => classByHost.get(h) ?? "unknown")),
  ].sort();
  if (classes.length === 1) return classes[0];
  return classes.length <= 2 ? classes.join("+") : "mixed";
}

export function addressableClasses(
  targets: Array<{ host?: string; class: string }>,
): Map<string, string> {
  return new Map(
    targets.flatMap((target) =>
      target.host ? [[target.host, target.class] as const] : [],
    ),
  );
}

export function scanInvocation(options: {
  profile: ScanProfile;
  resultFile: string | null;
  configFile?: string;
  dast?: boolean;
}): { command: string; args: string[] } {
  const { profile, resultFile } = options;
  if (profile === "discovery") {
    return {
      command: "pnpm",
      args: [
        "--dir",
        "app",
        "exec",
        "tsx",
        "server/discovery-profile.ts",
        "--hosts",
        HOST_LIST_RELATIVE,
      ],
    };
  }
  if (!resultFile) throw new Error(`${profile} scan requires a result file`);
  return {
    command: "nuclei",
    args: [
      "-config",
      options.configFile ?? `config/${profile}.yaml`,
      "-etags",
      EXCLUDE_TAGS,
      ...(options.dast ? ["-dast", "-t", "dast/"] : []),
      "-l",
      HOST_LIST_RELATIVE,
      "-t",
      "templates/",
      "-enable-self-contained",
      "-jsonl",
      "-o",
      `results/${resultFile}`,
      "-sarif-export",
      `results/${resultFile.replace(/\.jsonl$/, ".sarif")}`,
      "-stats",
      "-stats-json",
      "-stats-interval",
      String(STATS_INTERVAL_SECONDS),
    ],
  };
}

export function resolveNucleiProfile(options: {
  profile: string;
  config?: Record<string, unknown>;
  profiles?: ProfileDocument[];
}): { config: Record<string, unknown>; dast: boolean } {
  const saved = (options.profiles ?? listProfiles()).find(
    (profile) =>
      profile.engine === "nuclei" && profile.name === options.profile,
  );
  if (!saved) throw new Error(`Nuclei profile not found: ${options.profile}`);
  const config = options.config ?? saved.config;
  validateProfileConfig("nuclei", config);
  return { config, dast: config.dast === true };
}

function completeSuccessfulRun(run: Run, finishedAt: string): void {
  if (run.profile === "discovery") {
    const records = parseDiscoveryJsonLines(run.discoveryJsonl);
    if (records.length === 0) {
      throw new Error("discovery profile produced no records");
    }
    const merged = inventoryStore.mergeDiscovery(records);
    const missing = run.hosts.filter((host) => !merged.updated.includes(host));
    if (missing.length > 0) {
      throw new Error(
        `discovery profile returned no observation for: ${missing.join(", ")}`,
      );
    }
    run.observations = merged.updated.length;
    appendScanOutput(
      run,
      "system",
      `[+] refreshed ${merged.updated.length} target observation(s)\n`,
    );
    run.phase = "done";
    return;
  }
  if (!run.path) throw new Error("nuclei scan completed without a result path");
  inventoryStore.recordScan({
    hosts: run.hosts,
    resultPath: run.path,
    scannedAt: finishedAt,
  });
  run.phase = "done";
}

export function startScan(opts: {
  hosts: string[];
  profile: ScanProfile;
  confirm?: boolean;
  config?: Record<string, unknown>;
}): ScanStatus {
  if (current?.phase === "running") {
    throw new Error(
      "a scan is already running — cancel it before starting another",
    );
  }
  if (opts.profile === "discovery" && opts.config) {
    throw new Error("discovery rescan does not accept a Nuclei config");
  }
  const hosts = [
    ...new Set((opts.hosts ?? []).map(normalizeHost).filter(Boolean)),
  ].sort();
  if (hosts.length === 0) throw new Error("no hosts to scan");
  const invalid = hosts.filter((h) => !HOST_RE.test(h));
  if (invalid.length) throw new Error(`invalid host(s): ${invalid.join(", ")}`);

  const classByHost = addressableClasses(inventoryStore.list().rows);
  const unsaved = hosts.filter((host) => !classByHost.has(host));
  if (opts.profile === "discovery" && unsaved.length > 0) {
    throw new Error(
      `discovery rescan requires saved inventory targets: ${unsaved.join(", ")}`,
    );
  }
  const nucleiProfile =
    opts.profile === "discovery"
      ? null
      : resolveNucleiProfile({
          profile: opts.profile,
          config: opts.config,
        });
  const risky = hosts.filter((h) =>
    CONFIRM_CLASSES.has(classByHost.get(h) ?? "unknown"),
  );
  if (nucleiProfile?.dast && risky.length && !opts.confirm) {
    throw new Error(
      `REFUSED: this DAST scan sends malicious payloads at ${risky.length} ` +
        `prod/public/unclassified host(s): ${risky.join(", ")}. Confirm the scan to proceed.`,
    );
  }

  mkdirSync(GEN_DIR, { recursive: true });
  if (opts.profile !== "discovery") {
    mkdirSync(RESULTS_DIR, { recursive: true });
  }
  writeFileSync(HOST_LIST, `${hosts.join("\n")}\n`, "utf8");
  if (nucleiProfile && opts.config) {
    writeFileSync(RUN_CONFIG, stringify(nucleiProfile.config), "utf8");
  }

  const group = groupFor(hosts, classByHost);
  const file =
    opts.profile === "discovery"
      ? null
      : `${opts.profile}-${group}-${timestamp()}.jsonl`;
  const invocation = scanInvocation({
    profile: opts.profile,
    resultFile: file,
    configFile: nucleiProfile && opts.config ? RUN_CONFIG_RELATIVE : undefined,
    dast: nucleiProfile?.dast,
  });
  const run: Run = {
    ...createScanOutputState(),
    phase: "running",
    profile: opts.profile,
    group,
    hosts,
    file,
    path: file ? resolve(RESULTS_DIR, file) : null,
    startedAt: new Date().toISOString(),
    finishedAt: null,
    error: null,
    command: [invocation.command, ...invocation.args],
    exitCode: null,
    observations: null,
    child: null,
    cancelling: false,
    discoveryJsonl: "",
  };
  appendScanOutput(
    run,
    "system",
    opts.profile === "discovery"
      ? `>>> Naabu + httpx discovery rescan of ${hosts.length} host(s)\n`
      : `>>> nuclei ${opts.profile} scan of ${hosts.length} host(s)\n`,
  );
  current = run;

  // detached: the whole process group is signalled on cancel/timeout — killing just
  // the scanner's shell would orphan its workers.
  const child = spawn(invocation.command, invocation.args, {
    cwd: NUCLEI_DIR,
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      PATH: `${process.env.HOME}/go/bin:${process.env.HOME}/.local/bin:${process.env.PATH}`,
    },
  });
  run.child = child;
  publishScan();

  child.stdout?.on("data", (buffer: Buffer) => {
    const text = buffer.toString();
    if (run.profile === "discovery") run.discoveryJsonl += text;
    appendScanOutput(run, "stdout", text);
    publishScan();
  });
  child.stderr?.on("data", (buffer: Buffer) => {
    appendScanOutput(run, "stderr", buffer.toString());
    publishScan();
  });

  const timer = setTimeout(() => {
    appendScanOutput(
      run,
      "system",
      `[!] scan exceeded ${MAX_RUNTIME_MS / 60_000}m — killing process group\n`,
    );
    publishScan();
    cancelScan();
  }, MAX_RUNTIME_MS);

  child.on("close", (code) => {
    clearTimeout(timer);
    if (opts.config) rmSync(RUN_CONFIG, { force: true });
    if (run.finishedAt) return;
    flushScanOutput(run);
    run.child = null;
    run.exitCode = code;
    const finishedAt = new Date().toISOString();
    run.finishedAt = finishedAt;
    if (run.cancelling) {
      run.phase = "cancelled";
    } else if (code === 0) {
      try {
        completeSuccessfulRun(run, finishedAt);
      } catch (error) {
        run.phase = "failed";
        run.error = `${run.profile} completed but inventory update failed: ${(error as Error).message}`;
        appendScanOutput(run, "system", `[!] ${run.error}\n`);
      }
    } else {
      run.phase = "failed";
      run.error = `${invocation.command} exited with code ${code}`;
    }
    if (run.phase !== "done") {
      appendScanOutput(
        run,
        "system",
        `[!] ${run.phase} — inventory scan state not updated\n`,
      );
    } else if (run.profile !== "discovery") {
      appendScanOutput(run, "system", `[+] ${invocation.command} completed successfully\n`);
    }
    publishScan();
  });

  child.on("error", (e) => {
    clearTimeout(timer);
    if (opts.config) rmSync(RUN_CONFIG, { force: true });
    if (run.finishedAt) return;
    run.child = null;
    run.phase = "failed";
    run.finishedAt = new Date().toISOString();
    run.error = `failed to spawn ${invocation.command}: ${e.message}`;
    appendScanOutput(run, "system", `[!] ${run.error}\n`);
    publishScan();
  });

  return getScanStatus();
}

export function cancelScan(): ScanStatus {
  if (!current || current.phase !== "running" || !current.child?.pid) {
    return getScanStatus();
  }
  current.cancelling = true;
  appendScanOutput(current, "system", "[!] cancellation requested\n");
  publishScan();
  try {
    // Negative pid targets the whole process group.
    process.kill(-current.child.pid, "SIGKILL");
  } catch {
    /* already gone — the close handler still runs */
  }
  return getScanStatus();
}

export function getScanStatus(): ScanStatus {
  if (!current) return IDLE;
  return {
    phase: current.phase,
    profile: current.profile,
    group: current.group,
    hosts: current.hosts,
    file: current.file,
    startedAt: current.startedAt,
    finishedAt: current.finishedAt,
    stats: current.stats,
    // Read live from the findings file Nuclei is still appending to.
    findings: current.path ? parseFindings(current.path) : [],
    log: current.log,
    error: current.error,
    command: [...current.command],
    exitCode: current.exitCode,
    observations: current.observations,
    output: current.outputEvents.map((event) => ({ ...event })),
  };
}
