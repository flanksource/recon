// Read helpers for scan runs under nuclei/results/. Nuclei writes one JSON object per
// line (JSONL) plus a .sarif and .txt; we parse the JSONL. Read-only.
import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { resolve, basename } from "node:path";

// nuclei/app/server -> nuclei/results
const RESULTS_DIR = resolve(import.meta.dirname, "../..", "results");

const SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"] as const;
export type Severity = (typeof SEVERITIES)[number];

export type Finding = {
  templateId: string;
  name: string;
  severity: Severity;
  host: string;
  matchedAt: string;
  matcherName?: string;
  type?: string;
  tags: string[];
  timestamp?: string;
  extracted?: string[];
  remediation?: string;
  reference?: string[];
  curl?: string;
  request?: string;
  response?: string;
};

export type ScanRun = {
  file: string;
  profile: string;
  group: string;
  startedAt: string; // parsed from filename, ISO-ish
  mtime: string;
  findings: number;
  hosts: string[];
  severities: Record<Severity, number>;
};

// safe-non-prod-20260808-231840.jsonl -> { profile, group, startedAt }
function parseName(file: string): { profile: string; group: string; startedAt: string } {
  const m = file.match(/^(.+?)-(.+)-(\d{8})-(\d{6})\.jsonl$/);
  if (!m) return { profile: "?", group: basename(file, ".jsonl"), startedAt: "" };
  const [, profile, group, d, t] = m;
  const startedAt = `${d.slice(0, 4)}-${d.slice(4, 6)}-${d.slice(6, 8)}T${t.slice(0, 2)}:${t.slice(2, 4)}:${t.slice(4, 6)}`;
  return { profile, group, startedAt };
}

function parseLines(path: string): Record<string, unknown>[] {
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => {
      try {
        return JSON.parse(l) as Record<string, unknown>;
      } catch {
        return null;
      }
    })
    .filter((v): v is Record<string, unknown> => v !== null);
}

function toFinding(raw: Record<string, unknown>): Finding {
  const info = (raw.info ?? {}) as Record<string, unknown>;
  const sev = String(info.severity ?? "unknown").toLowerCase();
  return {
    templateId: String(raw["template-id"] ?? ""),
    name: String(info.name ?? raw["template-id"] ?? ""),
    severity: (SEVERITIES as readonly string[]).includes(sev)
      ? (sev as Severity)
      : "unknown",
    host: String(raw.host ?? raw.url ?? ""),
    matchedAt: String(raw["matched-at"] ?? raw.url ?? ""),
    matcherName: raw["matcher-name"] ? String(raw["matcher-name"]) : undefined,
    type: raw.type ? String(raw.type) : undefined,
    tags: Array.isArray(info.tags) ? (info.tags as string[]) : [],
    timestamp: raw.timestamp ? String(raw.timestamp) : undefined,
    extracted: Array.isArray(raw["extracted-results"])
      ? (raw["extracted-results"] as string[])
      : undefined,
    remediation: info.remediation ? String(info.remediation) : undefined,
    reference: Array.isArray(info.reference) ? (info.reference as string[]) : undefined,
    curl: raw["curl-command"] ? String(raw["curl-command"]) : undefined,
    request: raw.request ? String(raw.request) : undefined,
    response: raw.response ? String(raw.response) : undefined,
  };
}

function emptySeverities(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
}

// Findings from any nuclei JSONL on disk — used for finished runs under results/ and,
// while a scan is in flight, for the partially-written file of the live run.
export function parseFindings(path: string): Finding[] {
  if (!existsSync(path)) return [];
  return parseLines(path).map(toFinding);
}

export function listScans(): ScanRun[] {
  if (!existsSync(RESULTS_DIR)) return [];
  const files = readdirSync(RESULTS_DIR).filter((f) => f.endsWith(".jsonl"));
  const runs = files.map((file) => {
    const path = resolve(RESULTS_DIR, file);
    const findings = parseFindings(path);
    const severities = emptySeverities();
    const hosts = new Set<string>();
    for (const f of findings) {
      severities[f.severity]++;
      if (f.host) hosts.add(f.host);
    }
    const { profile, group, startedAt } = parseName(file);
    return {
      file,
      profile,
      group,
      startedAt,
      mtime: statSync(path).mtime.toISOString(),
      findings: findings.length,
      hosts: [...hosts].sort(),
      severities,
    } satisfies ScanRun;
  });
  // Newest first.
  return runs.sort((a, b) => b.mtime.localeCompare(a.mtime));
}

export function readScan(file: string): { file: string; findings: Finding[] } {
  // Guard against path traversal — only a bare basename under results/ is allowed.
  const safe = basename(file);
  const path = resolve(RESULTS_DIR, safe);
  if (!path.startsWith(RESULTS_DIR) || !existsSync(path)) {
    throw new Error(`scan not found: ${safe}`);
  }
  return { file: safe, findings: parseFindings(path) };
}
