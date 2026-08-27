import type { ScanReportData } from "../reports/scan-report-types";
import { overrideFields, scanFileUrl } from "./api-helpers";
import type { EngineConfig, RunTarget } from "./api-run-types";
import { json, query, request } from "./api-client";
import { reportDataUrl } from "./scan-report";
import type {
  Finding,
  Scan,
  ScanFiles,
  ScanStatus,
} from "./types";

const API = "/api/v1";

export type FindingPage = {
  data: Finding[];
  page: { limit: number; offset: number; total: number };
};

export type FindingSelector = {
  scan?: string | string[];
  target?: string | string[];
  severity?: string | string[];
  host?: string | string[];
  template?: string | string[];
  tag?: string | string[];
  resource?: string | string[];
  search?: string;
  sort?: string;
  order?: "asc" | "desc";
  limit?: number;
  offset?: number;
};

export function fetchScans(params?: {
  engine?: string;
  profile?: string;
  phase?: string;
  since?: string;
  severity?: string;
  limit?: number;
}): Promise<Scan[]> {
  return request<Scan[]>(`${API}/scan${query(params)}`);
}

export function fetchScan(id: string): Promise<Scan> {
  return request<Scan>(`${API}/scan/${encodeURIComponent(id)}`);
}

export function fetchScanFiles(id: string): Promise<ScanFiles> {
  return request<ScanFiles>(`/api/scan/${encodeURIComponent(id)}/files`);
}

export async function fetchScanParameters(
  id: string,
): Promise<Record<string, unknown>> {
  const parameters = await request<unknown>(scanFileUrl(id, "config.json"));
  if (!parameters || typeof parameters !== "object" || Array.isArray(parameters)) {
    throw new Error(`scan ${id} config.json must contain a JSON object`);
  }
  return parameters as Record<string, unknown>;
}

export function fetchReportData(id: string): Promise<ScanReportData> {
  return request<ScanReportData>(reportDataUrl(id));
}

export function fetchFindingPage(params?: FindingSelector): Promise<FindingPage> {
  return request<FindingPage>(`${API}/finding${query(params)}`);
}

export async function fetchFindings(params?: FindingSelector): Promise<Finding[]> {
  return (await fetchFindingPage(params)).data;
}

export function fetchFinding(id: string): Promise<Finding> {
  return request<Finding>(`${API}/finding/${encodeURIComponent(id)}`);
}

export function fetchScanStatus(): Promise<ScanStatus> {
  return request<ScanStatus>("/api/scan/current");
}

export const SCAN_EVENTS_URL = "/api/scan/events";

export function startScan(args: {
  target: RunTarget;
  engine: string;
  profile: string;
  discoveryProfiles?: string[];
  discoveryEngines?: string[];
  override?: EngineConfig;
  discoveryOverride?: Record<string, EngineConfig>;
  confirm?: boolean;
  noMutes?: boolean;
}): Promise<Scan> {
  return request<Scan>(
    `${API}/scan`,
    json("POST", {
      ...args.target,
      engine: args.engine,
      profile: args.profile,
      "discovery-profile": args.discoveryProfiles ?? ["default"],
      ...(args.discoveryEngines?.length
        ? { "discovery-engine": args.discoveryEngines }
        : {}),
      ...overrideFields("override", args.override),
      ...overrideFields("discovery-override", args.discoveryOverride),
      confirm: args.confirm ?? false,
      "no-mutes": args.noMutes ?? false,
      wait: false,
    }),
  );
}

export function cancelScan(): Promise<ScanStatus> {
  return request<ScanStatus>("/api/scan/cancel", { method: "POST" });
}
