import { json, query, request } from "./api-client";
import type { FindingGroupPage, FindingStatePage, InsightSync } from "./types";

const API = "/api/v1";

export type InsightSelector = Record<string, string | number | boolean | undefined>;

export function fetchFindingGroups(params?: InsightSelector): Promise<FindingGroupPage> {
  return request<FindingGroupPage>(`${API}/finding-group${query(params)}`);
}

export function fetchFindingStates(params?: InsightSelector): Promise<FindingStatePage> {
  return request<FindingStatePage>(`${API}/finding-state${query(params)}`);
}

export function syncFindings(params: InsightSelector, dryRun: boolean): Promise<InsightSync> {
  return request<InsightSync>(
    `${API}/finding/sync`,
    json("POST", { ...params, "dry-run": dryRun }),
  );
}

export function syncResources(params: InsightSelector, dryRun: boolean): Promise<InsightSync> {
  return request<InsightSync>(
    `${API}/resource/sync`,
    json("POST", { ...params, "dry-run": dryRun }),
  );
}
