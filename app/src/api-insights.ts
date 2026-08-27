import { json, query, request } from "./api-client";
import type { FindingGroupPage, FindingStatePage, InsightSync } from "./types";

const API = "/api/v1";

export type InsightSelector = Record<string, string | number | boolean | undefined>;

/**
 * One sync, previewed or performed.
 *
 * `choices` answers the identities the catalog gave more than one config item
 * for, keyed by identity — one account is the answer for every resource inside
 * it. A sync that pushes remembers each choice against the resources it decided,
 * so the same question is not asked twice; `repin` is the way back out of one
 * that has since become wrong.
 */
export type SyncRequest = {
  dryRun: boolean;
  choices?: Record<string, string>;
  repin?: boolean;
};

function syncBody(params: InsightSelector, sync: SyncRequest) {
  const config = Object.entries(sync.choices ?? {}).map(
    ([identity, id]) => `${identity}=${id}`,
  );
  return {
    ...params,
    "dry-run": sync.dryRun,
    ...(sync.repin ? { repin: true } : {}),
    ...(config.length > 0 ? { config } : {}),
  };
}

export function fetchFindingGroups(params?: InsightSelector): Promise<FindingGroupPage> {
  return request<FindingGroupPage>(`${API}/finding-group${query(params)}`);
}

export function fetchFindingStates(params?: InsightSelector): Promise<FindingStatePage> {
  return request<FindingStatePage>(`${API}/finding-state${query(params)}`);
}

export function syncFindings(params: InsightSelector, sync: SyncRequest): Promise<InsightSync> {
  return request<InsightSync>(`${API}/finding/sync`, json("POST", syncBody(params, sync)));
}

export function syncResources(params: InsightSelector, sync: SyncRequest): Promise<InsightSync> {
  return request<InsightSync>(`${API}/resource/sync`, json("POST", syncBody(params, sync)));
}
