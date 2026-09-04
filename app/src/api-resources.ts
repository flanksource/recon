// The resource listing's client. Separate from api.ts for the reason api-mutes
// is: that file is already at the size the repo splits at, and this shares the
// same fetch helpers so there is one way of reaching the API rather than two.

import { json, query, request } from "./api-client";
import { fetchFindings } from "./api-scans";
import type { Finding } from "./types";

const API = "/api/v1";

/** One thing a scan examined, whatever the verdict. */
export type Resource = {
  id: string;
  provider: string;
  scope?: string;
  uid: string;

  kind: string;
  type?: string;
  name?: string;
  service?: string;
  region?: string;

  targetId?: string;
  accountName?: string;
  /** Every engine that has described this resource, not the last one to. */
  engines?: string[];

  configType?: string;
  externalIds?: string[];
  /** The catalog config item finding sync attaches this resource's insights to. */
  configId?: string;
  configMatchMethod?: "automatic" | "manual";
  configRolledUp?: boolean;
  configServer?: string;

  tags?: string[];
  labels?: Record<string, string>;
  metadata?: Record<string, unknown>;

  state?: string;
  firstSeen?: string;
  lastSeen?: string;

  /** What is open against it now, counted by the server at read time. */
  findings: number;
  severities?: Record<string, number>;

  // DataTable's row type is constrained to Record<string, unknown>, and the
  // listing carries fields the browser does not model. Finding does the same.
  [key: string]: unknown;
};

/**
 * A page of resources and the total behind it.
 *
 * Resources are the one listing that pages, because the tab opens cold with no
 * filter and the first question asked of it is "what have I got" — to which
 * the first hundred of an unstated number is not a partial answer but a wrong
 * one.
 */
export type ResourcePage = {
  data: Resource[];
  page: { limit: number; offset: number; total: number };
};

export type LinkedConfig = {
  id: string;
  name: string;
  type: string;
  url: string;
  method?: "automatic" | "manual";
  rolledUp?: boolean;
  server?: string;
};

/** What is currently true about one check on one resource. */
export type FindingState = {
  id: string;
  resourceId: string;
  engine: string;
  checkId: string;
  status: string;
  severity: string;
  reason?: string;
  firstSeen: string;
  lastSeen: string;
  resolvedAt?: string;
  findingId?: string;
  occurrences: number;
};

export type ResourceSelector = Record<
  string,
  string | string[] | number | undefined
>;

export function fetchResources(
  params?: ResourceSelector,
): Promise<ResourcePage> {
  return request<ResourcePage>(`${API}/resource${query(params)}`);
}

export function fetchResource(id: string): Promise<Resource> {
  return request<Resource>(`${API}/resource/${encodeURIComponent(id)}`);
}

export function fetchResourceConfig(id: string): Promise<LinkedConfig | null> {
  return request<LinkedConfig | null>(
    `${API}/resource/${encodeURIComponent(id)}/config`,
  );
}

export async function removeResourceConfig(id: string): Promise<void> {
  await request(`${API}/resource/${encodeURIComponent(id)}/unlink-config`, {
    method: "POST",
  });
}

/**
 * The evidence behind a resource's open findings.
 *
 * A filter on the findings listing rather than a route under the resource:
 * `finding list --resource X` is the same query, and a second endpoint would be
 * a second implementation of it that could drift.
 */
export function fetchResourceFindings(id: string): Promise<Finding[]> {
  return fetchFindings({ resource: id });
}

/**
 * How a resource reads at a glance: failing, clean, or never checked.
 *
 * Three states rather than two, and the third is only answerable because
 * passing checks are recorded. Without them a bucket nothing has ever looked at
 * and a bucket that passes every check are the same empty row — which is the
 * failure mode this whole feature exists to remove, so the UI must not quietly
 * reintroduce it by rendering both as "clean".
 */
export function resourceStatus(
  resource: Resource,
  checks: number,
): "failing" | "clean" | "unchecked" {
  if (resource.findings > 0) return "failing";
  return checks > 0 ? "clean" : "unchecked";
}

export { json };
