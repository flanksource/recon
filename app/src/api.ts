// Client for the recon entity API.
//
// Every resource is served at /api/v1/<entity> from the same declaration that
// generates the CLI, so a filter here and a flag on `reconctl` are the same
// operation. The two hand-written routes — the scan event stream and the target
// edit schema — are the ones the entity layer cannot express.

import type {
  CuratedTarget,
  Discover,
  Engine,
  Finding,
  Profile,
  ProbeRun,
  Scan,
  ScanStatus,
  Target,
  TargetDocument,
  TargetSelector,
  Template,
  TemplatePreview,
  FilterVocabulary,
  Zone,
} from "./types";
import { curatedTarget } from "./types";

const API = "/api/v1";

// The executor reports a command failure as 200 with success:false, so the
// status code alone does not tell us whether the call worked.
type ExecutorFailure = { success?: boolean; error?: string; message?: string };

async function request<T>(
  path: string,
  init?: RequestInit,
  ...rest: never[]
): Promise<T> {
  void rest;
  const method = init?.method ?? "GET";
  const res = await fetch(path, init);

  let body: unknown = null;
  const text = await res.text();
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      throw new Error(
        `${method} ${path} returned invalid JSON: ${text.slice(0, 200)}`,
      );
    }
  }

  const failure = body as ExecutorFailure | null;
  if (!res.ok) {
    throw new Error(
      failure?.error ??
        failure?.message ??
        `${method} ${path} failed: ${res.status}`,
    );
  }
  if (failure && typeof failure === "object" && failure.success === false) {
    throw new Error(
      failure.error ?? failure.message ?? `${method} ${path} failed`,
    );
  }
  return body as T;
}

function query(params: Record<string, unknown> | undefined): string {
  if (!params) return "";
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (
      value === undefined ||
      value === null ||
      value === "" ||
      value === false
    )
      continue;
    search.set(key, Array.isArray(value) ? value.join(",") : String(value));
  }
  const encoded = search.toString();
  return encoded ? `?${encoded}` : "";
}

function json(method: string, body: unknown): RequestInit {
  return {
    method,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  };
}

// ---------------------------------------------------------------- filters

// The lookup is a convention on every listing rather than a route of its own:
// `?__lookup=filters` asks what the listing can be narrowed by instead of
// returning rows. It is answered from the same declaration that generates the
// query parameters, so a control can never offer a filter the server does not
// have.
type LookupFilter = {
  label?: string;
  total?: number;
  truncated?: boolean;
  // Keyed by the value the filter sends; the value is a rendered node the
  // filter bar does not need, because these values are their own labels.
  options?: Record<string, unknown>;
};

type LookupResponse = { filters?: Record<string, LookupFilter> };

function lookupURL(
  entity: string,
  params: Record<string, string> = {},
): string {
  return `${API}/${entity}${query({ __lookup: "filters", ...params })}`;
}

function optionValues(filter: LookupFilter): string[] {
  return Object.keys(filter.options ?? {});
}

export async function fetchFilters(
  entity: string,
): Promise<FilterVocabulary[]> {
  const response = await request<LookupResponse>(lookupURL(entity));
  return Object.entries(response.filters ?? {}).map(([key, filter]) => ({
    key,
    label: filter.label ?? key,
    options: optionValues(filter),
    total: filter.total ?? optionValues(filter).length,
    truncated: filter.truncated ?? false,
  }));
}

// A search is answered by the server rather than by narrowing what was already
// loaded: the head set is capped, so the values past it exist only in the
// database until someone types.
export async function fetchFilterOptions(
  entity: string,
  key: string,
  search: string,
): Promise<string[]> {
  const response = await request<LookupResponse>(
    lookupURL(entity, { __lookup_filter: key, __lookup_q: search }),
  );
  return optionValues(response.filters?.[key] ?? {});
}

// ---------------------------------------------------------------- targets

export function fetchTargets(selector?: TargetSelector): Promise<Target[]> {
  return request<Target[]>(`${API}/target${query(selector)}`);
}

export function fetchTarget(host: string): Promise<Target> {
  return request<Target>(`${API}/target/${encodeURIComponent(host)}`);
}

// The edit form needs constraints the list surface cannot express — conditional
// requirements, formats, readOnly — so the Draft 2020-12 schema is served whole
// on its own route rather than derived from the entity.
export function fetchTargetSchema(): Promise<Record<string, unknown>> {
  return request<Record<string, unknown>>("/api/schema/target");
}

// A save replaces the curated fields wholesale; the machine-owned sections are
// discovery's and are never sent. Always send every curated field: omitting one
// clears it rather than leaving it alone.
export function saveTarget(
  host: string,
  curated: CuratedTarget,
): Promise<Target> {
  return request<Target>(
    `${API}/target`,
    json("PUT", { ...curated, id: host }),
  );
}

// Classifying a host a sweep found is a create, not an edit: an update refuses
// a host that is not in the inventory, because a curated record it would have
// to invent is exactly what nobody asked for.
export function createTarget(
  host: string,
  curated: CuratedTarget,
): Promise<Target> {
  return request<Target>(`${API}/target`, json("POST", { ...curated, host }));
}

export async function saveTargets(
  rows: TargetDocument[],
  isNew: (host: string) => boolean = () => false,
): Promise<Target[]> {
  const saved: Target[] = [];
  for (const row of rows) {
    const write = isNew(row.host) ? createTarget : saveTarget;
    try {
      saved.push(await write(row.host, curatedTarget(row)));
    } catch (error) {
      throw new Error(
        `saved ${saved.length} target(s); ${row.host} failed: ${(error as Error).message}`,
      );
    }
  }
  return saved;
}

// ---------------------------------------------------------------- zones

export function fetchZones(): Promise<Zone[]> {
  return request<Zone[]>(`${API}/zone`);
}

export function addZone(zone: string): Promise<Zone> {
  return request<Zone>(`${API}/zone`, json("POST", { zone }));
}

export function deleteZone(zone: string): Promise<void> {
  return request<void>(`${API}/zone/${encodeURIComponent(zone)}`, {
    method: "DELETE",
  });
}

// ---------------------------------------------------------------- engines

export function fetchEngines(kind?: "discovery" | "scan"): Promise<Engine[]> {
  return request<Engine[]>(`${API}/engine${query({ kind })}`);
}

export function fetchEngine(name: string): Promise<Engine> {
  return request<Engine>(`${API}/engine/${encodeURIComponent(name)}`);
}

// ---------------------------------------------------------------- profiles

export function fetchProfiles(params?: {
  kind?: string;
  engine?: string;
}): Promise<Profile[]> {
  return request<Profile[]>(`${API}/profile${query(params)}`);
}

export function saveProfile(profile: {
  kind: string;
  engine: string;
  name: string;
  config: Record<string, unknown>;
  comment?: string;
}): Promise<Profile> {
  return request<Profile>(`${API}/profile`, json("POST", profile));
}

export function deleteProfile(id: string): Promise<void> {
  return request<void>(`${API}/profile/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

// ---------------------------------------------------------------- templates

export function fetchTemplates(params?: {
  engine?: string;
  severity?: string;
  type?: string;
  tag?: string;
  author?: string;
  profile?: string;
  search?: string;
  limit?: number;
}): Promise<Template[]> {
  return request<Template[]>(`${API}/template${query(params)}`);
}

// Previews a configuration that has not been saved.
//
// A POST because the subject is the draft in the form, not a stored profile:
// the whole point is to answer "what would this change run" without having to
// save it first. A stored profile is previewed with
// fetchTemplates({ profile }) instead.
export function previewTemplates(args: {
  engine?: string;
  config: Record<string, unknown>;
}): Promise<TemplatePreview> {
  return request<TemplatePreview>(
    "/api/template/preview",
    json("POST", { engine: args.engine ?? "nuclei", config: args.config }),
  );
}

// ---------------------------------------------------------------- scans

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

// Findings are queried rather than read out of a result file, so the same call
// drills into one scan or compares a template across every run.
export function fetchFindings(params: {
  scan?: string;
  severity?: string;
  host?: string;
  template?: string;
  tag?: string;
  limit?: number;
}): Promise<Finding[]> {
  return request<Finding[]>(`${API}/finding${query(params)}`);
}

// The current (or last) scan. The event stream replays this to every new
// subscriber; this route exists for the first paint and for tests without an
// EventSource.
export function fetchScanStatus(): Promise<ScanStatus> {
  return request<ScanStatus>("/api/scan/current");
}

export const SCAN_EVENTS_URL = "/api/scan/events";

// Starts a scan over everything the selector matches and returns the created
// scan — not a live status, which arrives on the event stream. `confirm`
// authorises an intrusive scan of prod, public or unclassified hosts; the
// server refuses without it and names the hosts. `wait` is false so the call
// returns as soon as the run starts.
export function startScan(args: {
  target: RunTarget;
  engine: string;
  profile: string;
  discoveryProfiles?: string[];
  /** Which engines sweep before the scan. Empty runs the ones the sweep needs. */
  discoveryEngines?: string[];
  /** Run-only scan configuration, layered over the profile without saving it. */
  override?: EngineConfig;
  /** Run-only discovery configuration, keyed by engine. */
  discoveryOverride?: Record<string, EngineConfig>;
  confirm?: boolean;
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
      wait: false,
    }),
  );
}

export function cancelScan(): Promise<ScanStatus> {
  return request<ScanStatus>("/api/scan/cancel", { method: "POST" });
}

// ---------------------------------------------------------------- discovery

export function fetchDiscoveries(params?: {
  chain?: string;
  since?: string;
  limit?: number;
}): Promise<Discover[]> {
  return request<Discover[]>(`${API}/discover${query(params)}`);
}

// The most recent sweep, or null when none has run. This is the cached view the
// discover dialog opens with.
export async function fetchLatestDiscovery(): Promise<Discover | null> {
  const [latest] = await fetchDiscoveries({ limit: 1 });
  return latest ?? null;
}

// Runs a sweep. With no selector it enumerates from the configured zones;
// with one it re-probes just those targets.
export type RunTarget = {
  selector?: string;
  host?: string[];
  domain?: string[];
  cidr?: string[];
};

// One engine's configuration: the keys its stored profile holds.
export type EngineConfig = Record<string, unknown>;

// Run-only configuration is sent as a nested object and omitted when empty.
//
// The server takes it as one JSON-encoded parameter rather than a repeatable
// key=value flag, because a flag value is a string and `50` and `"50"` are not
// the same thing to an engine's schema. Sending the object is what keeps the
// types the form produced; an empty one is dropped so a run that customises
// nothing says so.
function overrideFields(
  field: string,
  value: Record<string, unknown> | undefined,
): Record<string, unknown> {
  return value && Object.keys(value).length > 0 ? { [field]: value } : {};
}

// `profile` is a list because a sweep runs several engines: a bare name applies
// to all of them and `engine=name` overrides one, which is the same grammar
// `reconctl discover --profile` takes. `engine` chooses which of them run at
// all, and `override` configures them for this sweep only.
// ---------------------------------------------------------------- probes

// Re-probes inventory targets and refreshes their liveness, status code and
// response time. Unlike `reconctl ping` this takes a selector rather than a
// URL — the server will only reach hosts the inventory already knows.
export function probeTargets(
  target: RunTarget & { timeout?: string; concurrency?: number } = {},
): Promise<ProbeRun> {
  return request<ProbeRun>(`${API}/probe`, json("POST", target));
}

export function runDiscovery(
  target: RunTarget & {
    profile?: string[];
    engine?: string[];
    override?: Record<string, EngineConfig>;
  } = {},
): Promise<Discover> {
  const { override, ...rest } = target;
  return request<Discover>(
    `${API}/discover`,
    json("POST", { ...rest, ...overrideFields("override", override) }),
  );
}
