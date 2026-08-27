// Wire types for the recon entity API.
//
// Every shape here is what `/api/v1/<entity>` actually returns — the Go types in
// internal/api are the source of truth and these mirror them.

import type { TargetCredentials } from "./credential-types";
import type { Profile } from "./engine-types";
export type {
  CredentialEnvVar,
  CredentialKeySelector,
  CredentialMutation,
  CredentialValueFrom,
  TargetCredentials,
} from "./credential-types";
export type {
  Engine,
  EngineKind,
  EngineOptionSchema,
  EngineOptions,
  EngineOptionVariant,
  Profile,
} from "./engine-types";
export type {
  Template,
  TemplateMetadata,
  TemplatePreview,
  TemplateRemediationMetadata,
  TemplateTag,
} from "./template-types";

export const CLASS_ORDER = [
  "public",
  "prod",
  "non-prod",
  "internal",
  "unclassified",
  "deactivated",
] as const;
export type TargetClass = (typeof CLASS_ORDER)[number];

// What a target addresses. A host is contacted over the network; a provider
// context carries provider-native scope arguments instead.
export const KIND_ORDER = ["host", "provider-context"] as const;
export type TargetKind = (typeof KIND_ORDER)[number];
export type CredentialMode = "ambient" | "configured";

// Absent means host: the server omits the field for one so an existing target
// document is unchanged by cloud accounts existing.
export const targetKind = (target: { kind?: TargetKind }): TargetKind =>
  target.kind ?? "host";

export function targetId(target: { id?: string }): string {
  if (!target.id) throw new Error("target response has no stable id");
  return target.id;
}

export function targetHost(target: { kind?: TargetKind; host?: string }): string {
  if (targetKind(target) !== "host" || !target.host) {
    throw new Error("host target response has no host");
  }
  return target.host;
}

// The profiles a target can opt into are whatever the server has stored, which
// is no longer a list short enough to keep here: nuclei ships focused profiles
// alongside its own, and a hardcoded pair would silently hide the rest from
// every control that offers them. Fetch with fetchProfiles({ kind: "scan" }).
export const FALLBACK_PROFILES = ["scan:nuclei:safe", "scan:nuclei:full"] as const;

// The server stamps `_id` onto rows in a list response so one is addressable
// without knowing which field is its key. A single get does not carry it, hence
// optional — prefer the entity's own key (host, id, kind:engine:name) wherever
// the value has to survive a round trip.
export type Identified = { _id?: string };

/**
 * Why the last probe of a host got no usable answer.
 *
 * Classified by the prober rather than pattern-matched out of the message here:
 * the wording of a Go dial error is not something the browser should have an
 * opinion about. Mirrors api.Failures() in internal/api/probe.go.
 */
export type ProbeFailure =
  | "dns"
  | "refused"
  | "unreachable"
  | "timeout"
  | "tls"
  | "http"
  | "other";

export type ObservedState = {
  first_observed?: string;
  last_seen?: string;
  last_attempt?: string;
  error?: string;
  failure?: ProbeFailure;
};

export type TargetDocument = {
  $schema: "../target.schema.json";
  version: number;
  id: string;
  host?: string;
  kind?: TargetKind;
  provider?: string;
  credentialMode?: CredentialMode;
  arguments?: Record<string, unknown>;
  credentials?: TargetCredentials;
  class: TargetClass;
  app?: string;
  cluster?: string;
  source?: string;
  profiles: string[];
  ports?: number[];
  tags: string[];
  notes?: string;
  reason?: string;
  observed?: ObservedState;
  network?: {
    ip?: string;
    ipv4?: string[];
    ipv6?: string[];
    cname?: string[];
    resolvers?: string[];
    open_ports?: number[];
    cdn?: { enabled: boolean; name?: string; type?: string };
    asn?: { number?: number; name?: string; country?: string; range?: string };
  };
  http?: {
    url?: string;
    scheme?: "http" | "https";
    port?: number;
    status_code?: number;
    title?: string;
    webserver?: string;
    content_type?: string;
    location?: string;
    response_time?: string;
    known_paths?: string[];
    login_methods?: string[];
    failed?: boolean;
  };
  tech?: {
    names?: string[];
    cpe?: Array<{ product?: string; vendor?: string; cpe: string }>;
  };
  tls?: Record<string, unknown>;
  scan?: { last_scan?: string; last_findings?: number };
};

export type Target = TargetDocument & Identified;
export type TargetRow = TargetDocument;

export type Inventory = {
  version: number;
  zones: string[];
  rows: TargetRow[];
  tagVocabulary: string[];
};

export type CuratedTarget = Pick<
  TargetDocument,
  | "class"
  | "app"
  | "cluster"
  | "source"
  | "profiles"
  | "ports"
  | "tags"
  | "notes"
  | "reason"
>;

export type TargetUpdate = CuratedTarget & {
  credentialMode?: CredentialMode;
  arguments?: Record<string, unknown>;
  credentials?: TargetCredentials | null;
};

// TargetSelector is the target list-options struct used by GET /target. Every
// value is comma-joined because that is how repeated CLI flags arrive over HTTP.
// Scan actions use RunTarget instead: its selectors are arrays in the POST body.
export type TargetSelector = {
  selector?: string;
  id?: string;
  provider?: string;
  class?: string;
  tags?: string;
  profiles?: string;
  hosts?: string;
  ports?: string;
  status?: string;
  "last-seen"?: string;
  live?: boolean;
};

// A selector that has been resolved and stored on a scan. It is not the request
// shape: the server parses the comma-joined query values into lists, and echoes
// them back that way. Use `selectorLabel` to render one.
export type StoredSelector = Record<string, string[] | string | boolean>;

/** A filter selection is filter key → chosen values, which is the query string. */
export type FilterSelection = Record<string, string[]>;

// One filter control as the listing's lookup describes it. The server owns the
// vocabulary — nothing here decides what a class or a tag can be.
export type FilterVocabulary = {
  key: string;
  label: string;
  options: string[];
  // How many values exist behind `options`. The lookup serves a capped head
  // set, so this is what lets the control say the rest are reachable by typing
  // rather than implying it listed everything.
  total: number;
  truncated: boolean;
};

export const SEVERITIES = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
  "unknown",
] as const;
export type Severity = (typeof SEVERITIES)[number];

export type SeverityCounts = Record<Severity, number>;

/**
 * OCSF's severity scale, which recon's ladder maps onto rung for rung.
 *
 * The integer is what a finding carries and what the server filters on;
 * `severityOf` renders it back into the vocabulary the UI groups and sorts by.
 * Fatal has no recon rung and reads as critical — a finding an engine called
 * the worst thing it found must not be filed under "nobody could classify it".
 */
export const OCSF_SEVERITY: Record<number, Severity> = {
  0: "unknown",
  1: "info",
  2: "low",
  3: "medium",
  4: "high",
  5: "critical",
  6: "critical",
};

export function severityOf(finding: {
  severity_id?: number;
}): Severity {
  return OCSF_SEVERITY[finding.severity_id ?? 0] ?? "unknown";
}

/** What a finding is about, in OCSF's words. */
export type FindingInfo = {
  uid?: string;
  title?: string;
  desc?: string;
  /** Recon's tags, projected. The engine's record class rides here too. */
  types?: string[];
  src_url?: string;
  uid_alt?: string;
};

export type OcsfProduct = {
  name?: string;
  vendor_name?: string;
  version?: string;
};

export type OcsfMetadata = {
  version?: string;
  event_code?: string;
  product?: OcsfProduct;
  /** Which OCSF profiles the record declares; prowler declares `cloud`. */
  profiles?: string[];
};

export type OcsfRemediation = {
  desc?: string;
  references?: string[];
};

export type OcsfCloud = {
  provider?: string;
  region?: string;
  account?: { uid?: string; name?: string; type?: string };
  org?: { uid?: string; name?: string };
};

export type OcsfCve = {
  uid?: string;
  title?: string;
  desc?: string;
  cvss?: { base_score?: number; vector_string?: string; severity?: string }[];
  /** OCSF carries the CWE both as an object and as a bare id. */
  cwe_uid?: string;
  cwe_url?: string;
  epss?: { score?: string; percentile?: number };
  references?: string[];
};

export type OcsfVulnerability = {
  title?: string;
  desc?: string;
  severity?: string;
  references?: string[];
  is_fix_available?: boolean;
  cve?: OcsfCve;
  cwe?: { uid?: string; caption?: string; src_url?: string };
  affected_packages?: {
    name?: string;
    version?: string;
    fixed_in_version?: string;
    purl?: string;
  }[];
};

/**
 * One piece of evidence for a finding.
 *
 * This is where the fat engine-specific payload lives now — nuclei's HTTP
 * exchange, inspec's failed assertions, trivy's cause metadata — bounded and
 * excluded from every list path, rather than a verbatim copy of the whole
 * engine record travelling with every row.
 *
 * `data` is OCSF's json_t: the engine's own shape, which the schema has no
 * names for. Render it as JSON rather than reaching for keys.
 */
export type NetworkEndpoint = {
  ip?: string;
  port?: number;
  hostname?: string;
  domain?: string;
  svc_name?: string;
};

export type Evidence = {
  name?: string;
  uid?: string;
  url?: { url_string?: string };
  http_request?: { args?: string; http_method?: string; url?: { url_string?: string } };
  http_response?: { code?: number; message?: string; status?: string };
  // The address that actually answered, which a URL does not say: behind a load
  // balancer or a wildcard record, which host served the request is what makes
  // a finding reproducible.
  src_endpoint?: NetworkEndpoint;
  dst_endpoint?: NetworkEndpoint;
  data?: unknown;
};

/**
 * One result an engine reported, stored as an OCSF Detection Finding.
 *
 * The OCSF attributes sit at the top level under their published names — this
 * is the record the schema defines, not a recon invention with OCSF projected
 * onto it — beside the identity recon needs in order to track a finding over
 * time. A mute expression addressing `finding.finding_info.title` is addressing
 * the same names as this type.
 *
 * The index signature stays: `unmapped` aside, nuclei emits template-specific
 * keys the details pane renders without knowing them in advance.
 */
export type Finding = {
  id?: string;
  scanId: string;
  // The line of the engine's own findings.jsonl this came from. Runs whose mute
  // rules removed something have gaps here rather than renumbered survivors, so
  // the artifact and the database still address the same evidence.
  lineNo: number;
  // The inventory subject the finding was attributed to. Distinct from host,
  // which is the provider's own identity in the evidence — for a cloud account
  // they differ, and a mute rule's target scope matches on this one.
  targetId?: string;

  /** The check this is an instance of. Was `templateId`. */
  checkId: string;
  /** Which scanner produced it. Was `type`, which named neither a type nor a kind. */
  engine?: string;
  /** `fail` or `manual`; absent means fail. Recon's vocabulary, not the engine's. */
  verdict?: string;

  host: string;
  matchedAt: string;
  tags: string[];

  // The OCSF envelope.
  class_uid?: number;
  category_uid?: number;
  type_uid?: number;
  activity_id?: number;
  severity_id?: number;
  /** OCSF's caption of severity_id — "High", not "high". Use `severityOf`. */
  severity?: string;
  status_id?: number;
  status?: string;
  /** The engine's own status code. prowler writes FAIL or MANUAL here. */
  status_code?: string;
  status_detail?: string;
  /** Epoch milliseconds, or absent when the engine reported no time. */
  time?: number;

  /** Why it matters, in OCSF's words. prowler writes its risk into risk_details. */
  impact?: string;
  impact_id?: number;
  confidence_id?: number;

  finding_info?: FindingInfo;
  metadata?: OcsfMetadata;
  remediation?: OcsfRemediation;
  cloud?: OcsfCloud;
  vulnerabilities?: OcsfVulnerability[];
  risk_details?: string;
  evidences?: Evidence[];
  /** Whatever the engine reported that the schema has no name for. */
  unmapped?: Record<string, unknown>;

  /**
   * The subjects the evidence names, in the engine's own order. Resources[0] is
   * the one the check has a verdict about; the rest are context. The server
   * always sends at least one, synthesising it from the finding's own identity
   * for engines that name none.
   */
  resources?: ResourceRef[];
  /** True when the row describes the check rather than an observation. */
  synthetic?: boolean;
  [key: string]: unknown;
};

/** What a finding calls itself, falling back to the check id. */
export function findingTitle(finding: Finding): string {
  return finding.finding_info?.title || finding.checkId;
}

/**
 * One thing a finding is about.
 *
 * `uid` is the provider's own identifier and is frequently not human-readable —
 * a GCP firewall's uid is an opaque number while its name is `tailscale-router`
 * — so render `name` and fall back to `uid`, never the other way round.
 */
export type ResourceRef = {
  id?: string;
  provider: string;
  scope?: string;
  uid: string;
  name?: string;
  type?: string;
  service?: string;
  region?: string;
};

export type FindingGroup = {
  engine: string;
  checkId: string;
  name: string;
  severity: Severity;
  affected: number;
  statuses: Record<string, number>;
  lastSeen: string;
  [key: string]: unknown;
};

export type FindingState = {
  id: string;
  resourceId: string;
  engine: string;
  checkId: string;
  status: string;
  severity: Severity;
  reason?: string;
  firstSeen: string;
  lastSeen: string;
  lastOpenAt?: string;
  resolvedAt?: string;
  findingId?: string;
  occurrences: number;
  resource?: ResourceRef & { findings: number; [key: string]: unknown };
  finding?: Finding;
  [key: string]: unknown;
};

export type FindingGroupPage = {
  data: FindingGroup[];
  page: { limit: number; offset: number; total: number };
};

export type FindingStatePage = {
  data: FindingState[];
  page: { limit: number; offset: number; total: number };
};

/** What to show for a resource: its name where it has one, its uid otherwise. */
export function resourceLabel(resource: ResourceRef): string {
  return resource.name || resource.uid;
}

// Template is one check a scan engine could run. The catalogue is read from the
// installed templates rather than the database, so these are the engine's own
// fields — renaming them would make it harder to trace a finding back to what
// produced it.
export type ScanPhase = "idle" | "queued" | "running" | "done" | "failed" | "cancelled";

export const TERMINAL_PHASES: ScanPhase[] = ["done", "failed", "cancelled"];

// What a run put on the wire, counted from the engine's per-request hooks. It
// covers every request the scan issued, including the overwhelming majority
// that matched nothing and so left no finding behind.
export type HTTPStats = {
  requests: number;
  responses: number;
  failed: number;
  bytes: number;
  statusCodes: Record<string, number>;
  protocols: Record<string, number>;
  errors: Record<string, number>;
  waf: Record<string, number>;
};

export type ScanStats = {
  requests: number;
  total: number;
  percent: number;
  rps: number;
  matched: number;
  errors: number;
  hosts: number;
  templates: number;
  duration: string;

  // Checks that ran and returned a clean verdict. Only compliance engines count
  // it: a benchmark control and a Prowler check each have a verdict, while a
  // network scanner's template that matched nothing did not "pass". Read it
  // only when `passRecorded` says a count was taken — zero otherwise means
  // nobody counted, not that nothing passed.
  passed: number;
  passRecorded?: boolean;

  // Absent for an engine that does not report its requests individually — which
  // is not the same as a scan that sent nothing.
  http?: HTTPStats;
};

// One file in a run's retained artifact directory.
export type ScanFile = {
  name: string;
  size: number;
  modified: string;
};

export type ScanFiles = {
  scanId: string;
  path: string;
  files: ScanFile[];
};

export type Scan = Identified & {
  id: string;
  name: string;
  engine: string;
  engineVersion?: string;
  profile: string;
  selector: StoredSelector;
  // A human-readable rendering of the selector, e.g. "class non-prod". The
  // server derives it so the CLI and the table describe a scan identically.
  selectorLabel: string;
  endpointCount: number;
  phase: ScanPhase;
  startedAt: string;
  finishedAt?: string;
  durationMs: number;
  command?: string[];
  exitCode?: number;
  error?: string;
  findings: number;
  // Findings a mute rule removed after the engine reported them. They are not
  // recorded, so without this a filtered run looks like a clean one. Checks a
  // rule stopped from running are not counted — the run's mutes.json names the
  // rules that did that.
  muted?: number;
  severities: SeverityCounts;
  stats?: ScanStats;
  hosts: string[];
  // The retained artifact directory on disk. Absent for runs made before
  // results were kept.
  resultPath?: string;
  outputCaptured?: boolean;
  stdout?: string;
  stderr?: string;
  stdoutTruncated?: boolean;
  stderrTruncated?: boolean;
};

export type ScanOutputEvent = {
  sequence: number;
  timestamp: string;
  stream: "stdout" | "stderr" | "system";
  text: string;
};

// ScanStatus is the live snapshot pushed over SSE: a scan plus the streaming
// fields that only exist while it runs.
export type ScanStatus = Scan & {
  running: boolean;
  log: string;
  output: ScanOutputEvent[];
};

// One catalog config item a sync attached insights to.
export type InsightConfig = {
  id: string;
  name?: string;
  type?: string;
  insights: number;
  // True when this config is the cluster, account or project containing the
  // thing the finding was about, rather than that thing itself.
  rolledUp?: boolean;
  // True when a person chose this config item rather than the ladder finding it.
  pinned?: boolean;
};

// One config item an ambiguous identity could be attached to.
export type InsightChoice = {
  id: string;
  name?: string;
  type?: string;
  /** Nothing in the catalog contains this item — it is the top of its tree. */
  root?: boolean;
  /** Offered because it contains the matches, not because it carried the identity. */
  ancestor?: boolean;
  deleted?: boolean;
};

// An identity more than one config item carries. Ambiguity is not a miss: the
// identity is right and the catalog holds several things wearing it, so nothing
// is attached until somebody says which one.
export type InsightAmbiguity = {
  identity: string;
  type?: string;
  /** The identity names the account, project or cluster, not the finding's subject. */
  scope?: boolean;
  states: number;
  /** A bounded sample of the affected resources; `states` is the true count. */
  resources?: string[];
  chosen?: string;
  options: InsightChoice[];
};

// A current state nothing in the Mission Control catalog claims, and every identity
// that was tried for it.
export type InsightUnresolved = {
  finding: string;
  host?: string;
  severity?: Severity;
  tried: string[];
  reason: string;
};

// The result of previewing or syncing current resource/check states.
export type InsightSync = {
  context?: string;
  server?: string;
  agent: string;
  dryRun?: boolean;
  matchedResources: number;
  matchedStates: number;
  eligible: number;
  skipped: number;
  open: number;
  resolved: number;
  silenced: number;
  direct: number;
  rolledUp: number;
  /** States attached through a choice an earlier sync remembered. */
  pinned: number;
  pushed: number;
  configs: InsightConfig[];
  unresolved: InsightUnresolved[];
  ambiguous: InsightAmbiguity[];
};

export type Zone = Identified & { zone: string };

export type DiscoveredHost = {
  host: string;
  engines: string[];
  live: boolean;
};

export type ProbeResult = {
  host: string;
  url?: string;
  up: boolean;
  statusCode?: number;
  responseTimeMs: number;
  ip?: string;
  contentType?: string;
  error?: string;
  /** Why `error` happened. Absent whenever the host answered. */
  failure?: ProbeFailure;
  /** When this host finished, which is not when the run started. */
  probedAt?: string;
  /** The host's inventory record was rewritten from this result. */
  updated: boolean;
};

// One liveness sweep. Unlike before it is a record and not just a response, so
// it can be followed while it runs and read back afterwards.
//
// `id` is also the id of the task group the run drives, so /api/v1/tasks/{id}
// and /api/v1/probe/{id} address the same sweep.
export type ProbeRun = Identified & {
  id: string;
  selector: StoredSelector;
  selectorLabel: string;
  phase: ScanPhase;
  ranAt: string;
  finishedAt?: string;
  durationMs: number;
  // How many hosts the run set out to probe. `results` is shorter while it is
  // still going, and that difference is the progress.
  total: number;
  live: number;
  updated: number;
  error?: string;
  results: ProbeResult[];
};

export type Discover = Identified & {
  id: string;
  chain: string;
  // The profile each engine in the chain ran with, keyed by engine name. A
  // sweep drives several engines and each can be configured separately, so one
  // name would misreport any run that overrode one of them.
  profiles: Record<string, string>;
  input: Record<string, unknown>;
  ranAt: string;
  durationMs: number;
  failed: boolean;
  hosts: DiscoveredHost[];
  error?: string;
  log: string;
};

// Flattened shape handed to DataTable so its timestamp/tags/status column kinds
// can read observed state by key. The index signature satisfies DataTable's
// `Record<string, unknown>` constraint.
export type TableRow = TargetRow & {
  first_observed?: string;
  last_seen?: string;
  last_scan?: string;
  last_status?: number;
  /** Set only while the host's last probe failed; clears the moment it answers. */
  failure?: ProbeFailure;
  last_error?: string;
  response_time?: string;
  open_ports?: string[];
  known_paths?: string[];
  login_methods?: string[];
  findings?: number;
  dirty: boolean;
  [key: string]: unknown;
};

export function curatedTarget(target: TargetDocument): CuratedTarget {
  const {
    class: targetClass,
    app,
    cluster,
    source,
    profiles,
    ports,
    tags,
    notes,
    reason,
  } = target;
  return {
    class: targetClass,
    app,
    cluster,
    source,
    profiles,
    ports,
    tags,
    notes,
    reason,
  };
}

// A profile's address, computed rather than read off the payload so it is the
// same value whether the profile came from a list or from a single get.
export function profileId(
  profile: Pick<Profile, "kind" | "engine" | "name">,
): string {
  return `${profile.kind}:${profile.engine}:${profile.name}`;
}

export function emptySeverities(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
}
