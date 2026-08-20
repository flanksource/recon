// Wire types for the recon entity API.
//
// Every shape here is what `/api/v1/<entity>` actually returns — the Go types in
// internal/api are the source of truth and these mirror them.

export const CLASS_ORDER = [
  "public",
  "prod",
  "non-prod",
  "internal",
  "unclassified",
  "deactivated",
] as const;
export type TargetClass = (typeof CLASS_ORDER)[number];

// What a target addresses. A host is something on the network with an address
// and ports; a gcp-project is a cloud account audited through an API, which is
// why it has neither. Mirrors api.TargetKinds() in internal/api/target.go.
export const KIND_ORDER = ["host", "gcp-project"] as const;
export type TargetKind = (typeof KIND_ORDER)[number];

// Absent means host: the server omits the field for one so an existing target
// document is unchanged by cloud accounts existing.
export const targetKind = (target: { kind?: TargetKind }): TargetKind =>
  target.kind ?? "host";

// The profiles a target can opt into are whatever the server has stored, which
// is no longer a list short enough to keep here: nuclei ships focused profiles
// alongside its own, and a hardcoded pair would silently hide the rest from
// every control that offers them. Fetch with fetchProfiles({ kind: "scan" }).
export const FALLBACK_PROFILES = ["safe", "full"] as const;

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
  version: 1;
  host: string;
  kind?: TargetKind;
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

// TargetSelector is the target list-options struct, and it is also what selects
// the endpoints a scan runs against — the same filter drives the table, the
// query string and the scan. Every value is a comma-joined list because that is
// how the CLI's repeated flags arrive over HTTP.
export type TargetSelector = {
  selector?: string;
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

// Findings keep an index signature: nuclei emits template-specific keys the
// details pane renders without knowing them in advance.
export type Finding = {
  _id?: string;
  scanId: string;
  lineNo: number;
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
  /** The engine's original record, kept verbatim. */
  raw?: Record<string, unknown>;
  [key: string]: unknown;
};

// Template is one check a scan engine could run. The catalogue is read from the
// installed templates rather than the database, so these are the engine's own
// fields — renaming them would make it harder to trace a finding back to what
// produced it.
export type Template = Identified & {
  id: string;
  name: string;
  engine: string;
  severity: Severity;
  type: string;
  tags: string[];
  authors: string[];
  path: string;
  description?: string;
  remediation?: string;
  reference?: string[];
  cveId?: string;
  cvssScore?: number;
  maxRequests?: number;
  // Options a profile must enable before this template runs at all.
  requires?: string[];
};

export type TemplateTag = { tag: string; count: number };

// TemplatePreview is what a profile configuration would run, answered before it
// runs. Counts describe the whole selection; `templates` is a capped sample, so
// read `total` for the number and `truncated` to know the list is partial.
export type TemplatePreview = {
  engine: string;
  profile?: string;
  total: number;
  bySeverity: Partial<Record<Severity, number>>;
  byType: Record<string, number>;
  byTag: TemplateTag[];
  maxRequests: number;
  templates: Template[];
  truncated: boolean;
  // Reasons the count may overstate what runs — a filter the preview cannot
  // evaluate, or a requirement that depends on the scanning host.
  caveats?: string[];
};

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

export type EngineKind = "discovery" | "scan";

export type SchemaProperty = {
  type?: string;
  title?: string;
  description?: string;
  enum?: unknown[];
  default?: unknown;
  minimum?: number;
  maximum?: number;
  multipleOf?: number;
  items?: SchemaProperty;
  [key: string]: unknown;
};

export type EngineSection = {
  id: string;
  title: string;
  description?: string;
  sourceUrl?: string;
  properties: Record<string, SchemaProperty>;
};

export type Engine = Identified & {
  name: string;
  kind: EngineKind;
  title: string;
  description?: string;
  docsUrl?: string;
  binary: string;
  // Discovery engines declare what they consume and produce so a chain can be
  // validated; scan engines leave these empty.
  accepts?: string;
  emits?: string;
  // Whether a sweep runs this engine when nothing is chosen. The engine picker
  // opens on this rather than on a list of its own, so what it shows as on is
  // what the server would actually run.
  default?: boolean;
  version?: string;
  installed: boolean;
  managed: boolean;
  path?: string;
  // The profile the engine ships with, which is what a picker should open on:
  // an engine's own idea of its default beats a name hardcoded here, and a
  // hardcoded one is simply wrong for every engine that does not use it.
  defaults?: string;
  // The template corpus, for engines that match against one. An in-process
  // engine's binary cannot be missing, so this is the part that can be — and
  // without it every scan matches nothing.
  templates?: {
    version?: string;
    count: number;
    path?: string;
    problem?: string;
  };
  sections: EngineSection[];
};

export type Profile = Identified & {
  kind: EngineKind;
  engine: string;
  name: string;
  config: Record<string, unknown>;
  // The leading comment block of the stored profile, preserved verbatim.
  comment?: string;
  // The engine's own verdict on this configuration. Gate on this rather than on
  // the profile's name: it is the rule the server enforces, so asking for
  // confirmation whenever it is false would be friction the server would not
  // have imposed.
  intrusive?: boolean;
  reason?: string;
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
