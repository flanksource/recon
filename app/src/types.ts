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

export const PROFILES = ["safe", "full"] as const;

// The server stamps `_id` onto rows in a list response so one is addressable
// without knowing which field is its key. A single get does not carry it, hence
// optional — prefer the entity's own key (host, id, kind:engine:name) wherever
// the value has to survive a round trip.
export type Identified = { _id?: string };

export type ObservedState = {
  first_observed?: string;
  last_seen?: string;
  last_attempt?: string;
  error?: string;
};

export type TargetDocument = {
  $schema: "../target.schema.json";
  version: 1;
  host: string;
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
  [key: string]: unknown;
};

export type ScanPhase = "idle" | "running" | "done" | "failed" | "cancelled";

export const TERMINAL_PHASES: ScanPhase[] = ["done", "failed", "cancelled"];

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
  command?: string[];
  exitCode?: number;
  error?: string;
  findings: number;
  severities: SeverityCounts;
  stats?: ScanStats;
  hosts: string[];
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
  version?: string;
  installed: boolean;
  managed: boolean;
  path?: string;
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

export type Discover = Identified & {
  id: string;
  chain: string;
  profile: string;
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
