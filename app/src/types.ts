export const CLASS_ORDER = [
  "public",
  "prod",
  "non-prod",
  "internal",
  "deactivated",
] as const;
export type TargetClass = (typeof CLASS_ORDER)[number];

export const PROFILES = ["safe", "full"] as const;
export const SCAN_PROFILES = ["safe", "full", "discovery"] as const;

export type {
  ProfileDocument,
  ProfileEngine,
} from "../profile-schema/index.ts";

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

export type TargetRow = TargetDocument;

export type Inventory = {
  version: 1;
  rows: TargetDocument[];
  zones: string[];
  tagVocabulary: string[];
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
  [key: string]: unknown;
};

export type ScanRun = {
  file: string;
  profile: string;
  group: string;
  startedAt: string;
  mtime: string;
  findings: number;
  hosts: string[];
  severities: Record<Severity, number>;
};

export type DiscoveredHost = {
  host: string;
  status?: number;
  responseTime?: string;
  openPorts?: number[];
  knownPaths?: string[];
  loginMethods?: string[];
  title?: string;
  tech?: string[];
  live: boolean;
  isKnown: boolean;
  [key: string]: unknown;
};

export type DiscoverResult = {
  hosts: DiscoveredHost[];
  newCount: number;
  ranAt: string | null;
  cached: boolean;
  log: string;
};

export type ScanProfile = string;

export type ScanPhase = "idle" | "running" | "done" | "failed" | "cancelled";

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

export type ScanOutputEvent = {
  sequence: number;
  timestamp: string;
  stream: "stdout" | "stderr" | "system";
  text: string;
};

export type ScanStatus = {
  phase: ScanPhase;
  profile: ScanProfile | null;
  group: string | null;
  hosts: string[];
  file: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  stats: ScanStats | null;
  findings: Finding[];
  log: string;
  error: string | null;
  command: string[] | null;
  exitCode: number | null;
  observations: number | null;
  output: ScanOutputEvent[];
};

// Flattened shape handed to DataTable so its timestamp/tags/status column kinds can
// read observed state by key. Carries an index signature to satisfy DataTable's
// `Record<string, unknown>` generic constraint.
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
