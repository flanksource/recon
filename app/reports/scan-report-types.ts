// The contract between a scan and the printed report.
//
// This is deliberately its own declaration rather than an import of
// `app/src/types.ts`: the report is compiled by facet from an extracted source
// directory that has no `app/src` beside it, and it is rendered from JSON the Go
// server marshals straight out of `internal/api`. Declaring the input here makes
// that JSON a checked contract in all three places — the app assigns its own
// `Scan`/`Finding` into it structurally, so a wire field the report depends on
// cannot be dropped without a type error.
//
// Everything here is a *subset* of the wire types. Never widen a field beyond
// what `internal/api` emits.

export const REPORT_SEVERITIES = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
  "unknown",
] as const;

export type ReportSeverity = (typeof REPORT_SEVERITIES)[number];

/** What a run put on the wire, when the engine counts its requests. */
export type ReportHTTPStats = {
  requests: number;
  responses: number;
  failed: number;
  bytes: number;
  statusCodes: Record<string, number>;
  protocols: Record<string, number>;
  errors: Record<string, number>;
  waf: Record<string, number>;
};

export type ReportStats = {
  requests: number;
  total: number;
  percent: number;
  rps: number;
  matched: number;
  errors: number;
  hosts: number;
  templates: number;
  duration?: string;
  /** Checks that ran and returned a clean verdict. Meaningful only with `passRecorded`. */
  passed?: number;
  /** The engine counts verdicts at all — see api.ScanStats.PassRecorded. */
  passRecorded?: boolean;
  http?: ReportHTTPStats;
};

export type ReportScan = {
  id: string;
  name: string;
  engine: string;
  engineVersion?: string;
  profile: string;
  selectorLabel: string;
  /** What the selector resolved to when the run started. */
  endpointCount: number;
  phase: string;
  startedAt: string;
  finishedAt?: string;
  durationMs: number;
  command?: string[];
  exitCode?: number;
  error?: string;
  findings: number;
  severities: Record<string, number>;
  stats?: ReportStats;
  /** Hosts that produced at least one finding — not the hosts that were scanned. */
  hosts: string[];
};

/**
 * One finding as the report payload carries it: an OCSF Detection Finding.
 *
 * The attributes sit under their published OCSF names, so the template renders
 * the record the schema defines rather than a recon-shaped one. The four
 * columns only nuclei ever filled — request, response, curl, extracted — are
 * one `evidences[]` array now, which is also where inspec's assertions and
 * trivy's cause metadata arrive.
 */
export type ReportFinding = {
  scanId: string;
  lineNo: number;
  /** The check this is an instance of. Was `templateId`. */
  checkId: string;
  /** Which scanner produced it. Was `type`. */
  engine?: string;
  host: string;
  matchedAt: string;
  tags: string[];
  severity_id?: number;
  /** The engine's own status code; prowler writes FAIL or MANUAL. */
  status_code?: string;
  /** Epoch milliseconds, absent when the engine reported no time. */
  time?: number;
  finding_info?: {
    uid?: string;
    title?: string;
    desc?: string;
    types?: string[];
    src_url?: string;
  };
  remediation?: { desc?: string; references?: string[] };
  cloud?: { provider?: string; region?: string; account?: { uid?: string; name?: string } };
  vulnerabilities?: {
    title?: string;
    desc?: string;
    severity?: string;
    is_fix_available?: boolean;
    cve?: { uid?: string; title?: string };
    affected_packages?: { name?: string; version?: string; fixed_in_version?: string }[];
  }[];
  evidences?: ReportEvidence[];
  unmapped?: Record<string, unknown>;
  /**
   * The subjects the evidence names, in the engine's own order. The server
   * always sends at least one, so the template never has to derive a resource
   * identity of its own.
   */
  resources?: ReportResourceRef[];
};

/** One piece of evidence. `data` is OCSF's json_t: the engine's own shape. */
export type ReportEvidence = {
  name?: string;
  url?: { url_string?: string };
  http_request?: { args?: string };
  http_response?: { message?: string; code?: number };
  data?: unknown;
};

/** Recon's severity ladder, from OCSF's integer scale. */
export const REPORT_SEVERITY_BY_ID: Record<number, ReportSeverity> = {
  0: "unknown",
  1: "info",
  2: "low",
  3: "medium",
  4: "high",
  5: "critical",
  6: "critical",
};

export function reportSeverity(finding: { severity_id?: number }): ReportSeverity {
  return REPORT_SEVERITY_BY_ID[finding.severity_id ?? 0] ?? "unknown";
}

/** What a finding calls itself, falling back to the check id. */
export function reportFindingTitle(finding: ReportFinding): string {
  return finding.finding_info?.title || finding.checkId;
}

/** One thing a finding is about. Render `name`, fall back to `uid`. */
export type ReportResourceRef = {
  id?: string;
  uid: string;
  name?: string;
  type?: string;
  service?: string;
  region?: string;
};

/** Which parts of the report to print. Every section defaults to on. */
export type ReportSections = {
  coverage?: boolean;
  traffic?: boolean;
  breakdowns?: boolean;
  summaryTable?: boolean;
  detailedFindings?: boolean;
  evidence?: boolean;
  appendix?: boolean;
};

export type ReportOptions = {
  title?: string;
  subtitle?: string;
  /** Printed in the footer of every page. */
  classification?: string;
  preparedBy?: string;
  audience?: string;
  /** One line describing what the run covered, printed under the metadata block. */
  scope?: string;
  /** Diagonal watermark on every page — e.g. "DRAFT". */
  watermark?: string;
  sections?: ReportSections;
  /** Drop findings below this severity from the printed report. */
  minSeverity?: ReportSeverity;
  /** Retain at most this many detailed occurrences before grouping them by template. */
  maxDetailedFindings?: number;
};

export type ScanReportData = {
  scan: ReportScan;
  findings: ReportFinding[];
  /** Effective engine configuration retained with the run, including overrides. */
  parameters?: Record<string, unknown>;
  options?: ReportOptions;
  /**
   * When the report was produced, as an ISO timestamp. Supplied by the caller
   * rather than read from the clock inside the template, so re-rendering the
   * same payload produces the same bytes.
   */
  generatedAt?: string;
  /**
   * How many findings the caller asked the API for. When the run holds more
   * than this, the report says so rather than presenting a page of the run as
   * the whole of it.
   */
  findingLimit?: number;
  /** Where the run can be read interactively. */
  sourceURL?: string;
};

/** The props facet hands a template: either the payload, or `{ data: payload }`. */
export type ScanReportProps = ScanReportData | { data: ScanReportData };

export function reportData(props: ScanReportProps): ScanReportData {
  return "data" in props && props.data ? props.data : (props as ScanReportData);
}
