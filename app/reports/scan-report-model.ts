// Everything the printed report derives from a run, computed once so the
// template is composition and the arithmetic is unit-testable.
//
// The rules that matter here are about honesty rather than layout:
//   - a count the engine did not report is absent, never zero;
//   - a findings list the API capped says so, rather than reading as the whole run;
//   - "scanned", "affected" and "clean" are three different numbers and are
//     never derived from one another unless both inputs are known.

import {
  REPORT_SEVERITIES,
  type ReportFinding,
  type ReportScan,
  type ReportSections,
  type ReportSeverity,
  type ReportStats,
  type ScanReportData,
} from "./scan-report-types";
import {
  uniqueFindingResourceInstances,
  type FindingResourceInstance,
} from "./finding-resources";
import {
  formatBytes,
  formatCount as count,
  formatDate,
  formatDuration,
} from "./scan-report-format";

export const SEVERITY_RANK: Record<ReportSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  unknown: 5,
};

/** facet's SeverityStatCard palette, keyed by our severity vocabulary. */
export const SEVERITY_COLOR: Record<
  ReportSeverity,
  "red" | "orange" | "yellow" | "blue" | "gray"
> = {
  critical: "red",
  high: "orange",
  medium: "yellow",
  low: "blue",
  info: "gray",
  unknown: "gray",
};

export const SEVERITY_BADGE: Record<ReportSeverity, string> = {
  critical: "bg-rose-50 text-rose-700 border-rose-200",
  high: "bg-orange-50 text-orange-700 border-orange-200",
  medium: "bg-yellow-50 text-yellow-800 border-yellow-200",
  low: "bg-sky-50 text-sky-700 border-sky-200",
  info: "bg-slate-100 text-slate-700 border-slate-300",
  unknown: "bg-slate-100 text-slate-700 border-slate-300",
};

export const SEVERITY_BORDER: Record<ReportSeverity, string> = {
  critical: "border border-l-2 border-l-red-500 border-gray-200",
  high: "border border-l-2 border-l-orange-500 border-gray-200",
  medium: "border border-l-2 border-l-yellow-500 border-gray-200",
  low: "border border-l-2 border-l-blue-300 border-gray-200",
  info: "border border-l-2 border-l-gray-300 border-gray-200",
  unknown: "border border-l-2 border-l-gray-200 border-gray-200",
};

export type Metric = {
  key: string;
  label: string;
  value: string;
  /** Printed under the value — what the number is counted from. */
  hint?: string;
};

/**
 * What a run-detail row is *about*, so the cover can tile it with the glyph and
 * hue the rest of the report already uses for that idea.
 *
 * The kind is a name rather than an icon because this module is arithmetic: the
 * vocabulary that turns a kind into a colour and a glyph lives in
 * scan-report-tags.tsx, beside the one that does it for tags and severities.
 */
export type MetadataKind =
  | "engine"
  | "profile"
  | "selector"
  | "time"
  | "outcome"
  | "incomplete"
  | "audience"
  | "author"
  | "source"
  | "classification";

export type MetadataRow = { label: string; value: string; kind: MetadataKind };

export type MetadataGroup = { title: string; rows: MetadataRow[] };

export type BreakdownRow = { name: string; count: number };

export type ParameterRow = { name: string; value: string };

export type Breakdown = { key: string; title: string; rows: BreakdownRow[] };

export type PassRate = { passed: number; failed: number; percent: number };

export type TrafficModel = {
  totals: Metric[];
  statusCodes: BreakdownRow[];
  protocols: BreakdownRow[];
  errors: BreakdownRow[];
  waf: BreakdownRow[];
};

export type FindingGroup = {
  templateId: string;
  names: string[];
  severity: ReportSeverity;
  findings: ReportFinding[];
  instances: FindingResourceInstance[];
  matcherNames: string[];
  types: string[];
  tags: string[];
  descriptions: string[];
  remediations: string[];
  references: string[];
};

export type ScanReportModel = {
  title: string;
  subtitle: string;
  classification: string;
  generatedAt: string;
  watermark?: string;
  /** Run detail, grouped so the cover can print it as two tables side by side. */
  metadata: MetadataGroup[];
  parameters: ParameterRow[];
  severityCards: Array<{ severity: ReportSeverity; label: string; value: number }>;
  totalFindings: number;
  coverage: Metric[];
  passRate?: PassRate;
  traffic?: TrafficModel;
  breakdowns: Breakdown[];
  /** Findings that survived the severity floor, worst first. */
  findings: ReportFinding[];
  /** Summary rows, grouped by the check that produced them. */
  findingGroups: FindingGroup[];
  /** The head of `findings` that gets a full detail block. */
  detailed: ReportFinding[];
  /** Detailed occurrences grouped by check, without restoring capped findings. */
  detailedGroups: FindingGroup[];
  /** Disclosures the report must print: caps, filters, failures. */
  notes: string[];
  sections: Required<ReportSections>;
};

const DEFAULT_SECTIONS: Required<ReportSections> = {
  coverage: true,
  traffic: true,
  breakdowns: true,
  summaryTable: true,
  detailedFindings: true,
  evidence: true,
  appendix: true,
};

function tally(values: Iterable<string>): BreakdownRow[] {
  const counts = new Map<string, number>();
  for (const value of values) {
    if (!value) continue;
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .map(([name, rows]) => ({ name, count: rows }));
}

function mapRows(source: Record<string, number> | undefined): BreakdownRow[] {
  if (!source) return [];
  return Object.entries(source)
    .filter(([, value]) => value > 0)
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .map(([name, value]) => ({ name, count: value }));
}

/**
 * Coverage: what the run touched, as separate facts.
 *
 * "Resources scanned" is only present when the engine reported it. Substituting
 * the selector's resolved target count would answer a question nobody asked —
 * how many things were *selected* is already its own row — and would silently
 * claim coverage for an engine that never said what it reached.
 */
export function coverageMetrics(scan: ReportScan): Metric[] {
  const stats = scan.stats;
  const metrics: Metric[] = [
    { key: "targets", label: "Targets selected", value: count(scan.endpointCount), hint: scan.selectorLabel },
  ];

  if (stats && stats.hosts > 0) {
    metrics.push({ key: "scanned", label: "Resources scanned", value: count(stats.hosts) });
    const clean = stats.hosts - scan.hosts.length;
    if (clean >= 0) {
      metrics.push({
        key: "clean",
        label: "Clean resources",
        value: count(clean),
        hint: "scanned, no findings",
      });
    }
  }

  metrics.push({
    key: "affected",
    label: "Affected resources",
    value: count(scan.hosts.length),
    hint: "at least one finding",
  });

  if (stats && stats.templates > 0) {
    metrics.push({ key: "checks", label: "Checks in scope", value: count(stats.templates) });
  }
  if (stats && stats.requests > 0) {
    metrics.push({ key: "executed", label: "Checks executed", value: count(stats.requests) });
  }
  if (stats?.passRecorded) {
    metrics.push({ key: "passed", label: "Passing checks", value: count(stats.passed ?? 0) });
  }
  metrics.push({ key: "duration", label: "Runtime", value: stats?.duration ?? formatDuration(scan.durationMs) });
  if (stats && stats.errors > 0) {
    metrics.push({ key: "errors", label: "Errors", value: count(stats.errors) });
  }
  return metrics;
}

/**
 * The pass/fail split, but only for engines that record a verdict per check.
 *
 * A network scanner's template that matched nothing did not "pass" — it found
 * no evidence — so inferring a rate from `requests - matched` would print a
 * compliance number the run never established.
 */
export function passRate(stats: ReportStats | undefined): PassRate | undefined {
  if (!stats?.passRecorded) return undefined;
  const passed = Math.round(stats.passed ?? 0);
  const failed = Math.round(stats.matched);
  const total = passed + failed;
  if (total === 0) return undefined;
  return { passed, failed, percent: (passed / total) * 100 };
}

export function trafficModel(stats: ReportStats | undefined): TrafficModel | undefined {
  const http = stats?.http;
  if (!http || (http.requests === 0 && http.responses === 0 && http.failed === 0)) {
    return undefined;
  }
  return {
    totals: [
      { key: "requests", label: "Requests sent", value: count(http.requests) },
      { key: "responses", label: "Responses", value: count(http.responses) },
      { key: "failed", label: "Failed", value: count(http.failed) },
      { key: "bytes", label: "Transferred", value: formatBytes(http.bytes) },
    ],
    statusCodes: mapRows(http.statusCodes),
    protocols: mapRows(http.protocols),
    errors: mapRows(http.errors),
    waf: mapRows(http.waf),
  };
}

export function severityCards(
  scan: ReportScan,
): Array<{ severity: ReportSeverity; label: string; value: number }> {
  return REPORT_SEVERITIES.filter(
    (severity) => (scan.severities[severity] ?? 0) > 0 || severity === "critical" || severity === "high",
  ).map((severity) => ({
    severity,
    label: severity.charAt(0).toUpperCase() + severity.slice(1),
    value: scan.severities[severity] ?? 0,
  }));
}

export function sortFindings(findings: ReportFinding[]): ReportFinding[] {
  return [...findings].sort(
    (left, right) =>
      SEVERITY_RANK[left.severity] - SEVERITY_RANK[right.severity] ||
      left.templateId.localeCompare(right.templateId) ||
      left.host.localeCompare(right.host) ||
      left.lineNo - right.lineNo,
  );
}

function uniqueValues(values: Iterable<string | undefined>): string[] {
  const unique = new Map<string, string>();
  for (const value of values) {
    const label = value?.trim();
    if (!label) continue;
    const key = label.toLowerCase();
    if (!unique.has(key)) unique.set(key, label);
  }
  return [...unique.values()];
}

export function visibleFindingTags(tags: Iterable<string>): string[] {
  return uniqueValues(tags).filter((tag) => !tag.toLowerCase().startsWith("compliance:"));
}

function findingDescription(finding: ReportFinding): string | undefined {
  const raw = finding.raw;
  const info = raw?.info;
  const nested =
    typeof info === "object" && info !== null && !Array.isArray(info)
      ? (info as Record<string, unknown>).description
      : undefined;
  for (const value of [nested, raw?.description, raw?.Description]) {
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return undefined;
}

export function groupFindings(findings: ReportFinding[]): FindingGroup[] {
  const grouped = new Map<string, ReportFinding[]>();
  for (const finding of sortFindings(findings)) {
    grouped.set(finding.templateId, [...(grouped.get(finding.templateId) ?? []), finding]);
  }
  return [...grouped.entries()].map(([templateId, occurrences]) => ({
    templateId,
    names: uniqueValues(occurrences.map((finding) => finding.name)),
    severity: occurrences[0].severity,
    findings: occurrences,
    instances: uniqueFindingResourceInstances(occurrences),
    matcherNames: uniqueValues(occurrences.map((finding) => finding.matcherName)),
    types: uniqueValues(occurrences.map((finding) => finding.type)),
    tags: visibleFindingTags(occurrences.flatMap((finding) => finding.tags)),
    descriptions: uniqueValues(occurrences.map(findingDescription)),
    remediations: uniqueValues(occurrences.map((finding) => finding.remediation)),
    references: uniqueValues(occurrences.flatMap((finding) => finding.reference ?? [])),
  }));
}

export function breakdowns(scan: ReportScan, findings: ReportFinding[]): Breakdown[] {
  const bySeverity = REPORT_SEVERITIES.filter((severity) => (scan.severities[severity] ?? 0) > 0).map(
    (severity) => ({ name: severity, count: scan.severities[severity] ?? 0 }),
  );
  return [
    { key: "severity", title: "By severity", rows: bySeverity },
    { key: "check", title: "By check", rows: tally(findings.map((finding) => finding.templateId)) },
    { key: "resource", title: "By resource", rows: tally(findings.map((finding) => finding.host)) },
    {
      key: "tag",
      title: "By tag",
      rows: tally(findings.flatMap((finding) => visibleFindingTags(finding.tags))),
    },
  ].filter((breakdown) => breakdown.rows.length > 0);
}

/**
 * Run detail, split into what the *run* was and what the *report* is.
 *
 * Two groups rather than one list because the cover prints them side by side:
 * eleven rows stacked would cost a third of the page for facts nobody reads
 * top-to-bottom. An unset option is an absent row, never a blank one — a
 * printed "Audience: —" claims the question was asked and answered.
 */
function metadataGroups(
  data: ScanReportData,
  generatedAt: string,
  classification: string,
): MetadataGroup[] {
  const { scan, options } = data;

  const run: MetadataRow[] = [
    { label: "Engine", value: [scan.engine, scan.engineVersion].filter(Boolean).join(" "), kind: "engine" },
    { label: "Profile", value: scan.profile, kind: "profile" },
    { label: "Selector", value: scan.selectorLabel, kind: "selector" },
    { label: "Started", value: formatDate(scan.startedAt), kind: "time" },
    { label: "Finished", value: formatDate(scan.finishedAt), kind: "time" },
    // A run that never reached "done" is not a clean verdict, and the tile it
    // gets is what says so on the row itself — before the disclosure note below
    // spells it out.
    {
      label: "Outcome",
      value: scan.phase,
      kind: scan.phase === "done" ? "outcome" : "incomplete",
    },
  ];

  const report: MetadataRow[] = [
    { label: "Generated", value: formatDate(generatedAt), kind: "time" },
    { label: "Classification", value: classification, kind: "classification" },
  ];
  if (options?.audience) report.push({ label: "Audience", value: options.audience, kind: "audience" });
  if (options?.preparedBy) {
    report.push({ label: "Prepared by", value: options.preparedBy, kind: "author" });
  }
  if (data.sourceURL) report.push({ label: "Source", value: data.sourceURL, kind: "source" });

  return [
    { title: "Run", rows: run },
    { title: "Report", rows: report },
  ];
}

function parameterRows(parameters: Record<string, unknown> | undefined): ParameterRow[] {
  return Object.entries(parameters ?? {})
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, value]) => {
      const rendered = typeof value === "string" ? value : JSON.stringify(value);
      if (rendered === undefined) {
        throw new Error(`scan parameter ${name} cannot be represented as JSON`);
      }
      return { name, value: rendered };
    });
}

/**
 * Disclosures the report is obliged to print.
 *
 * A capped findings query and a severity floor both make the printed list
 * shorter than the run; saying which, and by how much, is what keeps the
 * document a report of the run rather than of the query.
 */
function disclosures(
  data: ScanReportData,
  kept: ReportFinding[],
  detailed: ReportFinding[],
): string[] {
  const notes: string[] = [];
  const { scan, findings, options, findingLimit } = data;

  if (findingLimit && findings.length >= findingLimit && scan.findings > findings.length) {
    notes.push(
      `This report covers the first ${findings.length} of ${scan.findings} findings — the API caps a query at ${findingLimit}.`,
    );
  }
  if (options?.minSeverity && kept.length < findings.length) {
    notes.push(
      `${findings.length - kept.length} findings below ${options.minSeverity} severity are excluded; the severity counts above are for the whole run.`,
    );
  }
  if (detailed.length < kept.length) {
    notes.push(
      `Detailed evidence is printed for the ${detailed.length} highest-severity findings; the summary table lists all ${kept.length}.`,
    );
  }
  if (scan.error) notes.push(`The run reported an error: ${scan.error}`);
  if (scan.phase !== "done") {
    notes.push(`The run finished in phase "${scan.phase}", so its coverage may be partial.`);
  }
  return notes;
}

export function buildScanReport(data: ScanReportData): ScanReportModel {
  const { scan, options } = data;
  const generatedAt = data.generatedAt ?? new Date().toISOString();
  const floor = options?.minSeverity ? SEVERITY_RANK[options.minSeverity] : Number.POSITIVE_INFINITY;
  const kept = sortFindings(
    data.findings.filter((finding) => SEVERITY_RANK[finding.severity] <= floor),
  );
  const detailed =
    options?.maxDetailedFindings && options.maxDetailedFindings < kept.length
      ? kept.slice(0, options.maxDetailedFindings)
      : kept;

  const classification = options?.classification ?? "Internal";

  return {
    title: options?.title ?? "Scan Findings Report",
    subtitle: options?.subtitle ?? scan.name,
    classification,
    generatedAt,
    watermark: options?.watermark,
    metadata: metadataGroups(data, generatedAt, classification),
    parameters: parameterRows(data.parameters),
    severityCards: severityCards(scan),
    totalFindings: scan.findings,
    coverage: coverageMetrics(scan),
    passRate: passRate(scan.stats),
    traffic: trafficModel(scan.stats),
    breakdowns: breakdowns(scan, kept),
    findings: kept,
    findingGroups: groupFindings(kept),
    detailed,
    detailedGroups: groupFindings(detailed),
    notes: disclosures(data, kept, detailed),
    sections: { ...DEFAULT_SECTIONS, ...options?.sections },
  };
}
