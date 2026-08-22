// The client side of the scan report.
//
// Report options live in the URL rather than in component state, so a report
// somebody tuned in the playground is a link: the same query string produces the
// same JSON payload, the same PDF and the same preview. These helpers are the
// one place that mapping is written down.

import type { ReportOptions, ScanReportData } from "../reports/scan-report-types";
import type { Scan } from "./types";

export type ReportFormat = "pdf" | "html";

/** The section toggles, in the order the playground lists them. */
export const REPORT_SECTIONS = [
  { key: "coverage", label: "Coverage" },
  { key: "traffic", label: "Traffic" },
  { key: "breakdowns", label: "Breakdowns" },
  { key: "summaryTable", label: "Findings table" },
  { key: "detailedFindings", label: "Detailed findings" },
  { key: "evidence", label: "Evidence" },
  { key: "appendix", label: "Appendix" },
] as const;

export type ReportSectionKey = (typeof REPORT_SECTIONS)[number]["key"];

const TEXT_OPTIONS = [
  "title",
  "subtitle",
  "classification",
  "preparedBy",
  "audience",
  "scope",
  "watermark",
] as const;

/**
 * Report options as a query string.
 *
 * Only what differs from the template's own defaults is written: an empty field
 * and a section left on contribute nothing, so the common case is a bare URL and
 * a customised one reads as a list of the decisions somebody actually made.
 */
export function reportQuery(options: ReportOptions): URLSearchParams {
  const query = new URLSearchParams();
  for (const key of TEXT_OPTIONS) {
    const value = options[key]?.trim();
    if (value) query.set(key, value);
  }
  if (options.minSeverity) query.set("minSeverity", options.minSeverity);
  if (typeof options.maxDetailedFindings === "number") {
    query.set("maxDetailedFindings", String(options.maxDetailedFindings));
  }
  for (const section of REPORT_SECTIONS) {
    if (options.sections?.[section.key] === false) query.set(section.key, "false");
  }
  return query;
}

/** Read report options back off a query string, for a pasted playground link. */
export function reportOptionsFromQuery(query: URLSearchParams): ReportOptions {
  const options: ReportOptions = {};
  for (const key of TEXT_OPTIONS) {
    const value = query.get(key);
    if (value) options[key] = value;
  }
  const minSeverity = query.get("minSeverity");
  if (minSeverity) options.minSeverity = minSeverity as ReportOptions["minSeverity"];

  const max = query.get("maxDetailedFindings");
  if (max !== null && Number.isFinite(Number(max))) {
    options.maxDetailedFindings = Number(max);
  }

  const sections: ReportOptions["sections"] = {};
  let toggled = false;
  for (const section of REPORT_SECTIONS) {
    if (query.get(section.key) === "false") {
      sections[section.key] = false;
      toggled = true;
    }
  }
  if (toggled) options.sections = sections;
  return options;
}

function withQuery(path: string, options: ReportOptions): string {
  const query = reportQuery(options).toString();
  return query ? `${path}?${query}` : path;
}

/** Where the rendered document lives. Followed directly, so the browser downloads it. */
export function reportUrl(
  scanId: string,
  format: ReportFormat,
  options: ReportOptions = {},
): string {
  return withQuery(`/api/scan/${encodeURIComponent(scanId)}/report.${format}`, options);
}

/** Where the payload the template renders lives. */
export function reportDataUrl(scanId: string, options: ReportOptions = {}): string {
  return withQuery(`/api/scan/${encodeURIComponent(scanId)}/report`, options);
}

/** The playground route for a run, carrying the options already chosen. */
export function playgroundUrl(scanId: string, options: ReportOptions = {}): string {
  return withQuery(`/reports/${encodeURIComponent(scanId)}`, options);
}

/**
 * The payload for a run the browser already holds.
 *
 * The playground renders the template locally so a design change is visible
 * without a round trip, which means it has to build the payload the server would
 * have built. `Scan` and `Finding` are assignable to the template's declared
 * input, so this is a re-labelling rather than a mapping — there is no second
 * derivation to keep in step.
 */
export function localReportData(
  scan: Scan,
  findings: ScanReportData["findings"],
  options: ReportOptions,
  findingLimit: number,
): ScanReportData {
  return {
    scan,
    findings,
    options,
    generatedAt: new Date().toISOString(),
    findingLimit,
    sourceURL: `${window.location.origin}/scans/${scan.id}`,
  };
}
