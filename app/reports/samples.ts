// Sample payloads the report playground opens with.
//
// Two, because the report says different things depending on what an engine can
// report: a network scan has wire traffic and no verdicts, a compliance audit
// has verdicts and no traffic. Designing against only one of them is how a
// section that never renders for half the engines gets shipped.
//
// The `as ScanReportData` assertions are load-bearing: JSON is inferred with
// `severity: string`, and asserting it against the contract is what makes a
// renamed field in scan-report-types.ts fail the type check here.

import compliance from "./sample-compliance.json";
import web from "./sample.json";
import type { ScanReportData } from "./scan-report-types";

export type ReportSample = {
  id: string;
  label: string;
  description: string;
  data: ScanReportData;
};

export const REPORT_SAMPLES: ReportSample[] = [
  {
    id: "web",
    label: "Web scan",
    description: "nuclei · wire traffic, no pass verdicts",
    data: web as ScanReportData,
  },
  {
    id: "compliance",
    label: "Compliance audit",
    description: "prowler · pass verdicts, no wire traffic",
    data: compliance as ScanReportData,
  },
];

export function reportSample(id: string): ReportSample | undefined {
  return REPORT_SAMPLES.find((sample) => sample.id === id);
}
