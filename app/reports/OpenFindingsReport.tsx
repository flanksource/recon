// A current-posture document, independent of any one scan. The server supplies
// one state per resource/engine/check, with evidence scoped to that resource.
import { Footer, Header, Page, PageNo, SeverityStatCard, StatCard } from "@flanksource/facet";
import { DetailedFindings, FindingsSummaryTable } from "./scan-report-sections";
import { PageHeading, SectionHeading } from "./scan-report-chrome";
import { formatDate } from "./scan-report-format";
import { groupFindings, SEVERITY_COLOR, SEVERITY_RANK } from "./scan-report-model";
import { REPORT_SEVERITIES, type ReportFinding, type ReportSeverity } from "./scan-report-types";

type OpenFindingState = {
  id: string;
  resourceId: string;
  engine: string;
  checkId: string;
  status: "open" | "manual";
  severity: ReportSeverity;
  firstSeen: string;
  lastSeen: string;
  finding: ReportFinding;
  resource: { provider: string; scope?: string; uid: string; name?: string };
};

export type OpenFindingsReportData = {
  states: OpenFindingState[];
  generatedAt: string;
};

const MARGINS = { top: 10, bottom: 10, left: 8, right: 8 };

/** Reuse the findings presentation, but count current states rather than runs. */
export default function OpenFindingsReport(props: OpenFindingsReportData | { data: OpenFindingsReportData }) {
  const data = "data" in props ? props.data : props;
  const states = [...data.states].sort((a, b) =>
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
    a.engine.localeCompare(b.engine) || a.checkId.localeCompare(b.checkId) || a.resourceId.localeCompare(b.resourceId));
  const byCheck = new Map<string, ReportFinding[]>();
  for (const state of states) {
    const key = JSON.stringify([state.engine, state.checkId]);
    const finding = {
      ...state.finding,
      engine: state.engine,
      checkId: state.checkId,
      // Resource UIDs can repeat across accounts. Keep that scope visible in
      // the existing instance tables instead of merging equal-looking rows.
      resources: state.finding.resources?.map((resource) => ({
        ...resource,
        name: `${state.resource.provider}/${state.resource.scope || "—"}: ${resource.name || resource.uid}`,
      })),
    };
    byCheck.set(key, [...(byCheck.get(key) ?? []), finding]);
  }
  const groups = [...byCheck.values()].flatMap(groupFindings);
  const resources = new Set(states.map((state) => state.resourceId));
  const manual = states.filter((state) => state.status === "manual").length;

  return (
    <>
      <Header type="default" height={10}>
        <div className="flex h-full items-center justify-between bg-[#1e293b] px-[4mm] text-[9pt] text-white">
          <span className="font-semibold tracking-[0.08em]">recon</span>
          <span>Open Findings Report</span>
        </div>
      </Header>
      <Footer type="default" height={8}>
        <div className="flex h-full items-center justify-between border-t border-gray-200 px-4 text-[7pt] text-gray-400">
          <span>INTERNAL · All resources</span>
          <PageNo format="Page ${page} of ${total}" />
        </div>
      </Footer>
      <Page margins={MARGINS}>
        <h1 className="mb-[2mm] text-[24pt] font-bold text-gray-900">Open Findings Report</h1>
        <p className="mb-[4mm] text-[8pt] text-gray-500">Generated {formatDate(data.generatedAt)}</p>
        <p className="mb-[5mm] text-[9pt]">
          All currently open and manual-review findings across the inventory. Resolved and muted findings
          are excluded. This snapshot is not a new scan and does not establish that other resources are clean.
        </p>
        <div className="mb-[5mm] grid grid-cols-3 gap-[3mm]">
          <StatCard label="Outstanding findings" value={states.length} />
          <StatCard label="Affected resources" value={resources.size} />
          <StatCard label="Manual review" value={manual} />
        </div>
        <SectionHeading>Severity of outstanding findings</SectionHeading>
        <div className="mb-[5mm] grid grid-cols-3 gap-[3mm]">
          {REPORT_SEVERITIES.map((severity) => (
            <SeverityStatCard key={severity} label={severity} color={SEVERITY_COLOR[severity]}
              value={states.filter((state) => state.severity === severity).length} />
          ))}
        </div>
        <p className="text-[8pt] text-gray-500">
          Each finding is one resource/engine/check pair, regardless of how many scans reported it.
          Last seen records the most recent verdict, not a guarantee that the problem is still reproducible.
          Findings from engines that do not report passes may remain open until explicitly resolved.
        </p>
        {states.length === 0 && <p className="mt-[5mm] text-[10pt]">No open or manual-review findings.</p>}
      </Page>
      {states.length > 0 && (
        <>
          <Page margins={MARGINS}>
            <FindingsSummaryTable groups={groups} showEngine />
          </Page>
          <Page margins={MARGINS}>
            <PageHeading>Current finding states</PageHeading>
            <table className="w-full text-left text-[7pt]">
              <thead><tr><th>Resource / account</th><th>Engine / check</th><th>Status</th><th>First / last seen</th></tr></thead>
              <tbody>
                {states.map((state) => (
                  <tr key={state.id} className="break-inside-avoid border-b border-gray-200">
                    <td className="break-all py-[2mm] pr-[2mm]">
                      {state.resource.name || state.resource.uid}<br />
                      {state.resource.provider}/{state.resource.scope || "—"}<br />{state.resource.uid}
                    </td>
                    <td className="break-all pr-[2mm]">{state.engine}<br />{state.checkId}</td>
                    <td className="pr-[2mm]">{state.status === "manual" ? "Manual review" : "Open"}</td>
                    <td>{formatDate(state.firstSeen)}<br />{formatDate(state.lastSeen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Page>
          <Page margins={MARGINS}>
            <DetailedFindings groups={groups} showEvidence />
          </Page>
        </>
      )}
    </>
  );
}
