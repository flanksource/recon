// The printed scan report.
//
// One template, two renderers: `facet pdf ScanReport.tsx -d report.json` prints
// it, and the in-app playground mounts the same component with the same payload
// so the design can be iterated without a render round trip. Anything that must
// look the same in both belongs here; nothing here may read the clock, the
// network, or the DOM.

import { Footer, Header, Page, PageNo } from "@flanksource/facet";
import { UiScan } from "@flanksource/clicky-ui/icons";

import { buildScanReport } from "./scan-report-model";
import {
  Appendix,
  DetailedFindings,
  FindingsSummaryTable,
} from "./scan-report-sections";
import {
  BreakdownGrid,
  CoverageSection,
  DisclosureNotes,
  ReportHeader,
  RunTable,
  SeverityRow,
  TrafficSection,
} from "./scan-report-summary";
import { reportData, type ScanReportProps } from "./scan-report-types";

const PAGE_MARGINS = { top: 10, bottom: 10, left: 8, right: 8 };

export default function ScanReport(props: ScanReportProps) {
  const data = reportData(props);
  const model = buildScanReport(data);
  const { sections } = model;

  return (
    <>
      <Header type="default" height={10}>
        <div className="flex h-full items-center justify-between bg-[#1e293b] px-[4mm]">
          <span className="flex items-center gap-[2mm]">
            <span className="grid h-[4.5mm] w-[4.5mm] shrink-0 place-items-center rounded-[1.2mm] border border-white/20 bg-white/10">
              <UiScan className="h-[3mm] w-[3mm] text-white/90" />
            </span>
            <span className="text-[10pt] font-semibold tracking-[0.08em] text-white">recon</span>
          </span>
          <span className="text-[7pt] font-semibold uppercase tracking-[0.08em] text-white/70">
            {model.title}
          </span>
        </div>
      </Header>

      <Footer type="default" height={8}>
        <div className="flex h-full items-center justify-between border-t border-gray-200 px-4 text-[7pt] text-gray-400">
          <span className="font-semibold uppercase tracking-[0.08em]">{model.classification}</span>
          <span className="truncate">{model.subtitle}</span>
          <PageNo format="Page ${page} of ${total}" />
        </div>
      </Footer>

      <Page margins={PAGE_MARGINS} watermark={model.watermark}>
        <ReportHeader model={model} scope={data.options?.scope} />
        <RunTable groups={model.metadata} />
        <SeverityRow model={model} />
        <DisclosureNotes notes={model.notes} />
        {sections.coverage && <CoverageSection metrics={model.coverage} rate={model.passRate} />}
        {sections.traffic && model.traffic && <TrafficSection traffic={model.traffic} />}
        {sections.breakdowns && <BreakdownGrid breakdowns={model.breakdowns} />}
      </Page>

      {sections.summaryTable && (
        <Page margins={PAGE_MARGINS} watermark={model.watermark}>
          <FindingsSummaryTable groups={model.findingGroups} />
        </Page>
      )}

      {sections.detailedFindings && model.detailedGroups.length > 0 && (
        <Page margins={PAGE_MARGINS} watermark={model.watermark}>
          <DetailedFindings groups={model.detailedGroups} showEvidence={sections.evidence} />
        </Page>
      )}

      {sections.appendix && (
        <Page margins={PAGE_MARGINS} watermark={model.watermark}>
          <Appendix scan={data.scan} parameters={model.parameters} />
        </Page>
      )}
    </>
  );
}
