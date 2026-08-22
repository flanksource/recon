// Page one: what the run was, and what it found.
//
// Everything here is presentational — it renders what scan-report-model.ts
// already decided, and makes no judgements of its own about what a number
// means. The shared vocabulary is in scan-report-chrome.tsx (tiles, facts runs,
// headings) and scan-report-tags.tsx (which hue and glyph an idea gets), so a
// severity means the same colour here that it means on a finding twenty pages
// later.

import { ProgressBar, SeverityStatCard, StatCard, ListTable } from "@flanksource/facet";

import {
  SEVERITY_COLOR,
  type Breakdown,
  type MetadataGroup,
  type MetadataRow,
  type Metric,
  type PassRate,
  type ScanReportModel,
  type TrafficModel,
} from "./scan-report-model";
import { formatDate } from "./scan-report-format";
import {
  CATEGORY_CLASS,
  METADATA_STYLE,
  checkStyle,
  resourceStyle,
  severityStyle,
  tagStyle,
  typeStyle,
  type TagStyle,
} from "./scan-report-tags";
import {
  Facts,
  FixedGrid,
  KindTile,
  SectionHeading,
  balancedColumns,
} from "./scan-report-chrome";
import { UiInfo, UiScan } from "@flanksource/clicky-ui/icons";

/**
 * The front of the document: what this is, what it covered, and how bad it is.
 *
 * The eyebrow tile carries the worst severity the run found, so the first mark
 * on the page already says whether the report is routine — colour keeps its
 * meaning here exactly as it does on a finding.
 */
export function ReportHeader({ model, scope }: { model: ScanReportModel; scope?: string }) {
  const worst = model.severityCards.find((card) => card.value > 0);
  return (
    <header className="mb-[5mm] border-b border-gray-200 pb-[3mm]">
      <div className="mb-[2mm] flex items-center gap-[2mm]">
        <KindTile size="md" style={worst ? severityStyle(worst.severity) : REPORT_STYLE} />
        <span className="text-[7pt] font-semibold uppercase tracking-[0.08em] text-gray-500">
          recon · {model.classification} · {model.subtitle}
        </span>
      </div>

      <h1 className="mb-[1.5mm] text-[24pt] font-bold leading-[28pt] tracking-tight text-gray-900">
        {model.title}
      </h1>

      {scope && (
        <p className="mb-[2mm] max-w-[76ch] text-[8.5pt] leading-[12pt] text-gray-500">{scope}</p>
      )}

      <Facts
        items={[
          `${model.totalFindings.toLocaleString("en-US")} findings`,
          `generated ${formatDate(model.generatedAt)}`,
        ]}
      />
    </header>
  );
}

/** The fallback eyebrow tile for a run that found nothing at all. */
const REPORT_STYLE: TagStyle = { className: CATEGORY_CLASS.stage, icon: UiScan };

/**
 * A definition list rather than a `<table>` on purpose.
 *
 * facet styles `thead th` at the element level as a saturated blue band — the
 * house look for the instance tables further in. On the cover that band shouts
 * louder than the severity cards beside it, and the second column header would
 * only ever read "Value". Two facts per row are a description list, and a `dl`
 * carries no element styling to fight.
 */
function RunTableRow({ row }: { row: MetadataRow }) {
  const style = METADATA_STYLE[row.kind];
  return (
    <div className="flex items-center gap-[2mm] px-[2.4mm] py-[1.1mm]">
      <dt className="flex w-[22mm] shrink-0 items-center gap-[1.4mm] whitespace-nowrap text-[7.5pt] leading-[10pt] text-gray-500">
        <KindTile style={style} />
        {row.label}
      </dt>
      <dd
        className={`min-w-0 break-all text-[7.5pt] font-medium leading-[10pt] text-gray-900 ${style.mono ? "font-mono" : ""}`}
      >
        {row.value}
      </dd>
    </div>
  );
}

/**
 * Run detail as two columns side by side — what the run was, and what this
 * document is. Stacked into one column the same eleven facts would cost a fifth
 * of the page for rows nobody reads top to bottom.
 */
export function RunTable({ groups }: { groups: MetadataGroup[] }) {
  return (
    <div
      className="mb-[5mm] grid grid-cols-2 overflow-hidden rounded-[1.5mm] border border-gray-200"
      style={{ breakInside: "avoid" }}
    >
      {groups.map((group, index) => (
        <div key={group.title} className={index > 0 ? "border-l border-gray-200" : ""}>
          <div className="border-b border-gray-200 bg-gray-50 px-[2.4mm] py-[1mm] text-[6.5pt] font-semibold uppercase tracking-[0.06em] text-gray-500">
            {group.title}
          </div>
          <dl className="divide-y divide-gray-100">
            {group.rows.map((row) => (
              <RunTableRow key={row.label} row={row} />
            ))}
          </dl>
        </div>
      ))}
    </div>
  );
}

export function SeverityRow({ model }: { model: ScanReportModel }) {
  return (
    <div className="mb-[5mm]">
      <FixedGrid columns={model.severityCards.length + 1}>
        {model.severityCards.map((card) => (
          <SeverityStatCard
            key={card.severity}
            color={SEVERITY_COLOR[card.severity]}
            value={card.value}
            label={card.label}
          />
        ))}
        <SeverityStatCard color="gray" value={model.totalFindings} label="Total" />
      </FixedGrid>
    </div>
  );
}

/**
 * Coverage — what the run reached, beside what it found.
 *
 * A findings count on its own is unreadable: two criticals out of eight targets
 * and two out of eight hundred are different reports. These are the numbers that
 * make the finding count mean something.
 */
export function CoverageSection({ metrics, rate }: { metrics: Metric[]; rate?: PassRate }) {
  return (
    <div className="mb-[5mm]">
      <SectionHeading>Coverage</SectionHeading>
      <FixedGrid columns={balancedColumns(metrics.length)}>
        {metrics.map((metric) => (
          <StatCard
            key={metric.key}
            variant="bordered"
            size="sm"
            shrink
            label={metric.label}
            value={metric.value}
            sublabel={metric.hint}
          />
        ))}
      </FixedGrid>
      {rate && (
        <div className="mt-[2.5mm]">
          {/* The counts are in the title rather than the subtitle: a rate with
              no denominator is the number people misread, and ProgressBar's
              subtitle does not render at this size. */}
          <ProgressBar
            title={`Passing checks — ${rate.passed.toLocaleString("en-US")} of ${(rate.passed + rate.failed).toLocaleString("en-US")}`}
            percentage={rate.percent}
            displayValue={`${rate.percent.toFixed(1)}%`}
            variant={rate.percent >= 90 ? "success" : rate.percent >= 70 ? "warning" : "danger"}
            size="sm"
          />
        </div>
      )}
    </div>
  );
}

export function DisclosureNotes({ notes }: { notes: string[] }) {
  if (notes.length === 0) return null;
  return (
    <aside
      className="mb-[5mm] flex gap-[2mm] rounded-[1.5mm] border border-sky-200 bg-sky-50 p-[2.4mm]"
      role="note"
    >
      <KindTile size="sm" style={{ className: CATEGORY_CLASS.audit, icon: UiInfo }} />
      <div className="min-w-0">
        <h3 className="mb-[1mm] text-[7pt] font-semibold uppercase tracking-[0.08em] text-sky-900">
          Scope of this report
        </h3>
        <ul className="ml-[3mm] list-disc space-y-[0.5mm] text-[8pt] leading-[11pt] text-sky-900">
          {notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      </div>
    </aside>
  );
}

// A short count table is one thing to read, so it is kept whole: split across a
// page boundary the header lands on one page and half the rows on the next.
function CountTable({
  title,
  rows,
  style,
}: {
  title: string;
  rows: Breakdown["rows"];
  style?: (name: string) => TagStyle;
}) {
  return (
    <div style={{ breakInside: "avoid" }}>
      <ListTable
        title={title}
        rows={rows}
        subject="name"
        icon={style ? "name" : undefined}
        iconMap={style ? (value) => <KindTile size="sm" style={style(String(value))} /> : undefined}
        keys={["count"]}
        size="xs"
        maxRows={12}
      />
    </div>
  );
}

/** Which vocabulary names the rows of each breakdown, keyed by what they count. */
const BREAKDOWN_STYLE: Record<string, (name: string) => TagStyle> = {
  severity: severityStyle,
  check: checkStyle,
  resource: resourceStyle,
  tag: tagStyle,
};

export function BreakdownGrid({ breakdowns }: { breakdowns: Breakdown[] }) {
  if (breakdowns.length === 0) return null;
  return (
    <div className="mb-[5mm] grid grid-cols-2 gap-[5mm]">
      {breakdowns.map((breakdown) => (
        <CountTable
          key={breakdown.key}
          title={breakdown.title}
          rows={breakdown.rows}
          style={BREAKDOWN_STYLE[breakdown.key]}
        />
      ))}
    </div>
  );
}

/**
 * Traffic — the requests that matched nothing.
 *
 * Almost every request a scan issues leaves no finding behind, so without this
 * "the scan found nothing" and "the scan never got a response" print identically.
 */
export function TrafficSection({ traffic }: { traffic: TrafficModel }) {
  const breakdowns: Array<[string, Breakdown["rows"], ((name: string) => TagStyle) | undefined]> = [
    ["Status codes", traffic.statusCodes, undefined],
    ["Protocols", traffic.protocols, typeStyle],
    ["Errors", traffic.errors, undefined],
    ["WAF fingerprints", traffic.waf, undefined],
  ];
  return (
    <div className="mb-[5mm]">
      <SectionHeading>Traffic</SectionHeading>
      <div className="mb-[2.5mm]">
        <FixedGrid columns={traffic.totals.length}>
          {traffic.totals.map((total) => (
            <StatCard
              key={total.key}
              variant="bordered"
              size="sm"
              shrink
              label={total.label}
              value={total.value}
            />
          ))}
        </FixedGrid>
      </div>
      <div className="grid grid-cols-2 gap-[5mm]">
        {breakdowns
          .filter(([, rows]) => rows.length > 0)
          .map(([title, rows, style]) => (
            <CountTable key={title} title={title} rows={rows} style={style} />
          ))}
      </div>
    </div>
  );
}
