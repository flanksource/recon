// The findings half of the report: the summary table, the detail blocks, and
// the appendix.
//
// Page one lives in scan-report-summary.tsx and the shared primitives in
// scan-report-chrome.tsx. Everything here is presentational: it renders what
// scan-report-model.ts already decided, and makes no judgements of its own about
// what a number means.

import { Finding, ListTable } from "@flanksource/facet";

import {
  SEVERITY_BADGE,
  SEVERITY_BORDER,
  type FindingGroup,
  type ParameterRow,
} from "./scan-report-model";
import { ReportMarkdownSection } from "./report-markdown";
import { PageHeading, SectionHeading } from "./scan-report-chrome";
import {
  findingBadges,
  findingTypeIcon,
  resourceInstanceIcon,
  severityBadge,
} from "./scan-report-tags";
import type { ReportFinding, ReportScan } from "./scan-report-types";

const SEVERITY_TAG_MAPPING = (key: string, value: unknown): string =>
  key === "severity" ? (SEVERITY_BADGE[value as keyof typeof SEVERITY_BADGE] ?? "") : "";

export function FindingsSummaryTable({ groups }: { groups: FindingGroup[] }) {
  const rows = groups.map((group, index) => ({
    id: `#${index + 1}`,
    name: group.names.join("; "),
    severity: group.severity,
    check: group.templateId,
    instances: `${group.instances.length} ${group.instances.length === 1 ? "instance" : "instances"}`,
  }));
  return (
    <ListTable
      title="Findings by check"
      rows={rows}
      subject="name"
      primaryTags={["severity"]}
      tagMapping={SEVERITY_TAG_MAPPING}
      keys={["check", "instances"]}
      size="sm"
      emptyMessage="No findings in this scan."
    />
  );
}

/**
 * The parts of a finding that are proof rather than description: where it
 * matched, what was pulled out of the response, and the one-liner that
 * reproduces it. Printed under the finding rather than inside it because a curl
 * line is a code block, and the Finding card has no slot that survives one.
 */
function Evidence({ finding }: { finding: ReportFinding }) {
  const extracted = finding.extracted?.filter(Boolean) ?? [];
  if (extracted.length === 0 && !finding.curl) return null;
  return (
    <div className="mb-4 ml-4 border-l-2 border-gray-200 pl-3">
      <div className="mb-1 text-[8pt] font-semibold text-gray-500">
        Evidence · {finding.scanId}#{finding.lineNo} · {finding.matchedAt}
      </div>
      {extracted.length > 0 && (
        <div className="mb-1 text-[8pt]">
          <span className="text-gray-400">Extracted: </span>
          <span className="font-mono text-gray-700">{extracted.join(", ")}</span>
        </div>
      )}
      {finding.curl && (
        <pre className="overflow-hidden whitespace-pre-wrap break-all rounded bg-gray-50 p-2 font-mono text-[7.5pt] text-gray-700">
          {finding.curl}
        </pre>
      )}
    </div>
  );
}

function InstancesTable({ group }: { group: FindingGroup }) {
  return (
    <div
      className="mb-3 ml-4 border-l-2 border-gray-200 pl-3"
      style={{ breakInside: "avoid" }}
    >
      <h4 className="mb-1 text-sm font-semibold text-slate-800">
        Instances ({group.instances.length})
      </h4>
      <table className="w-full table-fixed border-collapse text-left text-[7.5pt] text-slate-600">
        <thead className="border-b border-slate-200 text-[7pt] font-semibold uppercase tracking-wide text-slate-400">
          <tr>
            <th className="w-[38%] pb-1 pr-2">Name</th>
            <th className="w-[12%] pb-1 pr-2">Region</th>
            <th className="w-[25%] pb-1 pr-2">Type</th>
            <th className="w-[25%] pb-1">UID</th>
          </tr>
        </thead>
        <tbody>
          {group.instances.map((instance) => {
            const InstanceIcon = resourceInstanceIcon(instance.type);
            return (
              <tr
                key={JSON.stringify(instance)}
                className="break-inside-avoid border-b border-slate-100 last:border-b-0"
              >
                <td className="py-1 pr-2 align-top font-medium text-slate-800">
                  <span className="flex items-start gap-1">
                    <InstanceIcon className="mt-px h-3 w-3 shrink-0 text-teal-700" />
                    <span className="break-all">{instance.name || "—"}</span>
                  </span>
                </td>
                <td className="break-all py-1 pr-2 align-top">{instance.region || "—"}</td>
                <td className="break-all py-1 pr-2 align-top">{instance.type || "—"}</td>
                <td className="break-all py-1 align-top font-mono">{instance.uid || "—"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function DetailedFindings({
  groups,
  showEvidence,
}: {
  groups: FindingGroup[];
  showEvidence: boolean;
}) {
  return (
    <div>
      <PageHeading>Detailed findings</PageHeading>
      {groups.map((group, index) => {
        const TypeIcon = findingTypeIcon(group);
        return (
          <div key={group.templateId}>
            <Finding
              id={`#${index + 1}`}
              title={group.names.join("; ")}
              summary={group.templateId}
              typeIcon={<TypeIcon className="h-full w-full" />}
              className={SEVERITY_BORDER[group.severity]}
              severity={severityBadge(group.severity)}
              tags={findingBadges(group)}
              metrics={{
                Instances: group.instances.length,
                ...(group.findings.length === group.instances.length
                  ? {}
                  : { Occurrences: group.findings.length }),
              }}
              references={group.references}
              variant="detail"
            />
            <ReportMarkdownSection title="Description" values={group.descriptions} />
            <ReportMarkdownSection title="Recommended action" values={group.remediations} />
            <InstancesTable group={group} />
            {showEvidence &&
              group.findings.map((finding) => (
                <Evidence key={`${finding.scanId}#${finding.lineNo}`} finding={finding} />
              ))}
          </div>
        );
      })}
    </div>
  );
}

export function Appendix({
  scan,
  parameters,
}: {
  scan: ReportScan;
  parameters: ParameterRow[];
}) {
  return (
    <div>
      <PageHeading>Appendix</PageHeading>

      <SectionHeading>Affected resources ({scan.hosts.length})</SectionHeading>
      {scan.hosts.length === 0 ? (
        <p className="mb-6 text-xs text-gray-500">No resource produced a finding.</p>
      ) : (
        <div className="mb-6 grid grid-cols-3 gap-x-4 gap-y-0.5">
          {scan.hosts.map((host) => (
            <span key={host} className="break-all font-mono text-[8pt] text-gray-700">
              {host}
            </span>
          ))}
        </div>
      )}

      <SectionHeading>Scan parameters</SectionHeading>
      {parameters.length === 0 ? (
        <p className="mb-6 text-xs text-gray-500">
          No effective scan parameters were retained for this run.
        </p>
      ) : (
        <div className="mb-6" style={{ breakInside: "avoid" }}>
          <ListTable
            title="Effective configuration"
            rows={parameters}
            subject="name"
            keys={["value"]}
            size="xs"
          />
        </div>
      )}

      <SectionHeading>Command</SectionHeading>
      {scan.command && scan.command.length > 0 ? (
        <pre className="whitespace-pre-wrap break-all rounded bg-gray-50 p-2 font-mono text-[7.5pt] text-gray-700">
          {scan.command.join(" ")}
        </pre>
      ) : (
        <p className="text-xs text-gray-500">No command recorded.</p>
      )}
    </div>
  );
}
