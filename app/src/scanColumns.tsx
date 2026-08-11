import type { DataTableColumn, BadgeStatus } from "@flanksource/clicky-ui";
import type { Finding, Severity } from "./types";

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  unknown: 5,
};

export function worstSeverity(findings: { severity: Severity }[]): Severity {
  return findings.reduce<Severity>(
    (worst, f) => (SEVERITY_RANK[f.severity] < SEVERITY_RANK[worst] ? f.severity : worst),
    "unknown",
  );
}

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "bg-red-600/20 text-red-700 dark:text-red-300",
  high: "bg-orange-500/20 text-orange-700 dark:text-orange-300",
  medium: "bg-amber-500/20 text-amber-700 dark:text-amber-300",
  low: "bg-sky-500/20 text-sky-700 dark:text-sky-300",
  info: "bg-neutral-500/15 text-neutral-600 dark:text-neutral-300",
  unknown: "bg-neutral-500/15 text-neutral-500",
};

export function severityBadge(sev: Severity) {
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-semibold uppercase ${SEVERITY_STYLE[sev]}`}
    >
      {sev}
    </span>
  );
}

export function severityStatus(sev: Severity): BadgeStatus | null {
  if (sev === "critical" || sev === "high") return "error";
  if (sev === "medium") return "warning";
  if (sev === "low") return "info";
  return null;
}

export const findingColumns: DataTableColumn<Finding>[] = [
  {
    key: "severity",
    label: "Severity",
    sortable: true,
    filterable: true,
    shrink: true,
    render: (value) => severityBadge(value as Severity),
    sortValue: (value) => SEVERITY_RANK[value as Severity] ?? 9,
    filterValue: (value) => String(value),
  },
  {
    key: "name",
    label: "Finding",
    grow: true,
    sortable: true,
    render: (value, row) => (
      <div className="flex flex-col">
        <span className="font-medium text-foreground">{String(value)}</span>
        <code className="text-xs text-muted-foreground">
          {row.templateId}
          {row.matcherName ? ` · ${row.matcherName}` : ""}
        </code>
      </div>
    ),
  },
  { key: "host", label: "Host", sortable: true, filterable: true, grow: true },
  { key: "type", label: "Type", sortable: true, filterable: true, shrink: true },
  {
    key: "tags",
    label: "Tags",
    kind: "tags",
    filterable: true,
    tags: { maxVisible: 3 },
  },
  {
    key: "matchedAt",
    label: "Matched at",
    grow: true,
    render: (value) =>
      value ? (
        <a
          href={String(value)}
          target="_blank"
          rel="noreferrer"
          className="text-xs text-primary hover:underline"
        >
          {String(value)}
        </a>
      ) : null,
  },
];

