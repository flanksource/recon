import type { DataTableColumn, BadgeStatus } from "@flanksource/clicky-ui/data";
import { findingSearchTokens } from "./finding-markdown";
import { resourceLabel, type Finding, type Severity } from "./types";

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
    filterValue: (_value, row) => findingSearchTokens(row),
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
  // What the finding is about, not where the engine happened to match.
  //
  // This column used to render matchedAt as a link. That is a URL for nuclei and
  // nothing of the kind for anything else — a prowler finding rendered
  // <a href="1429543158501771126">, which is a broken link on every row of a
  // cloud posture scan. A resource is only a link when the engine named one that
  // is addressable.
  {
    key: "resources",
    label: "Resource",
    grow: true,
    filterValue: (_value, row) => resourceSearchText(row),
    render: (_value, row) => <ResourceCell finding={row} />,
  },
];

/** The text a resource column is searched and filtered by: every name and uid. */
function resourceSearchText(finding: Finding): string {
  const resources = finding.resources ?? [];
  if (resources.length === 0) return finding.matchedAt ?? "";
  return resources.flatMap((r) => [r.name ?? "", r.uid, r.type ?? ""]).filter(Boolean).join(" ");
}

function ResourceCell({ finding }: { finding: Finding }) {
  const resources = finding.resources ?? [];
  if (resources.length === 0) {
    return <span className="text-xs text-muted-foreground">{finding.matchedAt}</span>;
  }

  const [primary, ...rest] = resources;
  const label = resourceLabel(primary);
  const href = addressable(label) ?? addressable(primary.uid);
  return (
    <span className="flex items-baseline gap-1.5">
      {href ? (
        <a
          href={href}
          target="_blank"
          rel="noreferrer"
          className="text-xs text-primary hover:underline"
        >
          {label}
        </a>
      ) : (
        <span className="text-xs text-foreground">{label}</span>
      )}
      {primary.type ? (
        <code className="text-[10px] text-muted-foreground">{shortType(primary.type)}</code>
      ) : null}
      {rest.length > 0 ? (
        <span className="text-[10px] text-muted-foreground">+{rest.length}</span>
      ) : null}
    </span>
  );
}

/**
 * A value a browser can open, or null.
 *
 * Only a URL qualifies — a GCP resource id, an ARN and a package coordinate are
 * all identifiers, and linking them is what produced the broken anchors this
 * column replaced. Both the label and the uid are offered because which of them
 * holds the URL depends on the engine: nuclei's endpoint arrives as the label
 * and a cloud resource's identity as the uid.
 */
function addressable(value: string): string | null {
  return value.startsWith("http://") || value.startsWith("https://") ? value : null;
}

/**
 * The readable tail of a provider type. Every GCP asset type is prefixed
 * `<service>.googleapis.com/`, which is the same on every row and so carries no
 * information in a column; the full value stays searchable and is on the title.
 */
function shortType(type: string): string {
  const slash = type.lastIndexOf("/");
  return slash === -1 ? type : type.slice(slash + 1);
}
