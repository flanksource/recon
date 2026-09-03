import type { DataTableColumn } from "@flanksource/clicky-ui/data";
import { ResourceIcon } from "@flanksource/icons/icon";
import { severityBadge } from "./scanColumns";
import type { Resource } from "./api-resources";
import type { Severity } from "./types";

const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
  "unknown",
];

/**
 * The tail of a provider type: `Firewall` from
 * `compute.googleapis.com/Firewall`.
 *
 * Rendered short because the prefix is the same for every row of a service and
 * carries no information at a glance. The whole string stays in `title` and in
 * the column's filterValue, so it is still readable and still searchable.
 */
export function typeTail(type: string | undefined): string {
  if (!type) return "";
  const cut = type.lastIndexOf("/");
  return cut === -1 ? type : type.slice(cut + 1);
}

/**
 * A severity-weighted sort key for a resource's open findings.
 *
 * Sorting on the count alone puts ten `info` findings above one `critical`,
 * which is exactly backwards for a table whose default sort is meant to surface
 * what needs attention. Weighting by rank keeps the worst first and uses the
 * count only to break ties within a severity.
 */
export function findingWeight(resource: Resource): number {
  const severities = resource.severities ?? {};
  return SEVERITY_ORDER.reduce((weight, severity, index) => {
    const count = severities[severity] ?? 0;
    return weight + count * Math.pow(1000, SEVERITY_ORDER.length - index);
  }, 0);
}

function worstSeverity(resource: Resource): Severity | null {
  return SEVERITY_ORDER.find((severity) => (resource.severities?.[severity] ?? 0) > 0) ?? null;
}

function severityStrip(resource: Resource) {
  const severities = resource.severities ?? {};
  const present = SEVERITY_ORDER.filter((s) => (severities[s] ?? 0) > 0);
  if (present.length === 0) {
    return <span className="text-xs text-muted-foreground">—</span>;
  }
  const total = present.reduce((sum, severity) => sum + (severities[severity] ?? 0), 0);
  const colors: Record<Severity, string> = {
    critical: "bg-red-600", high: "bg-orange-500", medium: "bg-amber-500",
    low: "bg-sky-500", info: "bg-neutral-400", unknown: "bg-neutral-300",
  };
  return (
    <span className="inline-flex items-center gap-2">
      <span
        role="img"
        aria-label={present.map((severity) => `${severities[severity]} ${severity}`).join(", ")}
        className="flex h-2 w-24 overflow-hidden rounded-full bg-muted"
      >
        {present.map((severity) => (
          <span
            key={severity}
            className={colors[severity]}
            style={{ width: `${((severities[severity] ?? 0) / total) * 100}%` }}
          />
        ))}
      </span>
      <span className="text-xs tabular-nums">{total}</span>
    </span>
  );
}

/**
 * The name, with the uid underneath only when they differ.
 *
 * Half of Prowler's uids are opaque numbers — a GCP firewall's is
 * 1429543158501771126 and its name is `tailscale-router` — so the name is what
 * an operator recognises and the uid is what a query needs. Showing both
 * unconditionally would double the row height of every table for the half of
 * rows where they are the same string.
 */
function nameCell(resource: Resource) {
  const name = resource.name || resource.uid;
  const icon = resource.configType || resource.type || resource.provider;
  return (
    <div className="flex min-w-0 items-baseline gap-2">
      <span
        role="img"
        aria-label={`${icon} icon`}
        className="inline-flex size-5 shrink-0 self-center items-center justify-center text-muted-foreground"
      >
        <ResourceIcon
          primary={resource.configType || resource.type}
          secondary={resource.configType ? resource.type : resource.provider}
          className="size-5"
          aria-hidden="true"
        />
      </span>
      <span className="truncate font-medium">{name}</span>
      {resource.uid && resource.uid !== name && (
        <span className="truncate text-xs text-muted-foreground" title={resource.uid}>
          {resource.uid}
        </span>
      )}
    </div>
  );
}

export const resourceColumns: DataTableColumn<Resource>[] = [
  {
    key: "worst",
    label: "Worst",
    shrink: true,
    sortable: true,
    render: (_value, row) => {
      const severity = worstSeverity(row);
      return severity ? severityBadge(severity) : <span className="text-xs text-muted-foreground">clean</span>;
    },
  },
  {
    key: "name",
    label: "Resource",
    sortable: true,
    render: (_value, row) => nameCell(row),
    // Both names, so a row the server matched on uid is not then hidden by
    // DataTable's second, client-side filtering pass over the visible text.
    filterValue: (_value, row) => `${row.name ?? ""} ${row.uid}`,
    sortValue: (_value, row) => (row.name || row.uid).toLowerCase(),
  },
  {
    key: "type",
    label: "Type",
    sortable: true,
    render: (_value, row) => (
      <span title={row.type} className="text-sm">
        {typeTail(row.type)}
      </span>
    ),
    filterValue: (_value, row) => row.type ?? "",
  },
  { key: "scope", label: "Account", sortable: true },
  { key: "region", label: "Region", sortable: true },
  {
    key: "firstSeen",
    label: "First seen",
    kind: "timestamp",
    filterKey: "first-seen",
    sortable: true,
    shrink: true,
  },
  {
    key: "lastSeen",
    label: "Last seen",
    kind: "timestamp",
    filterKey: "last-seen",
    sortable: true,
    shrink: true,
  },
  {
    key: "findings",
    label: "Findings",
    sortable: true,
    render: (_value, row) => severityStrip(row),
    // Descending, because the point of the column is what is wrong.
    sortValue: (_value, row) => -findingWeight(row),
    filterValue: (_value, row) => Object.keys(row.severities ?? {}).join(" "),
  },
  {
    key: "state",
    label: "State",
    render: (value) =>
      value === "absent" ? (
        <span className="text-xs text-muted-foreground" title="a covering run no longer sees it">
          last seen
        </span>
      ) : (
        <span className="text-xs">present</span>
      ),
  },
];
