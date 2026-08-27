import type { DataTableColumn } from "@flanksource/clicky-ui/data";
import { severityBadge } from "./scanColumns";
import { findingTitle, resourceLabel, severityOf, type Finding } from "./types";

export function typeTail(type: string | undefined): string {
  if (!type) return "";
  const slash = type.lastIndexOf("/");
  return slash === -1 ? type : type.slice(slash + 1);
}

export function findingService(finding: Finding): string {
  const tagged = finding.tags.find((tag) => tag.startsWith("service:"));
  return tagged?.slice("service:".length) || finding.resources?.[0]?.service || "(no service)";
}

function checkCell(finding: Finding) {
  return (
    <div className="flex min-w-0 items-baseline gap-2">
      <span className="truncate font-medium">{findingTitle(finding)}</span>
      <code className="truncate text-xs text-muted-foreground" title={finding.checkId}>
        {finding.checkId}
      </code>
    </div>
  );
}

function resourceCell(finding: Finding) {
  const resource = finding.resources?.[0];
  const label = resource ? resourceLabel(resource) : finding.matchedAt;
  const content = (
    <span className="flex min-w-0 items-baseline gap-2">
      <span className="truncate font-medium">{label}</span>
      {resource?.type && (
        <span className="truncate text-xs text-muted-foreground" title={resource.type}>
          {typeTail(resource.type)}
        </span>
      )}
    </span>
  );
  return resource?.id ? (
    <a
      href={`/resources/${encodeURIComponent(resource.id)}`}
      className="block min-w-0 hover:underline"
      onClick={(event) => event.stopPropagation()}
    >
      {content}
    </a>
  ) : content;
}

function classifications(finding: Finding): string[] {
  return finding.tags.filter((tag) =>
    !["provider:", "service:", "compliance:", "resource-type:"].some((prefix) =>
      tag.startsWith(prefix),
    ),
  );
}

function compliance(finding: Finding): string[] {
  return [...new Set(finding.tags
    .filter((tag) => tag.startsWith("compliance:"))
    .map((tag) => tag.split(":")[1])
    .filter((value): value is string => Boolean(value)))];
}

export const findingListColumns: DataTableColumn<Finding>[] = [
  {
    key: "severity",
    label: "Severity",
    sortable: true,
    shrink: true,
    // From severity_id rather than the column: the record carries OCSF's
    // integer scale, and the ladder the UI groups by is derived from it.
    render: (_value, row) => severityBadge(severityOf(row)),
  },
  {
    key: "checkId",
    label: "Check",
    sortable: true,
    grow: true,
    render: (_value, row) => checkCell(row),
  },
  {
    key: "matchedAt",
    label: "Resource",
    sortable: true,
    grow: true,
    render: (_value, row) => resourceCell(row),
  },
  { key: "host", label: "Account", sortable: true },
  {
    key: "classification",
    label: "Classification",
    render: (_value, row) => {
      const tags = classifications(row);
      return tags.length ? (
        <span className="flex items-center gap-1">
          {tags.slice(0, 3).map((tag) => (
            <span key={tag} className="rounded bg-muted px-1.5 py-0.5 text-xs">{tag}</span>
          ))}
          {tags.length > 3 && <span className="text-xs text-muted-foreground">+{tags.length - 3}</span>}
        </span>
      ) : <span className="text-muted-foreground">—</span>;
    },
  },
  {
    key: "compliance",
    label: "Compliance",
    render: (_value, row) => {
      const frameworks = compliance(row);
      return frameworks.length ? (
        <span className="text-xs" title={frameworks.join(", ")}>{frameworks.length} · {frameworks.join(", ")}</span>
      ) : <span className="text-muted-foreground">—</span>;
    },
  },
];
