import {
  Badge,
  type DataTableColumn,
  type BadgeStatus,
} from "@flanksource/clicky-ui";
import type { TableRow, TargetClass } from "./types";

const CLASS_STYLES: Record<TargetClass, string> = {
  public: "bg-sky-500/15 text-sky-600 dark:text-sky-300",
  prod: "bg-red-500/15 text-red-600 dark:text-red-300",
  "non-prod": "bg-emerald-500/15 text-emerald-600 dark:text-emerald-300",
  internal: "bg-amber-500/15 text-amber-600 dark:text-amber-300",
  unclassified: "bg-violet-500/15 text-violet-600 dark:text-violet-300",
  deactivated: "bg-neutral-500/15 text-neutral-500 dark:text-neutral-400",
};

function classPill(cls: TargetClass) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${CLASS_STYLES[cls]}`}
    >
      {cls}
    </span>
  );
}

function httpStatus(raw: unknown): BadgeStatus | null {
  const n = typeof raw === "number" ? raw : Number(raw);
  if (!n) return null;
  if (n >= 500) return "error";
  if (n >= 400) return "warning";
  if (n >= 300) return "info";
  return "success";
}

export function HttpStatusBadge({ value }: { value: unknown }) {
  const status = httpStatus(value);
  return status ? (
    <Badge variant="status" status={status} value={String(value)} />
  ) : (
    "—"
  );
}

function findingsStatus(raw: unknown): BadgeStatus | null {
  const n = typeof raw === "number" ? raw : Number(raw);
  if (Number.isNaN(n)) return null;
  if (n === 0) return "success";
  if (n >= 4) return "error";
  return "warning";
}

export const columns: DataTableColumn<TableRow>[] = [
  {
    key: "host",
    label: "Host",
    grow: true,
    sortable: true,
    render: (value, row) => (
      <div className="flex flex-col">
        <span className="font-medium text-foreground">{String(value)}</span>
        {row.http?.title ? (
          <span className="truncate text-xs text-muted-foreground">
            {row.http.title}
          </span>
        ) : null}
      </div>
    ),
  },
  {
    key: "class",
    label: "Class",
    sortable: true,
    filterable: true,
    render: (value) => classPill(value as TargetClass),
    filterValue: (value) => String(value),
  },
  {
    key: "tags",
    label: "Tags",
    kind: "tags",
    grow: true,
    filterable: true,
    tags: { maxVisible: 4 },
  },
  {
    key: "profiles",
    label: "Profiles",
    kind: "tags",
    filterable: true,
    shrink: true,
  },
  { key: "app", label: "App", sortable: true, filterable: true },
  { key: "cluster", label: "Cluster", sortable: true, filterable: true },
  {
    key: "last_status",
    label: "Status",
    shrink: true,
    align: "center",
    sortable: true,
    render: (value) => <HttpStatusBadge value={value} />,
  },
  {
    key: "response_time",
    label: "Response",
    shrink: true,
    sortable: true,
  },
  {
    key: "open_ports",
    label: "Open ports",
    kind: "tags",
    shrink: true,
    tags: { maxVisible: 3 },
  },
  {
    key: "known_paths",
    label: "Known paths",
    kind: "tags",
    grow: true,
    tags: { maxVisible: 2 },
  },
  {
    key: "login_methods",
    label: "Login methods",
    kind: "tags",
    grow: true,
    tags: { maxVisible: 2 },
  },
  {
    key: "findings",
    label: "Findings",
    kind: "status",
    shrink: true,
    align: "center",
    sortable: true,
    status: {
      map: findingsStatus,
      showLabel: true,
      title: (raw) => `${raw ?? 0} finding(s) at last scan`,
    },
  },
  {
    key: "first_observed",
    label: "First seen",
    kind: "timestamp",
    sortable: true,
    timestamp: { mode: "relative", alwaysShowFullOnHover: true },
  },
  {
    key: "last_seen",
    label: "Last seen",
    kind: "timestamp",
    sortable: true,
    timestamp: { mode: "relative", alwaysShowFullOnHover: true },
  },
  {
    key: "last_scan",
    label: "Last scan",
    kind: "timestamp",
    sortable: true,
    timestamp: { mode: "relative", alwaysShowFullOnHover: true },
  },
  {
    key: "source",
    label: "Source",
    hideable: true,
    render: (value) =>
      value ? (
        <code className="text-xs text-muted-foreground">{String(value)}</code>
      ) : null,
  },
];
