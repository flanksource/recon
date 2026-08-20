import {
  Badge,
  type DataTableColumn,
  type BadgeStatus,
} from "@flanksource/clicky-ui";
import type {
  ProbeFailure,
  TableRow,
  TargetClass,
  TargetKind,
} from "./types";
import { targetKind } from "./types";

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

const KIND_LABELS: Record<TargetKind, string> = {
  host: "Host",
  "gcp-project": "GCP project",
};

function kindPill(kind: TargetKind) {
  return (
    <span className="inline-flex items-center rounded-full bg-slate-500/15 px-2 py-0.5 text-xs font-medium text-slate-600 dark:text-slate-300">
      {KIND_LABELS[kind] ?? kind}
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

function HttpStatusBadge({ value }: { value: unknown }) {
  const status = httpStatus(value);
  return status ? (
    <Badge variant="status" status={status} value={String(value)} />
  ) : (
    "—"
  );
}

// Short enough to sit in a narrow column and still name the problem. "http" is
// absent: a served error status is a status, and the code itself says more than
// the word would.
const FAILURE_LABELS: Record<Exclude<ProbeFailure, "http">, string> = {
  dns: "DNS",
  refused: "refused",
  unreachable: "unreachable",
  timeout: "timeout",
  tls: "TLS",
  other: "error",
};

/**
 * What the Status column shows for a host whose last probe did not get through.
 *
 * A failed probe deliberately keeps the status code from the host's last good
 * probe, so without this the row of a host that no longer resolves still reads
 * as a green 200 — which was the whole problem.
 */
export function TargetStatusBadge({
  failure,
  value,
}: {
  failure?: ProbeFailure;
  value: unknown;
}) {
  if (!failure || failure === "http") return <HttpStatusBadge value={value} />;
  return (
    <Badge variant="status" status="error" value={FAILURE_LABELS[failure]} />
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
    key: "kind",
    label: "Kind",
    sortable: true,
    filterable: true,
    // Read through targetKind rather than the raw value: the server omits the
    // field for a host, so filtering on the cell would offer an empty option
    // for every host in the inventory.
    render: (_value, row) => kindPill(targetKind(row)),
    filterValue: (_value, row) => targetKind(row),
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
    render: (value, row) => (
      <TargetStatusBadge failure={row.failure} value={value} />
    ),
  },
  {
    key: "response_time",
    label: "Response",
    shrink: true,
    sortable: true,
  },
  {
    key: "last_error",
    label: "Error",
    grow: true,
    hideable: true,
    render: (value) =>
      value ? (
        // Truncated with the whole message on hover: a wrapped dial error is
        // several lines long and would set the height of every row in the table.
        <span
          className="block truncate text-xs text-destructive"
          title={String(value)}
        >
          {String(value)}
        </span>
      ) : null,
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
