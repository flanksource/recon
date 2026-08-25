import { useCallback, useEffect, useMemo, useState } from "react";
import { Button } from "@flanksource/clicky-ui/components";
import { DataTable, type BadgeStatus, type DataTableColumn } from "@flanksource/clicky-ui/data";
import { fetchFindingGroups, fetchFindingStates, syncFindings } from "./api-insights";
import { selectionQuery, useEntityFilters } from "./filters";
import { severityBadge } from "./scanColumns";
import { SyncInsightsButton } from "./SyncInsightsButton";
import type { FindingGroup, FindingGroupPage, FindingState, FindingStatePage } from "./types";

const PAGE_SIZE = 100;
const FINDING_STATUSES: Record<string, BadgeStatus> = {
  open: "error",
  resolved: "success",
  muted: "warning",
  manual: "info",
};
const findingStatus = (raw: unknown): BadgeStatus | null => FINDING_STATUSES[String(raw)] ?? null;
const FINDING_SORT_KEYS: Record<string, string> = {
  severity: "severity",
  name: "check",
  affected: "affected",
  lastSeen: "last-seen",
};

const findingGroupColumns: DataTableColumn<FindingGroup>[] = [
  {
    key: "severity",
    label: "Severity",
    sortable: true,
    shrink: true,
    render: (value) => severityBadge(value as FindingGroup["severity"]),
  },
  {
    key: "name",
    label: "Check",
    sortable: true,
    grow: true,
    render: (_value, row) => (
      <div className="flex min-w-0 items-baseline gap-2">
        <span className="truncate font-medium">{row.name}</span>
        <span className="truncate text-xs text-muted-foreground">{row.checkId}</span>
      </div>
    ),
  },
  { key: "engine", label: "Engine", shrink: true },
  { key: "affected", label: "Affected", sortable: true, shrink: true },
  {
    key: "statuses",
    label: "States",
    render: (_value, row) => Object.entries(row.statuses)
      .filter(([, count]) => count > 0)
      .map(([status, count]) => `${count} ${status}`)
      .join(" · "),
  },
  { key: "lastSeen", label: "Last seen", kind: "timestamp", sortable: true },
];

const findingStateColumns: DataTableColumn<FindingState>[] = [
  {
    key: "resource",
    label: "Resource",
    grow: true,
    render: (_value, row) => row.resource ? (
      <a className="font-medium hover:underline" href={`/resources/${encodeURIComponent(row.resource.id ?? row.resourceId)}`}>
        {row.resource.name || row.resource.uid}
      </a>
    ) : row.resourceId,
  },
  { key: "account", label: "Account", accessor: (row) => row.resource?.scope },
  {
    key: "finding",
    label: "Finding",
    shrink: true,
    render: (_value, row) => row.finding?.id ? (
      <a className="font-medium text-primary hover:underline" href={`/findings/${encodeURIComponent(row.finding.id)}`}>
        View finding
      </a>
    ) : <span className="text-muted-foreground">Finding unavailable</span>,
  },
  {
    key: "status",
    label: "Status",
    kind: "status",
    status: { map: findingStatus, showLabel: true },
    shrink: true,
  },
  { key: "lastSeen", label: "Last seen", kind: "timestamp" },
  { key: "occurrences", label: "Occurrences", shrink: true },
];

export function FindingsView() {
  const [page, setPage] = useState<FindingGroupPage | null>(null);
  const [offset, setOffset] = useState(0);
  const [pageSize, setPageSize] = useState(PAGE_SIZE);
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<{ key: string; dir: "asc" | "desc" }>({ key: "severity", dir: "asc" });
  const [showResolved, setShowResolved] = useState(false);
  const [showMuted, setShowMuted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { filters, selection, error: filterError } = useEntityFilters("finding-group", { exclude: ["status"] });

  const selector = useMemo(() => ({
    ...selectionQuery(selection),
    status: ["open", ...(showResolved ? ["resolved"] : []), ...(showMuted ? ["muted"] : [])].join(","),
    ...(query ? { search: query } : {}),
  }), [query, selection, showMuted, showResolved]);

  const load = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      setPage(await fetchFindingGroups({
        ...selector,
        limit: pageSize,
        offset,
        sort: FINDING_SORT_KEYS[sort.key] ?? "severity",
        order: sort.dir,
      }));
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setBusy(false);
    }
  }, [offset, pageSize, selector, sort]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => { setOffset(0); }, [selector]);
  const sync = useCallback((dryRun: boolean) => syncFindings(selector, dryRun), [selector]);

  return (
    <div className="flex h-full min-h-0 flex-col">
      {(error || filterError) && (
        <div role="alert" className="border-b border-border bg-destructive/10 px-4 py-2 text-sm text-destructive">
          {error ?? filterError}
        </div>
      )}
      <DataTable<FindingGroup>
        className="min-h-0 flex-1"
        data={page?.data ?? []}
        columns={findingGroupColumns}
        loading={busy}
        getRowId={(row) => `${row.engine}/${row.checkId}`}
        renderExpandedRow={(row) => <AffectedResources group={row} selector={selector} />}
        externalFilters={filters}
        showGlobalFilter
        globalFilter={query}
        globalFilterPlaceholder="Search checks and affected resources…"
        onGlobalFilterChange={setQuery}
        manualFilter
        sort={sort}
        onSortChange={(next) => {
          setSort(next ?? { key: "severity", dir: "asc" });
          setOffset(0);
        }}
        manualSort
        emptyMessage="No current findings match these filters."
        filterBarProps={{
          trailing: (
            <div className="flex items-center gap-2">
              <StatusToggle label="Resolved" selected={showResolved} onClick={() => setShowResolved((value) => !value)} />
              <StatusToggle label="Muted" selected={showMuted} onClick={() => setShowMuted((value) => !value)} />
              <SyncInsightsButton sync={sync} />
            </div>
          ),
        }}
        pagination={{
          page: Math.floor(offset / pageSize),
          pageSize,
          total: page?.page.total ?? 0,
          totalRelation: "eq",
          onPageChange: (next) => setOffset(next * pageSize),
          onPageSizeChange: (next) => {
            setPageSize(next);
            setOffset(0);
          },
        }}
      />
    </div>
  );
}

function StatusToggle({ label, selected, onClick }: { label: string; selected: boolean; onClick: () => void }) {
  return (
    <Button size="sm" variant={selected ? "secondary" : "outline"} aria-pressed={selected} onClick={onClick}>
      {label}
    </Button>
  );
}

function AffectedResources({ group, selector }: { group: FindingGroup; selector: Record<string, string> }) {
  const [page, setPage] = useState<FindingStatePage | null>(null);
  const [offset, setOffset] = useState(0);
  const [pageSize, setPageSize] = useState(PAGE_SIZE);
  const [error, setError] = useState<string | null>(null);
  const selectorKey = JSON.stringify(selector);

  useEffect(() => {
    let live = true;
    setError(null);
    fetchFindingStates({
      ...JSON.parse(selectorKey) as Record<string, string>,
      engine: group.engine,
      check: group.checkId,
      limit: pageSize,
      offset,
    })
      .then((result) => { if (live) setPage(result); })
      .catch((cause: Error) => { if (live) setError(cause.message); });
    return () => { live = false; };
  }, [group.checkId, group.engine, offset, pageSize, selectorKey]);

  if (error) return <p role="alert" className="p-3 text-sm text-destructive">{error}</p>;
  return (
    <div className="bg-muted/20 p-3">
      <DataTable<FindingState>
        data={page?.data ?? []}
        columns={findingStateColumns}
        getRowId={(row) => row.id}
        emptyMessage="No affected resources match these filters."
        pagination={{
          page: Math.floor(offset / pageSize),
          pageSize,
          total: page?.page.total ?? 0,
          totalRelation: "eq",
          onPageChange: (next) => setOffset(next * pageSize),
          onPageSizeChange: (next) => {
            setPageSize(next);
            setOffset(0);
          },
        }}
      />
    </div>
  );
}
