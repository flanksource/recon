import { useCallback, useEffect, useMemo, useState } from "react";
import { Button } from "@flanksource/clicky-ui/components";
import { DataTable, type DataTableColumn } from "@flanksource/clicky-ui/data";
import { fetchFindingGroups, syncFindings, type SyncRequest } from "./api-insights";
import { selectionQuery, useEntityFilters } from "./filters";
import { findingGroupHref } from "./finding-routes";
import { severityBadge } from "./scanColumns";
import { SyncInsightsButton } from "./SyncInsightsButton";
import type { FindingGroup, FindingGroupPage } from "./types";

const PAGE_SIZE = 100;
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
    // The row's link is anchored in the first column, so this cell's text is
    // the link's accessible name. Severity alone would announce a table of
    // links all called "high"; the check name says where the link goes without
    // disturbing a layout that is deliberately severity-first.
    // The separator is inside the string rather than between the elements:
    // accessible-name computation trims each node's own edge whitespace, so a
    // bare space between them concatenates to "criticalCloud Storage…".
    render: (value, row) => (
      <>
        {severityBadge(value as FindingGroup["severity"])}
        <span className="sr-only">{`: ${row.name}`}</span>
      </>
    ),
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
  const sync = useCallback((request: SyncRequest) => syncFindings(selector, request), [selector]);

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
        // A real <a> per row rather than an onClick: the check a row stands for
        // is a page someone can link to, open in a new tab, and reach by
        // keyboard — none of which an expanding row offered.
        getRowHref={(row) => findingGroupHref(row.engine, row.checkId)}
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

