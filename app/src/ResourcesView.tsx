import { useCallback, useEffect, useMemo, useState } from "react";
import { Button } from "@flanksource/clicky-ui/components";
import { DataTable, type DataTableGroupingMode } from "@flanksource/clicky-ui/data";
import { resourceColumns } from "./resourceColumns";
import { selectionQuery, useEntityFilters } from "./filters";
import { fetchResources, type Resource, type ResourcePage } from "./api-resources";
import { syncResources, type SyncRequest } from "./api-insights";
import { SyncInsightsButton } from "./SyncInsightsButton";

const PAGE_SIZE = 100;
const RESOURCE_SORT_KEYS: Record<string, string> = {
  worst: "worst",
  name: "name",
  type: "type",
  scope: "account",
  region: "region",
  firstSeen: "first-seen",
  lastSeen: "last-seen",
  findings: "findings",
};

const RESOURCE_GROUPINGS: Array<DataTableGroupingMode<Resource>> = [
  {
    type: "custom",
    value: "account",
    label: "By account",
    getGroupKey: (row) => row.scope || "(no account)",
    getGroupLabel: (key) => key,
  },
  {
    type: "custom",
    value: "service",
    label: "By service",
    getGroupKey: (row) => row.service || "(no service)",
    getGroupLabel: (key) => key,
  },
  {
    type: "custom",
    value: "type",
    label: "By type",
    getGroupKey: (row) => row.type || "(no type)",
    getGroupLabel: (key) => key,
  },
  {
    type: "custom",
    value: "region",
    label: "By region",
    getGroupKey: (row) => row.region || "(no region)",
    getGroupLabel: (key) => key,
  },
  { type: "none", value: "none", label: "No grouping" },
];

/**
 * The estate: everything the scans examined, not only what they found wrong.
 *
 * Paged against the server rather than loaded whole. Targets are curated by
 * hand and bounded by human effort; resources are enumerated by a machine and
 * bounded by nothing — 94 for two GCP projects, four orders of magnitude more
 * for one AWS estate.
 */
export function ResourcesView({
  onOpenResource,
}: {
  onOpenResource: (id: string) => void;
}) {
  const [page, setPage] = useState<ResourcePage | null>(null);
  const [offset, setOffset] = useState(0);
  const [pageSize, setPageSize] = useState(PAGE_SIZE);
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<{ key: string; dir: "asc" | "desc" }>({
    key: "worst",
    dir: "asc",
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { filters, selection, error: filterError } = useEntityFilters("resource");
  const selector = useMemo(() => ({
    ...selectionQuery(selection),
    ...(query ? { search: query } : {}),
  }), [query, selection]);
  const sync = useCallback((request: SyncRequest) => syncResources(selector, request), [selector]);

  const load = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      setPage(
        await fetchResources({
          ...(selectionQuery(selection) as Record<string, string | string[]>),
          limit: pageSize,
          offset,
          // Server-side, because a page is not the whole set: narrowing in the
          // browser would search the hundred rows on screen and call the result
          // a search of the estate.
          ...(query ? { search: query } : {}),
          sort: RESOURCE_SORT_KEYS[sort.key] ?? "worst",
          order: sort.dir,
        }),
      );
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [selection, offset, pageSize, query, sort]);

  useEffect(() => {
    void load();
  }, [load]);

  // Narrowing returns to the first page. Staying on page four of a set that now
  // has two is an empty table that reads as "no matches".
  const narrowed = JSON.stringify(selection) + query;
  useEffect(() => {
    setOffset(0);
  }, [narrowed]);

  const rows = page?.data ?? [];
  const total = page?.page.total ?? 0;
  const filtered = hasSelection(selection) || query !== "";

  // Distinct empty states, because conflating them is exactly the failure
  // recording passing checks was meant to remove. Nothing recorded yet is a
  // different fact from nothing matching a filter, and the first is not the
  // table's to explain in an emptyMessage.
  //
  // `page` rather than `total`, and that is the whole point: a request that
  // failed leaves no page, and a null page is not an empty estate. Reading the
  // count alone would answer a transient API error with "you have no
  // resources" — stating as fact something recon does not know.
  const nothingRecorded = !busy && !error && page !== null && total === 0 && !filtered;

  return (
    <div className="flex h-full min-h-0 flex-col">
      {(error || filterError) && (
        <div className="border-b border-border bg-destructive/10 px-4 py-2 text-sm text-destructive">
          {error ?? filterError}
        </div>
      )}

      {nothingRecorded ? (
        <div className="p-6">
          <h2 className="text-lg font-semibold">No resources yet</h2>
          <p className="mt-1 max-w-prose text-sm text-muted-foreground">
            Resources are recorded by a scan. Run one against a cloud account —
            Prowler and InSpec report every resource they examine, including the
            ones every check passed on.
          </p>
        </div>
      ) : (
        <DataTable<Resource>
            className="min-h-0 flex-1"
            data={rows}
            columns={resourceColumns}
            loading={busy}
            getRowId={(row) => row.id}
            getRowHref={(row) => `/resources/${encodeURIComponent(row.id)}`}
            onRowClick={(row) => onOpenResource(row.id)}
            isRowClickable={() => true}
            externalFilters={filters}
            filterBarProps={{ trailing: <SyncInsightsButton sync={sync} /> }}
            showGlobalFilter
            globalFilter={query}
          // Server-side. The rows on screen are one page of the estate, so
          // narrowing them in the browser would search a hundred rows and
          // report the result as a search of everything.
            onGlobalFilterChange={setQuery}
            manualFilter
            sort={sort}
            onSortChange={(next) => {
              setSort(next ?? { key: "worst", dir: "asc" });
              setOffset(0);
            }}
            manualSort
            groupingModes={RESOURCE_GROUPINGS}
            defaultGroupingMode="account"
            emptyMessage="No resources match these filters."
          // The framework's own footer rather than a hand-rolled one: it
          // already renders "Page X of Y" from a total the server counted, and
          // knows the difference between a count and a lower bound.
            pagination={{
              page: Math.floor(offset / pageSize),
              pageSize,
              total,
              totalRelation: "eq",
              onPageChange: (next) => setOffset(next * pageSize),
              onPageSizeChange: (next) => {
                setPageSize(next);
                setOffset(0);
              },
            }}
          />
      )}

      {/* Deliberately outside the table. With filters in the URL a deep link to
          an empty result is otherwise a dead end, and emptyMessage takes a
          string — a button inside it is not something the table can render. */}
      {!busy && rows.length === 0 && filtered && (
        <div className="flex justify-center border-t border-border py-3">
          <Button size="sm" variant="outline" onClick={() => setQuery("")}>
            Clear search
          </Button>
        </div>
      )}
    </div>
  );
}

function hasSelection(selection: unknown): boolean {
  const query = selectionQuery(selection as never) as Record<string, unknown>;
  return Object.values(query).some(
    (value) => value !== undefined && value !== "" && (!Array.isArray(value) || value.length > 0),
  );
}
