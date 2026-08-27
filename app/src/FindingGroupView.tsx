import { useCallback, useEffect, useMemo, useState } from "react";
import { Button, Panel } from "@flanksource/clicky-ui/components";
import { DataTable, KeyValueList, Timestamp, type BadgeStatus, type DataTableColumn } from "@flanksource/clicky-ui/data";
import { fetchFindingGroups, fetchFindingStates } from "./api-insights";
import { findingHref, resourceHref } from "./finding-routes";
import { muteCheckPath } from "./mute-prefill";
import { severityBadge } from "./scanColumns";
import { typeTail } from "./resourceColumns";
import type { FindingGroup, FindingState, FindingStatePage } from "./types";

const PAGE_SIZE = 100;

const FINDING_STATUSES: Record<string, BadgeStatus> = {
  open: "error",
  resolved: "success",
  muted: "warning",
  manual: "info",
};

/**
 * One check, and every resource it currently has a verdict about.
 *
 * A page rather than a row that expands: the affected resources are a table,
 * and a table inside a table cell inherits the outer one's scroll container —
 * which is what made the inner header float up over the outer one. It is also
 * the thing someone wants to send a link to.
 */
export function FindingGroupView({
  engine,
  checkId,
  onBack,
  onMuteCheck,
}: {
  engine: string;
  checkId: string;
  onBack: () => void;
  onMuteCheck?: (path: string) => void;
}) {
  const [group, setGroup] = useState<FindingGroup | null>(null);
  const [page, setPage] = useState<FindingStatePage | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);
  const [pageSize, setPageSize] = useState(PAGE_SIZE);
  // The list's search does not follow anyone here. A page about a check that
  // silently showed a subset of its affected resources would answer "how much
  // of the estate does this affect" with a number that is about the search box.
  const [showResolved, setShowResolved] = useState(false);
  const [showMuted, setShowMuted] = useState(false);

  const status = ["open", ...(showResolved ? ["resolved"] : []), ...(showMuted ? ["muted"] : [])].join(",");

  const load = useCallback(async () => {
    setBusy(true);
    setError(null);
    // Cleared rather than left behind: stale rows under a new filter read as
    // the answer to the new question.
    setPage(null);
    try {
      const [groups, states] = await Promise.all([
        fetchFindingGroups({ engine, check: checkId, status, limit: 1 }),
        fetchFindingStates({ engine, check: checkId, status, limit: pageSize, offset }),
      ]);
      setGroup(groups.data[0] ?? null);
      setPage(states);
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setBusy(false);
    }
  }, [checkId, engine, offset, pageSize, status]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => { setOffset(0); }, [status]);

  // Status only earns a column once it can vary: with the default filter every
  // row reads "open", which is the filter talking rather than the data.
  const columns = useMemo(
    () => affectedColumns(showResolved || showMuted),
    [showMuted, showResolved],
  );

  const mutePath = muteCheckPath(checkId, engine);

  return (
    <div className="flex h-full min-h-0 flex-col gap-4 overflow-auto p-4">
      <div className="flex items-center gap-3">
        <Button size="sm" variant="outline" onClick={onBack}>
          Back
        </Button>
        {group && severityBadge(group.severity)}
        <h1 className="truncate text-lg font-semibold">{group?.name ?? checkId}</h1>
        <code className="truncate text-xs text-muted-foreground" title={checkId}>{checkId}</code>
        {onMuteCheck && (
          <Button
            className="ml-auto"
            size="sm"
            variant="outline"
            onClick={() => onMuteCheck(mutePath)}
          >
            Mute this check
          </Button>
        )}
      </div>

      {error && (
        <div role="alert" className="flex items-center gap-3 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          <span className="min-w-0 flex-1">{error}</span>
          <Button size="sm" variant="outline" onClick={() => void load()}>
            Retry
          </Button>
        </div>
      )}

      {/* shrink-0 on both panels: they are flex children of a scrolling
          column, and without it the summary is compressed below its content
          height and its last rows are clipped by the table panel underneath. */}
      <Panel className="shrink-0" title="Check">
        <KeyValueList
          items={[
            { key: "engine", label: "Engine", value: engine },
            { key: "checkId", label: "Check ID", value: checkId },
            { key: "affected", label: "Affected resources", value: group ? String(group.affected) : "—" },
            { key: "states", label: "States", value: group ? stateSummary(group) : "—" },
            {
              key: "lastSeen",
              label: "Last seen",
              // The same renderer the table's column uses: a summary reading
              // "2026-08-25T19:05:54+03:00" above rows reading "15h ago" makes
              // the reader work out that they are the same instant.
              value: group
                ? <Timestamp value={group.lastSeen} format="relative" showTitleOnHover />
                : "—",
            },
          ]}
        />
      </Panel>

      <Panel className="shrink-0" title={`Affected resources${page ? ` (${page.page.total})` : ""}`}>
        <DataTable<FindingState>
          data={page?.data ?? []}
          columns={columns}
          loading={busy}
          getRowId={(row) => row.id}
          // The evidence where a run recorded some, the resource otherwise. A
          // column of identical "View finding" links was a link list a screen
          // reader could not tell apart; the row is the link now.
          getRowHref={(row) => row.finding?.id
            ? findingHref(row.finding.id)
            : resourceHref(row.resource?.id ?? row.resourceId)}
          emptyMessage="This check has no affected resources in the selected states."
          filterBarProps={{
            trailing: (
              <div className="flex items-center gap-2">
                <StatusToggle label="Resolved" selected={showResolved} onClick={() => setShowResolved((value) => !value)} />
                <StatusToggle label="Muted" selected={showMuted} onClick={() => setShowMuted((value) => !value)} />
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
      </Panel>
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

function stateSummary(group: FindingGroup): string {
  return Object.entries(group.statuses)
    .filter(([, count]) => count > 0)
    .map(([status, count]) => `${count} ${status}`)
    .join(" · ") || "none";
}

function resourceCell(row: FindingState) {
  const resource = row.resource;
  return (
    <span className="flex min-w-0 items-baseline gap-2">
      <span className="truncate font-medium">{resource?.name || resource?.uid || row.resourceId}</span>
      {resource?.type && (
        <span className="truncate text-xs text-muted-foreground" title={resource.type}>
          {typeTail(resource.type)}
        </span>
      )}
      {/* A state with no persisted evidence still links somewhere — to the
          resource — so the row must say which of the two it is about. */}
      {!row.finding?.id && (
        <span className="shrink-0 rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground">
          no evidence
        </span>
      )}
    </span>
  );
}

function affectedColumns(withStatus: boolean): DataTableColumn<FindingState>[] {
  return [
    {
      key: "resource",
      label: "Resource",
      grow: true,
      sortable: true,
      sortValue: (_value, row) => row.resource?.name || row.resource?.uid || row.resourceId,
      render: (_value, row) => resourceCell(row),
    },
    {
      key: "account",
      label: "Account",
      sortable: true,
      accessor: (row) => row.resource?.scope,
    },
    {
      key: "region",
      label: "Region",
      sortable: true,
      shrink: true,
      accessor: (row) => row.resource?.region,
    },
    ...(withStatus
      ? [{
          key: "status",
          label: "Status",
          kind: "status" as const,
          status: { map: (raw: unknown) => FINDING_STATUSES[String(raw)] ?? null, showLabel: true },
          shrink: true,
        }]
      : []),
    { key: "occurrences", label: "Occurrences", sortable: true, shrink: true },
    { key: "lastSeen", label: "Last seen", kind: "timestamp", sortable: true },
  ];
}
