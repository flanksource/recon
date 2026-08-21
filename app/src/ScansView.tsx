import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  AppShell,
  Button,
  Select,
  Tabs,
} from "@flanksource/clicky-ui/components";
import {
  DataTable,
  type DataTableGrouping,
} from "@flanksource/clicky-ui/data";
import { fetchFindings, fetchScan, fetchScans } from "./api";
import { selectionQuery, useEntityFilters } from "./filters";
import { findingColumns, severityBadge, SEVERITY_RANK, worstSeverity } from "./scanColumns";
import { FindingDetail } from "./FindingDetail";
import { SEVERITIES, type Finding, type Scan, type Severity } from "./types";
import { ScanExecutionDetails } from "./ScanExecutionDetails";

type GroupBy = "type" | "severity" | "host" | "none";

// The select carries no visible label — the header row has no room for one — so
// each option says what it groups by rather than naming a bare dimension.
const GROUP_OPTIONS: { value: GroupBy; label: string }[] = [
  { value: "type", label: "By result type" },
  { value: "severity", label: "By severity" },
  { value: "host", label: "By affected domain" },
  { value: "none", label: "No grouping" },
];

function uniqueHosts(findings: Finding[]): string[] {
  return [...new Set(findings.map((f) => f.host).filter(Boolean))].sort();
}

// Compact "affected domains" chip list rendered at the trailing edge of a group
// header. It has to stay on one line: DataTable truncates the header label, and
// the meta slot never wraps — so the list is capped and the rest is a tooltip.
function DomainChips({ hosts }: { hosts: string[] }) {
  if (hosts.length === 0) return null;
  const shown = hosts.slice(0, 3);
  const extra = hosts.length - shown.length;
  return (
    <span className="flex items-center gap-1" title={hosts.join("\n")}>
      {shown.map((h) => (
        <span key={h} className="max-w-52 truncate rounded bg-muted px-1.5 py-0.5 text-xs">
          {h}
        </span>
      ))}
      {extra > 0 && <span className="text-xs text-muted-foreground">+{extra}</span>}
    </span>
  );
}

// DataTable already renders the row count beside every group header, so the meta
// slot carries what it does not know: which hosts the group touches.
function buildGrouping(groupBy: GroupBy): DataTableGrouping<Finding> | undefined {
  if (groupBy === "none") return undefined;

  if (groupBy === "host") {
    return {
      getGroupKey: (row) => row.host || "(no host)",
      getGroupLabel: (key, rows) => (
        <span className="flex items-center gap-2">
          {severityBadge(worstSeverity(rows))}
          <span className="font-medium">{key}</span>
        </span>
      ),
      compareGroups: (a, b) =>
        SEVERITY_RANK[worstSeverity(a.rows)] - SEVERITY_RANK[worstSeverity(b.rows)] ||
        b.rows.length - a.rows.length,
    };
  }

  if (groupBy === "severity") {
    return {
      getGroupKey: (row) => row.severity,
      getGroupLabel: (key) => severityBadge(key as Severity),
      getGroupMeta: (_key, rows) => <DomainChips hosts={uniqueHosts(rows)} />,
      compareGroups: (a, b) =>
        SEVERITY_RANK[a.key as Severity] - SEVERITY_RANK[b.key as Severity],
    };
  }

  // Default: group by result type (template), show affected domains in the header.
  return {
    getGroupKey: (row) => row.templateId,
    getGroupLabel: (key, rows) => (
      <span className="flex items-center gap-2">
        {severityBadge(worstSeverity(rows))}
        <span className="font-medium">{rows[0]?.name ?? key}</span>
        <code className="text-xs text-muted-foreground">{key}</code>
      </span>
    ),
    getGroupMeta: (_key, rows) => <DomainChips hosts={uniqueHosts(rows)} />,
    compareGroups: (a, b) =>
      SEVERITY_RANK[worstSeverity(a.rows)] - SEVERITY_RANK[worstSeverity(b.rows)] ||
      b.rows.length - a.rows.length,
  };
}

const SEVERITY_BAR: Record<Severity, string> = {
  critical: "bg-red-600",
  high: "bg-orange-500",
  medium: "bg-amber-500",
  low: "bg-sky-500",
  info: "bg-neutral-400",
  unknown: "bg-neutral-300",
};

function relative(iso: string): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const s = Math.round((Date.now() - then) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

function SeverityBar({ run }: { run: Scan }) {
  const total = run.findings || 1;
  return (
    <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-muted">
      {SEVERITIES.map((sev) =>
        run.severities[sev] ? (
          <div
            key={sev}
            className={SEVERITY_BAR[sev]}
            style={{ width: `${(run.severities[sev] / total) * 100}%` }}
            title={`${run.severities[sev]} ${sev}`}
          />
        ) : null,
      )}
    </div>
  );
}

function RunCard({ run, onClick }: { run: Scan; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="flex w-full flex-col gap-1.5 rounded-md border border-border p-3 text-left transition-colors hover:border-primary/50 hover:bg-accent"
    >
      <div className="flex items-center gap-1.5">
        <span className="rounded bg-muted px-1.5 py-0.5 text-xs font-medium">
          {run.profile}
        </span>
        <span className="rounded bg-muted px-1.5 py-0.5 text-xs">{run.selectorLabel}</span>
        <span className="flex-1" />
        <span className="text-xs text-muted-foreground">{relative(run.finishedAt ?? "")}</span>
      </div>
      <div className="flex items-center gap-2 text-sm">
        <span className="font-semibold">{run.findings}</span>
        <span className="text-muted-foreground">
          findings · {run.endpointCount} targets · {run.hosts.length} affected hosts
        </span>
      </div>
      <SeverityBar run={run} />
    </button>
  );
}

export function ScansView({ onOpenScan }: { onOpenScan: (id: string) => void }) {
  const [runs, setRuns] = useState<Scan[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const loadRuns = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const list = await fetchScans();
      setRuns(list);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    void loadRuns();
  }, [loadRuns]);

  return (
    <div className="h-full overflow-y-auto p-4">
      <div className="mx-auto flex max-w-7xl flex-col gap-3">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-semibold">Scans</h1>
            <p className="text-sm text-muted-foreground">{runs.length} scan runs</p>
          </div>
          <Button variant="outline" size="sm" onClick={() => void loadRuns()} disabled={busy}>
            Refresh
          </Button>
        </div>
        {error && <span className="text-sm text-destructive">{error}</span>}
        {runs.length === 0 && !busy && (
          <p className="text-sm text-muted-foreground">
            No scans yet. Run <code>task scan:safe</code>.
          </p>
        )}
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {runs.map((run) => (
            <RunCard key={run.id} run={run} onClick={() => onOpenScan(run.id)} />
          ))}
        </div>
      </div>
    </div>
  );
}

// The severity mix, as counts rather than the proportional bar the run cards
// use: on the run itself the number of criticals is the thing to read, not how
// wide a stripe it draws.
function SeveritySummary({ scan }: { scan: Scan }) {
  const present = SEVERITIES.filter((severity) => scan.severities[severity]);
  if (present.length === 0) return null;
  return (
    <span className="flex flex-wrap items-center gap-1.5">
      {present.map((severity) => (
        <span key={severity} className="flex items-center gap-1">
          {severityBadge(severity)}
          <span className="text-xs font-medium tabular-nums">{scan.severities[severity]}</span>
        </span>
      ))}
    </span>
  );
}

type DetailTab = "findings" | "execution";

// The API caps a finding query at this many rows. Asking for it explicitly is
// what makes the cap visible: the view can compare what it received against the
// run's own count and say so, instead of quietly showing the first page as if
// it were the whole run.
const FINDING_LIMIT = 500;

export function ScanDetailView({
  id,
  onBack,
  tabs,
  taskButton,
}: {
  id: string;
  onBack: () => void;
  // The app's primary nav, handed down so it renders inside this view's shell
  // rather than in a second header band above it.
  tabs?: ReactNode;
  taskButton?: ReactNode;
}) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [groupBy, setGroupBy] = useState<GroupBy>("type");
  const [tab, setTab] = useState<DetailTab>("findings");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);
  const grouping = useMemo(() => buildGrouping(groupBy), [groupBy]);
  const { filters, selection, error: filterError } = useEntityFilters("finding", { exclude: ["scan"] });

  useEffect(() => {
    let cancelled = false;
    setBusy(true);
    setError(null);
    fetchScan(id)
      .then((result) => !cancelled && setScan(result))
      .catch((reason) => !cancelled && setError((reason as Error).message))
      .finally(() => !cancelled && setBusy(false));
    return () => {
      cancelled = true;
    };
  }, [id]);

  useEffect(() => {
    let cancelled = false;
    fetchFindings({ scan: id, limit: FINDING_LIMIT, ...selectionQuery(selection) })
      .then((result) => !cancelled && setFindings(result))
      .catch((reason) => !cancelled && setError((reason as Error).message));
    return () => {
      cancelled = true;
    };
  }, [id, selection]);

  return (
    <AppShell
      nav={
        <div className="flex min-w-0 items-center gap-3">
          {tabs && <div className="flex shrink-0 items-center gap-1">{tabs}</div>}
          <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-1 text-xs">
            <span className="shrink-0 text-muted-foreground">Scans</span>
            <span className="shrink-0 text-muted-foreground/60">›</span>
            <span className="truncate font-medium text-foreground">{scan?.name ?? id}</span>
          </nav>
        </div>
      }
      actions={
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={onBack}>
            Back to scans
          </Button>
          {taskButton}
        </div>
      }
      bodyHeader={
        <div className="flex min-w-0 flex-col gap-2">
          <div className="min-w-0">
            <h1 className="truncate text-lg font-semibold">{scan?.name ?? "Scan details"}</h1>
            <p className="truncate text-xs text-muted-foreground">
              {scan ? `${scan.engine} · ${scan.profile} · ${scan.selectorLabel}` : id}
            </p>
          </div>
          <Tabs
            tabs={[
              { id: "findings", label: "Findings", count: findings.length },
              { id: "execution", label: "Execution" },
            ]}
            value={tab}
            onChange={(next) => setTab(next as DetailTab)}
          />
        </div>
      }
      bodyActions={
        tab === "findings" && (
          <div className="flex items-center gap-3">
            {scan && <SeveritySummary scan={scan} />}
            <Select
              id="scan-findings-group"
              aria-label="Group findings by"
              className="w-40 shrink-0"
              value={groupBy}
              options={GROUP_OPTIONS}
              onChange={(event) => setGroupBy(event.target.value as GroupBy)}
            />
          </div>
        )
      }
      // A findings table is wide — severity, finding, host, type and a tag list
      // — and the default centred width caps it well below what it needs, which
      // truncated the template id mid-word and pushed the rest into a
      // horizontal scroll. This is a table to be read across, so it gets the
      // whole workspace.
      contentWidth="full"
      contentClassName="overflow-hidden p-density-4"
    >
      {/* The findings table owns the scroll so its sticky header stays pinned.
          h-full rather than flex-1: AppShell puts its content-width wrapper
          between `main` and these children and that wrapper is a block, so a
          flex class on contentClassName never reaches here — which left the
          table sized to its content and everything past the first screen
          clipped. */}
      <div className="flex h-full min-h-0 flex-col gap-density-2">
      {(error ?? filterError) && (
        <div role="alert" className="text-sm text-destructive">
          {error ?? filterError}
        </div>
      )}
      {busy && !scan && <p className="text-sm text-muted-foreground">Loading scan…</p>}

      {tab === "execution" ? (
        <div className="min-h-0 flex-1 overflow-y-auto">
          {scan && <ScanExecutionDetails scan={scan} />}
        </div>
      ) : (
        <>
          {scan && findings.length >= FINDING_LIMIT && scan.findings > findings.length && (
            <p className="text-xs text-muted-foreground">
              Showing the first {findings.length} of {scan.findings} findings — narrow the list
              with a filter to see the rest.
            </p>
          )}
          <DataTable<Finding>
            className="min-h-0 flex-1"
            data={findings}
            columns={findingColumns}
            getRowId={(row) => `${row.scanId}#${row.lineNo}`}
            externalFilters={filters}
            showGlobalFilter
            globalFilterPlaceholder="Search findings, hosts, templates…"
            defaultSort={{ key: "severity" }}
            grouping={grouping}
            // A pentest run reports hundreds of findings; rendering them all on
            // first paint locks the tab up for seconds.
            clientReveal={{ batchSize: 100 }}
            emptyMessage="No findings in this scan."
            detailStyle="row"
            renderExpandedRow={(row) => <FindingDetail finding={row} />}
            isRowClickable={() => true}
          />
        </>
      )}
      </div>
    </AppShell>
  );
}
