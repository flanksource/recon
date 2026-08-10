import { useCallback, useEffect, useMemo, useState } from "react";
import { Button, DataTable, Select, type DataTableGrouping } from "@flanksource/clicky-ui";
import { fetchFindings, fetchScans } from "./api";
import { selectionQuery, useEntityFilters } from "./filters";
import {
  findingColumns,
  FindingDetail,
  severityBadge,
  SEVERITY_RANK,
  worstSeverity,
} from "./scanColumns";
import { SEVERITIES, type Finding, type Scan, type Severity } from "./types";

type GroupBy = "type" | "severity" | "host" | "none";

const GROUP_OPTIONS: { value: GroupBy; label: string }[] = [
  { value: "type", label: "Result type" },
  { value: "severity", label: "Severity" },
  { value: "host", label: "Affected domain" },
  { value: "none", label: "No grouping" },
];

function uniqueHosts(findings: Finding[]): string[] {
  return [...new Set(findings.map((f) => f.host).filter(Boolean))].sort();
}

// Compact "affected domains" chip list rendered in each group header.
function DomainChips({ hosts }: { hosts: string[] }) {
  const shown = hosts.slice(0, 4);
  const extra = hosts.length - shown.length;
  return (
    <span className="flex flex-wrap items-center gap-1">
      <span className="text-xs text-muted-foreground">
        {hosts.length} domain{hosts.length === 1 ? "" : "s"}:
      </span>
      {shown.map((h) => (
        <span key={h} className="rounded bg-muted px-1.5 py-0.5 text-xs">
          {h}
        </span>
      ))}
      {extra > 0 && (
        <span className="text-xs text-muted-foreground" title={hosts.join("\n")}>
          +{extra}
        </span>
      )}
    </span>
  );
}

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
      getGroupMeta: (_key, rows) => (
        <span className="text-xs text-muted-foreground">{rows.length} findings</span>
      ),
      compareGroups: (a, b) =>
        SEVERITY_RANK[worstSeverity(a.rows)] - SEVERITY_RANK[worstSeverity(b.rows)] ||
        b.rows.length - a.rows.length,
    };
  }

  if (groupBy === "severity") {
    return {
      getGroupKey: (row) => row.severity,
      getGroupLabel: (key, rows) => (
        <span className="flex flex-col gap-1 py-1">
          <span className="flex items-center gap-2">
            {severityBadge(key as Severity)}
            <span className="text-xs text-muted-foreground">{rows.length} findings</span>
          </span>
          <DomainChips hosts={uniqueHosts(rows)} />
        </span>
      ),
      getGroupMeta: (_key, rows) => (
        <span className="text-xs text-muted-foreground">{rows.length}</span>
      ),
      compareGroups: (a, b) =>
        SEVERITY_RANK[a.key as Severity] - SEVERITY_RANK[b.key as Severity],
    };
  }

  // Default: group by result type (template), show affected domains in the header.
  return {
    getGroupKey: (row) => row.templateId,
    getGroupLabel: (_key, rows) => (
      <span className="flex flex-col gap-1 py-1">
        <span className="flex items-center gap-2">
          {severityBadge(worstSeverity(rows))}
          <span className="font-medium">{rows[0]?.name ?? _key}</span>
          <code className="text-xs text-muted-foreground">{_key}</code>
        </span>
        <DomainChips hosts={uniqueHosts(rows)} />
      </span>
    ),
    getGroupMeta: (_key, rows) => (
      <span className="text-xs text-muted-foreground">{rows.length} findings</span>
    ),
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

function RunCard({
  run,
  active,
  onClick,
}: {
  run: Scan;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex w-full flex-col gap-1.5 rounded-md border p-2.5 text-left transition-colors ${
        active
          ? "border-primary bg-primary/5"
          : "border-border hover:bg-accent"
      }`}
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
        <span className="text-muted-foreground">findings · {run.hosts.length} hosts</span>
      </div>
      <SeverityBar run={run} />
    </button>
  );
}

// `file` preselects a run by scan id — set when the Targets tab hands off a scan it just finished.
export function ScansView({ file }: { file?: string | null }) {
  const [runs, setRuns] = useState<Scan[]>([]);
  const [selected, setSelected] = useState<string | null>(file ?? null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [groupBy, setGroupBy] = useState<GroupBy>("type");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const grouping = useMemo(() => buildGrouping(groupBy), [groupBy]);

  // The run list owns which scan is shown, so the findings bar offers only the
  // rest. The options come from the finding entity's own declaration, which
  // means they describe every finding in the database rather than the page that
  // happens to be loaded — a scan is capped at 500 findings here, and filters
  // derived from a truncated page quietly omit whatever fell off it.
  const { filters, selection, error: filterError } = useEntityFilters("finding", {
    exclude: ["scan"],
  });

  const loadRuns = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const list = await fetchScans();
      setRuns(list);
      setSelected((cur) => cur ?? list[0]?.id ?? null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    void loadRuns();
  }, [loadRuns]);

  useEffect(() => {
    if (file) setSelected(file);
  }, [file]);

  useEffect(() => {
    if (!selected) return;
    let cancelled = false;
    setBusy(true);
    fetchFindings({ scan: selected, ...selectionQuery(selection) })
      .then((f) => !cancelled && setFindings(f))
      .catch((e) => !cancelled && setError((e as Error).message))
      .finally(() => !cancelled && setBusy(false));
    return () => {
      cancelled = true;
    };
  }, [selected, selection]);

  const activeRun = useMemo(
    () => runs.find((r) => r.id === selected),
    [runs, selected],
  );

  return (
    <div className="flex min-h-0 flex-1 gap-3 p-3">
      <aside className="flex w-72 shrink-0 flex-col gap-2 overflow-y-auto">
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium">{runs.length} scan runs</span>
          <Button variant="outline" size="sm" onClick={() => void loadRuns()} disabled={busy}>
            Refresh
          </Button>
        </div>
        {(error ?? filterError) && (
          <span className="text-sm text-destructive">{error ?? filterError}</span>
        )}
        {runs.length === 0 && !busy && (
          <p className="text-sm text-muted-foreground">
            No scans yet. Run <code>task scan:safe</code>.
          </p>
        )}
        {runs.map((run) => (
          <RunCard
            key={run.id}
            run={run}
            active={run.id === selected}
            onClick={() => setSelected(run.id)}
          />
        ))}
      </aside>

      <section className="flex min-h-0 flex-1 flex-col">
        <div className="mb-2 flex items-center gap-2 text-sm text-muted-foreground">
          {activeRun && (
            <>
              <code className="text-foreground">{activeRun.name}</code>
              <span>·</span>
              <span>{activeRun.findings} findings</span>
              <span>·</span>
              <span>{activeRun.hosts.length} hosts</span>
            </>
          )}
          <span className="flex-1" />
          <label className="text-xs">Group by</label>
          <Select
            className="w-40"
            value={groupBy}
            options={GROUP_OPTIONS}
            onChange={(e) => setGroupBy(e.target.value as GroupBy)}
          />
        </div>
        <DataTable<Finding>
          data={findings}
          columns={findingColumns}
          getRowId={(row, i) => `${row.templateId}:${row.host}:${row.matcherName ?? i}`}
          externalFilters={filters}
          showGlobalFilter
          globalFilterPlaceholder="Search findings, hosts, templates…"
          defaultSort={{ key: "severity" }}
          grouping={grouping}
          emptyMessage="No findings in this scan."
          detailStyle="row"
          renderExpandedRow={(row) => <FindingDetail finding={row} />}
          isRowClickable={() => true}
        />
      </section>
    </div>
  );
}
