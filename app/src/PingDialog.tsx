import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Button,
  Modal,
  SegmentedControl,
} from "@flanksource/clicky-ui/components";
import {
  DataTable,
  ProgressBar,
  type DataTableColumn,
} from "@flanksource/clicky-ui/data";
import { probeTargets } from "./api";
import { useProbeRun } from "./useProbeRun";
import {
  TERMINAL_PHASES,
  targetHost,
  type ProbeResult,
  type TargetRow,
} from "./types";

type Scope = "selected" | "all";

const columns: DataTableColumn<ProbeResult>[] = [
  {
    key: "host",
    label: "Host",
    grow: true,
    sortable: true,
    render: (value, row) => (
      <a
        href={row.url ?? `https://${String(value)}`}
        target="_blank"
        rel="noreferrer"
        className="font-medium hover:underline"
      >
        {String(value)}
      </a>
    ),
  },
  {
    key: "up",
    label: "Live",
    shrink: true,
    align: "center",
    sortable: true,
    render: (value) =>
      value ? (
        <span className="text-emerald-600 dark:text-emerald-400">yes</span>
      ) : (
        <span className="text-destructive">no</span>
      ),
  },
  { key: "statusCode", label: "Status", shrink: true, align: "right", sortable: true },
  {
    key: "responseTimeMs",
    label: "Response",
    shrink: true,
    align: "right",
    sortable: true,
    render: (value) => (typeof value === "number" ? `${value}ms` : "—"),
  },
  { key: "ip", label: "IP", shrink: true },
  { key: "error", label: "Error", grow: true },
];

type Props = {
  open: boolean;
  onClose: () => void;
  rows: TargetRow[];
  selectedHosts: string[];
  /**
   * Refreshes the inventory rows for hosts the sweep has just finished. Called
   * repeatedly as a run progresses, not once at the end.
   */
  onProbed: (hosts: string[]) => void;
};

export function PingDialog({
  open,
  onClose,
  rows,
  selectedHosts,
  onProbed,
}: Props) {
  const [scope, setScope] = useState<Scope>("selected");
  const [starting, setStarting] = useState(false);
  const [runId, setRunId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // The run is followed rather than awaited: the POST returns as soon as the
  // sweep is recorded, and this is what fills the table while it works.
  const { run, error: pollError } = useProbeRun(runId, onProbed);
  const running = starting || (run !== null && !TERMINAL_PHASES.includes(run.phase));

  // Scope is defaulted when the dialog opens, not re-derived while it is open:
  // a selection changing underneath would silently widen the run.
  useEffect(() => {
    if (!open) return;
    setScope(selectedHosts.length ? "selected" : "all");
    setRunId(null);
    setError(null);
  }, [open, selectedHosts.length]);

  const hosts = useMemo(() => {
    if (scope === "all") return rows.map(targetHost);
    const selected = new Set(selectedHosts);
    return rows.filter((row) => selected.has(targetHost(row))).map(targetHost);
  }, [rows, scope, selectedHosts]);

  const ping = useCallback(async () => {
    setStarting(true);
    setError(null);
    try {
      setRunId((await probeTargets({ host: hosts })).id);
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setStarting(false);
    }
  }, [hosts]);

  const result = run;
  const probed = result?.results.length ?? 0;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Ping hosts"
      size="xl"
      className={result || running ? "h-[calc(100dvh-4rem)]" : undefined}
      scrollBody={false}
      closeOnEsc={!running}
    >
      <div className="flex min-h-0 flex-1 flex-col gap-3">
        <div className="flex shrink-0 flex-wrap items-end gap-3 rounded-md border border-border bg-muted/30 p-3">
          {/* A span, not a label: a label wrapping a radiogroup lends its text
              to every option, so each one announces the same name. */}
          <span className="flex flex-col gap-1 text-xs">
            Targets
            <SegmentedControl<Scope>
              size="sm"
              value={scope}
              onChange={setScope}
              options={[
                {
                  id: "selected",
                  label: `Selected (${selectedHosts.length})`,
                  disabled: selectedHosts.length === 0 || running,
                },
                { id: "all", label: `All targets (${rows.length})`, disabled: running },
              ]}
            />
          </span>
          <span className="flex-1" />
          <Button
            onClick={() => void ping()}
            loading={running}
            disabled={running || hosts.length === 0}
          >
            Ping {hosts.length} host{hosts.length === 1 ? "" : "s"}
          </Button>
        </div>

        {(error ?? pollError) && (
          <p
            className="shrink-0 rounded-md border border-destructive/40 bg-destructive/10 p-2 text-sm text-destructive"
            role="alert"
          >
            {error ?? pollError}
          </p>
        )}

        {/* Progress against the hosts the run set out to probe, not against the
            ones it has finished — dividing by the latter would sit at 100% from
            the first answer. */}
        {result && running && (
          <div className="shrink-0 space-y-1">
            <ProgressBar
              height="h-2"
              total={result.total || 1}
              segments={[
                { count: result.live, color: "bg-emerald-500", label: "answered" },
                { count: probed - result.live, color: "bg-destructive", label: "no answer" },
              ]}
            />
            <p className="text-sm text-muted-foreground">
              Probing {result.selectorLabel || "selected hosts"} — {probed} of{" "}
              {result.total} checked, {result.live} answered
            </p>
          </div>
        )}

        {result && !running && (
          <p className="shrink-0 text-sm text-muted-foreground">
            {result.live} of {probed} answered · {result.updated} target
            {result.updated === 1 ? "" : "s"} updated · {result.durationMs}ms
          </p>
        )}

        {(result || running) && (
          <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-md border border-border">
            <DataTable<ProbeResult>
              className="min-h-0 flex-1"
              data={result?.results ?? []}
              columns={columns}
              getRowId={(row) => row.host}
              autoFilter
              showGlobalFilter
              globalFilterPlaceholder="Search probed hosts…"
              defaultSort={{ key: "host" }}
              // Only while there is nothing to show: once hosts start landing the
              // table renders them, and a spinner over a filling list would hide
              // exactly the thing this change exists to show.
              loading={running && probed === 0}
              loadingMessage="Probing hosts…"
              emptyMessage="No hosts probed."
            />
          </div>
        )}

        {!result && !running && (
          <p className="px-3 pb-2 text-sm text-muted-foreground">
            Probes each host over HTTPS then HTTP and records what answered —
            liveness, status code, response time and address. Technology, TLS
            and open ports are left as discovery found them; use Discover
            targets to refresh those. The sweep runs on the server, so closing
            this dialog does not stop it.
          </p>
        )}
      </div>
    </Modal>
  );
}
