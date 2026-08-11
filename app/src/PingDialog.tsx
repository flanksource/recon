import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Button,
  DataTable,
  Modal,
  SegmentedControl,
  type DataTableColumn,
} from "@flanksource/clicky-ui";
import { probeTargets } from "./api";
import type { ProbeResult, ProbeRun, TargetRow } from "./types";

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
  /** Reloads the inventory, because a probe rewrites what the table shows. */
  onProbed: () => void;
};

export function PingDialog({
  open,
  onClose,
  rows,
  selectedHosts,
  onProbed,
}: Props) {
  const [scope, setScope] = useState<Scope>("selected");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<ProbeRun | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Scope is defaulted when the dialog opens, not re-derived while it is open:
  // a selection changing underneath would silently widen the run.
  useEffect(() => {
    if (!open) return;
    setScope(selectedHosts.length ? "selected" : "all");
    setResult(null);
    setError(null);
  }, [open, selectedHosts.length]);

  const hosts = useMemo(() => {
    if (scope === "all") return rows.map((row) => row.host);
    const selected = new Set(selectedHosts);
    return rows.filter((row) => selected.has(row.host)).map((row) => row.host);
  }, [rows, scope, selectedHosts]);

  const ping = useCallback(async () => {
    setRunning(true);
    setError(null);
    try {
      setResult(await probeTargets({ host: hosts }));
      // The inventory now holds what the probe saw, so the table behind this
      // dialog is stale until it reloads.
      onProbed();
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setRunning(false);
    }
  }, [hosts, onProbed]);

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

        {error && (
          <p
            className="shrink-0 rounded-md border border-destructive/40 bg-destructive/10 p-2 text-sm text-destructive"
            role="alert"
          >
            {error}
          </p>
        )}

        {result && !running && (
          <p className="shrink-0 text-sm text-muted-foreground">
            {result.live} of {result.results.length} answered ·{" "}
            {result.updated} target{result.updated === 1 ? "" : "s"} updated ·{" "}
            {result.durationMs}ms
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
              loading={running}
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
            targets to refresh those.
          </p>
        )}
      </div>
    </Modal>
  );
}
