import { useEffect, useMemo, useState, type RefObject } from "react";
import { Button } from "@flanksource/clicky-ui/components";
import { AnsiHtml, ProgressBar } from "@flanksource/clicky-ui/data";
import { fetchFindings } from "./api";
import { boundedScanPercent } from "./scanProgress";
import { formatBytes } from "./format";
import { severityBadge, SEVERITY_RANK } from "./scanColumns";
import {
  SEVERITIES,
  TERMINAL_PHASES,
  findingTitle,
  severityOf,
  type Finding,
  type ScanOutputEvent,
  type ScanStatus,
  type SeverityCounts as SeverityCountsMap,
} from "./types";

const PHASE_LABEL: Record<ScanStatus["phase"], string> = {
  idle: "Idle",
  queued: "Queued",
  running: "Running",
  done: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
};

function elapsed(from: string, to?: string): string {
  const seconds = Math.max(
    0,
    Math.round(
      (new Date(to ?? Date.now()).getTime() - new Date(from).getTime()) / 1000,
    ),
  );
  return seconds < 60
    ? `${seconds}s`
    : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <span className="flex items-baseline gap-1">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className="text-sm font-medium tabular-nums">{value}</span>
    </span>
  );
}

function SeverityBreakdown({ counts }: { counts: SeverityCountsMap }) {
  const present = SEVERITIES.filter((severity) => counts[severity] > 0);
  if (!present.length) return null;
  return (
    <span className="flex items-center gap-1.5">
      {present.map((severity) => (
        <span key={severity} className="flex items-center gap-1">
          {severityBadge(severity)}
          <span className="text-sm font-medium tabular-nums">
            {counts[severity]}
          </span>
        </span>
      ))}
    </span>
  );
}

function LiveFindings({ findings }: { findings: Finding[] }) {
  const sorted = useMemo(
    () =>
      [...findings]
        .reverse()
        .sort(
          (left, right) =>
            SEVERITY_RANK[severityOf(left)] - SEVERITY_RANK[severityOf(right)],
        ),
    [findings],
  );
  if (!sorted.length) {
    return (
      <p className="p-3 text-sm text-muted-foreground">No findings yet.</p>
    );
  }
  return (
    <ul className="divide-y divide-border">
      {sorted.map((finding, index) => (
        <li
          key={`${finding.checkId}:${finding.host}:${index}`}
          className="flex items-center gap-2 px-3 py-1.5 text-sm"
        >
          {severityBadge(severityOf(finding))}
          <span className="truncate font-medium">{findingTitle(finding)}</span>
          <code className="truncate text-xs text-muted-foreground">
            {finding.checkId}
          </code>
          <span className="flex-1" />
          <span
            className="truncate text-xs text-muted-foreground"
            title={finding.matchedAt}
          >
            {finding.host}
          </span>
        </li>
      ))}
    </ul>
  );
}

const STREAM_STYLE: Record<ScanOutputEvent["stream"], string> = {
  stdout: "text-emerald-600 dark:text-emerald-400",
  stderr: "text-amber-600 dark:text-amber-400",
  system: "text-sky-600 dark:text-sky-400",
};

function LiveOutput({
  output,
  logRef,
}: {
  output: ScanOutputEvent[];
  logRef: RefObject<HTMLDivElement | null>;
}) {
  return (
    <div
      ref={logRef}
      role="log"
      aria-label="Live scan output"
      aria-live="polite"
      className="min-h-40 flex-1 overflow-y-auto rounded-md border border-border bg-muted/30 p-2"
    >
      {output.length === 0 ? (
        <p className="text-xs text-muted-foreground">Waiting for process output…</p>
      ) : (
        output.map((event) => (
          <div
            key={event.sequence}
            className="grid grid-cols-[3.75rem_minmax(0,1fr)] gap-2 text-xs leading-snug"
          >
            <span className={`select-none font-medium ${STREAM_STYLE[event.stream]}`}>
              {event.stream}
            </span>
            <AnsiHtml
              as="pre"
              text={event.text}
              className="min-w-0 whitespace-pre-wrap break-all font-mono"
            />
          </div>
        ))
      )}
    </div>
  );
}

export function ScanRunStatus({
  status,
  logRef,
  onOpenScan,
}: {
  status: ScanStatus;
  logRef: RefObject<HTMLDivElement | null>;
  onOpenScan?: (file: string) => void;
}) {
  const discovery = status.profile === "discovery";
  const percent =
    status.phase === "done" ? 100 : boundedScanPercent(status.stats?.percent);
  const resultId = status.id;
  const title = discovery
    ? "Discovery rescan"
    : `Nuclei ${status.profile ?? ""} scan`.replace("  ", " ");

  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingsError, setFindingsError] = useState<string | null>(null);

  useEffect(() => {
    setFindings([]);
    setFindingsError(null);
    if (!TERMINAL_PHASES.includes(status.phase)) return;
    let cancelled = false;
    fetchFindings({ scan: status.id })
      .then((rows) => !cancelled && setFindings(rows))
      .catch((e) => !cancelled && setFindingsError((e as Error).message));
    return () => {
      cancelled = true;
    };
  }, [status.id, status.phase]);

  return (
    <>
      <div className="flex shrink-0 flex-col gap-3 rounded-md border border-border p-3">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="text-sm font-semibold">{title}</h3>
          <span className="rounded-full bg-muted px-2 py-0.5 text-xs font-medium">
            {PHASE_LABEL[status.phase]}
          </span>
          {status.selectorLabel && (
            <span className="text-xs text-muted-foreground">{status.selectorLabel}</span>
          )}
          <span className="flex-1" />
          {status.exitCode !== undefined && (
            <code className="text-xs text-muted-foreground">exit {status.exitCode}</code>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <Stat label="targets" value={status.endpointCount} />
          {!discovery && (
            <>
              <Stat
                label="requests"
                value={
                  status.stats
                    ? `${status.stats.requests} / ${status.stats.total}`
                    : "—"
                }
              />
              <Stat label="templates" value={status.stats?.templates ?? "—"} />
              <Stat label="matched" value={status.stats?.matched ?? 0} />
              <Stat label="rps" value={status.stats?.rps ?? "—"} />
              <Stat label="errors" value={status.stats?.errors ?? 0} />
              {/* Live traffic: the engine's progress counters say how far
                  through the templates it is, these say whether anything is
                  answering. A scan at 60% with zero responses is not working. */}
              {status.stats?.http && (
                <>
                  <Stat label="responses" value={status.stats.http.responses} />
                  <Stat label="received" value={formatBytes(status.stats.http.bytes)} />
                </>
              )}
            </>
          )}
          <Stat
            label="elapsed"
            value={
              status.startedAt
                ? elapsed(status.startedAt, status.finishedAt)
                : "—"
            }
          />
          <span className="flex-1" />
          {!discovery && (
            <>
              <SeverityBreakdown counts={status.severities} />
              <span className="text-sm font-medium tabular-nums">
                {status.findings} finding
                {status.findings === 1 ? "" : "s"}
              </span>
              {/* Only once something was actually removed. Rules are applied to
                  the results, so a run still in flight has nothing to report
                  here and a standing "0 muted" would just be noise. */}
              {status.muted ? (
                <span className="text-xs text-muted-foreground tabular-nums">
                  {status.muted} muted
                </span>
              ) : null}
            </>
          )}
        </div>
        <ProgressBar
          height="h-2"
          total={100}
          segments={[
            {
              count: percent,
              color:
                status.phase === "failed" ? "bg-destructive" : "bg-primary",
              label: "% complete",
            },
          ]}
        />
        <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          <span className="tabular-nums">{percent}%</span>
          {status.command && (
            <code className="min-w-0 truncate" title={status.command.join(" ")}>
              {status.command.join(" ")}
            </code>
          )}
          {status.name && <code>{status.name}</code>}
          <span className="flex-1" />
          {status.error && (
            <span className="text-destructive">{status.error}</span>
          )}
          {status.phase !== "running" && resultId && onOpenScan && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => onOpenScan(resultId)}
            >
              View in Scans
            </Button>
          )}
        </div>
      </div>
      {!discovery && (
        <div className="min-h-0 flex-1 overflow-y-auto rounded-md border border-border">
          {findingsError && (
            <p className="p-2 text-xs text-destructive">{findingsError}</p>
          )}
          <LiveFindings findings={findings} />
        </div>
      )}
      <LiveOutput output={status.output} logRef={logRef} />
    </>
  );
}
