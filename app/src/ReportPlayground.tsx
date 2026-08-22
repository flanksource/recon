// The report playground: design the printed report against real or sample data.
//
// It exists because the alternative loop is a PDF render per change — tens of
// seconds each — and a design nobody iterates on is a design nobody fixes. The
// component it previews is the same ScanReport.tsx facet prints, given the same
// payload the server would send, so what is tuned here is what comes out.
//
// The remaining difference is the renderer: the browser lays the report out in
// one continuous column, while facet paginates it in Chromium. That is what the
// Download buttons are for — they go through the real pipeline.

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { AppShell, Button, SegmentedControl } from "@flanksource/clicky-ui/components";
import { DropdownMenu } from "@flanksource/clicky-ui/components";
import { SplitPane } from "@flanksource/clicky-ui/components";

import ScanReport from "../reports/ScanReport";
import { REPORT_SAMPLES, reportSample } from "../reports/samples";
import type { ReportOptions, ScanReportData } from "../reports/scan-report-types";
import { fetchReportData, fetchScans } from "./api";
import { ReportOptionsForm } from "./ReportOptionsForm";
import { ReportPreviewFrame, type PreviewZoom } from "./ReportPreviewFrame";
import {
  playgroundUrl,
  reportOptionsFromQuery,
  reportQuery,
  reportUrl,
} from "./scan-report";
import type { Scan } from "./types";

const ZOOMS: PreviewZoom[] = [50, 75, 100];

// How many runs the source menu offers. The playground is for designing the
// report, not for browsing the archive — the scan list is one click away.
const RECENT_SCANS = 15;

type Source = { kind: "sample"; id: string } | { kind: "scan"; id: string };

// The payload's scan is the template's own narrower view of a run, not the
// app's `Scan` — all this needs from it is a name.
function sourceLabel(source: Source, runName: string | undefined): string {
  if (source.kind === "sample") {
    return `Sample · ${reportSample(source.id)?.label ?? source.id}`;
  }
  return runName ?? source.id;
}

export function ReportPlayground({
  scanId,
  onSelectScan,
  tabs,
  taskButton,
}: {
  /** The run to preview. Absent previews a sample. */
  scanId?: string;
  onSelectScan: (id: string | undefined) => void;
  tabs?: ReactNode;
  taskButton?: ReactNode;
}) {
  // The options the page was opened with. Kept in a ref rather than state
  // because the URL is rewritten on every edit: re-reading it would feed the
  // playground its own output.
  const openedWith = useRef(reportOptionsFromQuery(new URLSearchParams(window.location.search)));
  const [options, setOptions] = useState<ReportOptions>(openedWith.current);
  const [sampleId, setSampleId] = useState(REPORT_SAMPLES[0].id);
  const [zoom, setZoom] = useState<PreviewZoom>(75);
  const [payload, setPayload] = useState<ScanReportData | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  const source: Source = scanId ? { kind: "scan", id: scanId } : { kind: "sample", id: sampleId };

  useEffect(() => {
    fetchScans({ limit: RECENT_SCANS })
      .then(setScans)
      // A playground that cannot list runs is still usable against the samples,
      // so this is reported rather than fatal.
      .catch((reason) => setError((reason as Error).message));
  }, []);

  // The server builds the payload for a real run; the samples are compiled in.
  // Options are applied locally either way, which is what keeps the preview
  // instant — a change to the title must not cost a round trip.
  useEffect(() => {
    if (!scanId) {
      setPayload(null);
      return;
    }
    let cancelled = false;
    setBusy(true);
    setError(null);
    fetchReportData(scanId)
      .then((result) => !cancelled && setPayload(result))
      .catch((reason) => !cancelled && setError((reason as Error).message))
      .finally(() => !cancelled && setBusy(false));
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  // Start from the presentation the data already carries — a sample ships a
  // title and a classification worth designing against — and let anything the
  // link asked for win over it. Re-seeds only when the source changes, so an
  // edit is never overwritten.
  useEffect(() => {
    const carried = scanId ? payload?.options : reportSample(sampleId)?.data.options;
    if (carried) setOptions({ ...carried, ...openedWith.current });
  }, [payload, sampleId, scanId]);

  // Options live in the URL so a report somebody tuned is a link. Replaced
  // rather than pushed: every keystroke in the title field would otherwise be a
  // separate history entry.
  useEffect(() => {
    const query = reportQuery(options).toString();
    window.history.replaceState(
      null,
      "",
      query ? `${window.location.pathname}?${query}` : window.location.pathname,
    );
    setCopied(false);
  }, [options]);

  const data: ScanReportData | null = useMemo(() => {
    const base = scanId ? payload : reportSample(sampleId)?.data;
    return base ? { ...base, options } : null;
  }, [options, payload, sampleId, scanId]);

  const copyLink = useCallback(async () => {
    const target = scanId
      ? `${window.location.origin}${playgroundUrl(scanId, options)}`
      : window.location.href;
    await navigator.clipboard?.writeText(target);
    setCopied(true);
  }, [options, scanId]);

  const sourceItems = [
    ...REPORT_SAMPLES.map((sample) => ({
      group: "Samples",
      label: `${sample.label} — ${sample.description}`,
      onSelect: () => {
        setSampleId(sample.id);
        onSelectScan(undefined);
      },
    })),
    ...scans.map((run) => ({
      group: "Recent scans",
      label: `${run.name} · ${run.findings} findings`,
      onSelect: () => onSelectScan(run.id),
    })),
  ];

  return (
    <AppShell
      nav={
        <div className="flex min-w-0 items-center gap-3">
          {tabs && <div className="flex shrink-0 items-center gap-1">{tabs}</div>}
          <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-1 text-xs">
            <span className="shrink-0 text-muted-foreground">Reports</span>
            <span className="shrink-0 text-muted-foreground/60">›</span>
            <span className="truncate font-medium text-foreground">
              {sourceLabel(source, payload?.scan.name)}
            </span>
          </nav>
        </div>
      }
      actions={
        <div className="flex items-center gap-2">
          <DropdownMenu
            variant="outline"
            size="sm"
            label="Data"
            items={sourceItems}
          />
          <SegmentedControl<string>
            size="sm"
            aria-label="Preview zoom"
            value={String(zoom)}
            options={ZOOMS.map((level) => ({ id: String(level), label: `${level}%` }))}
            onChange={(id) => setZoom(Number(id) as PreviewZoom)}
          />
          <Button variant="outline" size="sm" onClick={() => void copyLink()}>
            {copied ? "Link copied" : "Copy link"}
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={!scanId}
            title={
              scanId
                ? "Render this design through facet"
                : "Rendering needs a real run — pick one from Data"
            }
            onClick={() => scanId && window.open(reportUrl(scanId, "html", options), "_blank")}
          >
            HTML
          </Button>
          <Button
            size="sm"
            disabled={!scanId}
            title={
              scanId
                ? "Render this design as a PDF"
                : "Rendering needs a real run — pick one from Data"
            }
            onClick={() => scanId && window.open(reportUrl(scanId, "pdf", options), "_blank")}
          >
            Download PDF
          </Button>
          {taskButton}
        </div>
      }
      contentWidth="full"
      contentClassName="overflow-hidden p-0"
    >
      <div className="flex h-full min-h-0 flex-col">
        {error && (
          <div role="alert" className="border-b border-border px-4 py-2 text-sm text-destructive">
            {error}
          </div>
        )}
        <SplitPane
          className="min-h-0 flex-1"
          defaultSplit={28}
          minLeft={20}
          minRight={40}
          leftClass="min-h-0 border-r border-border"
          rightClass="min-h-0"
          left={<ReportOptionsForm options={options} onChange={setOptions} />}
          right={
            data ? (
              <ReportPreviewFrame zoom={zoom} title="Scan report preview">
                <ScanReport data={data} />
              </ReportPreviewFrame>
            ) : (
              <p className="p-6 text-sm text-muted-foreground">
                {busy ? "Loading the run…" : "Pick a run or a sample from Data."}
              </p>
            )
          }
        />
      </div>
    </AppShell>
  );
}
