import { useCallback, useState } from "react";
import { Button, Modal } from "@flanksource/clicky-ui/components";
import { uploadScan } from "./api";
import type { Scan, Upload } from "./types";

// Uploading is preview-first: the button runs a dry run, shows how much of the
// run will land on the resource it is actually about and how much will only
// reach the cluster or account containing it, and only then offers to push. The
// counts are the point — a run where everything rolls up means Mission Control
// does not hold what recon scanned, and that is worth seeing before writing
// insights to a system other people read.
export function UploadInsightsButton({ scan }: { scan: Scan | null }) {
  const [open, setOpen] = useState(false);
  const [preview, setPreview] = useState<Upload | null>(null);
  const [pushed, setPushed] = useState<Upload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = useCallback(
    async (dryRun: boolean) => {
      if (!scan) return;
      setBusy(true);
      setError(null);
      try {
        const result = await uploadScan(scan.id, { dryRun });
        if (dryRun) setPreview(result);
        else setPushed(result);
      } catch (e) {
        setError((e as Error).message);
      } finally {
        setBusy(false);
      }
    },
    [scan],
  );

  const start = useCallback(() => {
    setPreview(null);
    setPushed(null);
    setError(null);
    setOpen(true);
    void run(true);
  }, [run]);

  // A run with no findings has nothing to upload, and a run that has not
  // finished has not decided what it found.
  const uploadable = Boolean(scan) && scan!.findings > 0 && scan!.phase === "done";

  return (
    <>
      <Button
        variant="outline"
        size="sm"
        onClick={start}
        disabled={!uploadable}
        title={
          uploadable
            ? "Push this run's findings to Mission Control as insights"
            : "Only a finished run with findings can be uploaded"
        }
      >
        Upload insights
      </Button>
      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title="Upload to Mission Control"
        size="lg"
        closeOnEsc={!busy}
      >
        <UploadBody
          busy={busy}
          error={error}
          preview={preview}
          pushed={pushed}
          onPush={() => void run(false)}
          onClose={() => setOpen(false)}
        />
      </Modal>
    </>
  );
}

function UploadBody({
  busy,
  error,
  preview,
  pushed,
  onPush,
  onClose,
}: {
  busy: boolean;
  error: string | null;
  preview: Upload | null;
  pushed: Upload | null;
  onPush: () => void;
  onClose: () => void;
}) {
  if (error) {
    return (
      <div className="flex flex-col gap-3">
        <p className="text-sm text-destructive">{error}</p>
        <p className="text-xs text-muted-foreground">
          Insights are pushed with the credential <code>faro auth login</code>{" "}
          stored on the machine serving this app.
        </p>
        <div className="flex justify-end">
          <Button variant="outline" size="sm" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    );
  }

  const result = pushed ?? preview;
  if (busy && !result) {
    return <p className="text-sm text-muted-foreground">Resolving findings against the catalog…</p>;
  }
  if (!result) return null;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap gap-4">
        <Count label="On the resource" value={result.resolved} />
        <Count label="Rolled up" value={result.rolledUp} />
        <Count label="Unresolved" value={result.unresolved.length} />
        {pushed && <Count label="Pushed" value={pushed.pushed} />}
      </div>

      {result.server && (
        <p className="text-xs text-muted-foreground">
          {pushed ? "Pushed to" : "Would push to"} {result.server} as agent{" "}
          <code>{result.agent}</code>
          {result.findings < result.total &&
            ` · ${result.findings} of ${result.total} findings selected`}
        </p>
      )}

      {result.configs.length > 0 && (
        <ConfigList configs={result.configs} />
      )}

      {result.unresolved.length > 0 && (
        <UnresolvedList unresolved={result.unresolved} />
      )}

      {result.notes?.map((note) => (
        <p key={note} className="text-xs text-amber-600 dark:text-amber-400">
          {note}
        </p>
      ))}

      <div className="flex justify-end gap-2">
        <Button variant="outline" size="sm" onClick={onClose}>
          {pushed ? "Close" : "Cancel"}
        </Button>
        {!pushed && (
          <Button size="sm" onClick={onPush} disabled={busy || result.resolved + result.rolledUp === 0}>
            {busy ? "Pushing…" : `Push ${result.resolved + result.rolledUp} insights`}
          </Button>
        )}
      </div>
    </div>
  );
}

function Count({ label, value }: { label: string; value: number }) {
  return (
    <div className="min-w-24 rounded-md border border-border bg-muted/30 p-3">
      <div className="text-lg font-semibold">{value}</div>
      <div className="text-xs text-muted-foreground">{label}</div>
    </div>
  );
}

function ConfigList({ configs }: { configs: Upload["configs"] }) {
  return (
    <div className="flex flex-col gap-1">
      <h3 className="text-xs font-medium text-muted-foreground">Config items</h3>
      <ul className="max-h-48 overflow-y-auto text-sm">
        {configs.map((config) => (
          <li key={config.id} className="flex items-baseline justify-between gap-2 py-0.5">
            <span className="truncate">
              {config.name || config.id}
              {config.type && (
                <span className="text-muted-foreground"> · {config.type}</span>
              )}
              {config.rolledUp && (
                <span className="text-amber-600 dark:text-amber-400"> · rolled up</span>
              )}
            </span>
            <span className="shrink-0 tabular-nums text-muted-foreground">
              {config.insights}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function UnresolvedList({ unresolved }: { unresolved: Upload["unresolved"] }) {
  return (
    <div className="flex flex-col gap-1">
      <h3 className="text-xs font-medium text-muted-foreground">
        Not uploaded — nothing in the catalog claims these
      </h3>
      <ul className="max-h-48 overflow-y-auto text-sm">
        {unresolved.map((item) => (
          <li key={item.finding} className="py-0.5">
            <span className="truncate">{item.host || item.finding}</span>
            <span className="text-xs text-muted-foreground">
              {" "}
              · tried {item.tried.join(", ")}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
