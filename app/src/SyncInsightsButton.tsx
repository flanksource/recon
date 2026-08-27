import { useCallback, useMemo, useState } from "react";
import { Button, Modal } from "@flanksource/clicky-ui/components";
import { TaskManager } from "@flanksource/clicky-ui/data";
import type { SyncRequest } from "./api-insights";
import { SyncPreflight } from "./SyncPreflight";
import type { InsightSync } from "./types";

/** The kind the server tags a sync task run with; see internal/entities/sync_tasks.go. */
const SYNC_TASK_KIND = "insight-sync";

export function SyncInsightsButton({ sync, disabled = false }: {
  sync: (request: SyncRequest) => Promise<InsightSync>;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [preview, setPreview] = useState<InsightSync | null>(null);
  const [pushed, setPushed] = useState<InsightSync | null>(null);
  const [choices, setChoices] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = useCallback(async (request: SyncRequest) => {
    setBusy(true);
    setError(null);
    try {
      const result = await sync(request);
      if (request.dryRun) setPreview(result);
      else setPushed(result);
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setBusy(false);
    }
  }, [sync]);

  const start = useCallback(() => {
    setPreview(null);
    setPushed(null);
    setChoices({});
    setError(null);
    setOpen(true);
    void run({ dryRun: true });
  }, [run]);

  const choose = useCallback((identity: string, configId: string) => {
    setChoices((current) => ({ ...current, [identity]: configId }));
  }, []);

  return (
    <>
      <Button variant="outline" size="sm" onClick={start} disabled={disabled}>Sync insights</Button>
      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title="Sync insights to Mission Control"
        size="lg"
        closeOnEsc={!busy}
      >
        <SyncBody
          busy={busy}
          error={error}
          preview={preview}
          pushed={pushed}
          choices={choices}
          onChoose={choose}
          onRun={run}
          onClose={() => setOpen(false)}
        />
      </Modal>
    </>
  );
}

function SyncBody({ busy, error, preview, pushed, choices, onChoose, onRun, onClose }: {
  busy: boolean;
  error: string | null;
  preview: InsightSync | null;
  pushed: InsightSync | null;
  choices: Record<string, string>;
  onChoose: (identity: string, configId: string) => void;
  onRun: (request: SyncRequest) => void;
  onClose: () => void;
}) {
  const result = pushed ?? preview;

  // What the sync would attach, including the ambiguities this preview has since
  // been given an answer for. Counted here rather than by re-previewing on every
  // click: each preview walks the whole catalog again, and the states riding on
  // each identity are already in the payload.
  const [attached, pending] = useMemo(() => {
    if (!result) return [0, 0];
    const decided = result.ambiguous
      .filter((item) => choices[item.identity] && choices[item.identity] !== item.chosen)
      .reduce((total, item) => total + item.states, 0);
    return [result.direct + result.rolledUp, decided];
  }, [result, choices]);

  if (error) {
    return (
      <div className="flex flex-col gap-3">
        <p className="text-sm text-destructive">{error}</p>
        <div className="flex justify-end">
          <Button variant="outline" size="sm" onClick={onClose}>Close</Button>
        </div>
      </div>
    );
  }

  if (busy && !result) return <SyncProgress />;
  if (!result) return null;
  const syncable = attached + pending;

  return (
    <div className="flex flex-col gap-4">
      {busy && <SyncProgress />}
      <SyncPreflight result={result} pushed={Boolean(pushed)} choices={choices} onChoose={onChoose} />
      {syncable === 0 && (
        <p className="text-sm text-muted-foreground">No resolvable insights match this selection.</p>
      )}

      <div className="flex justify-end gap-2">
        <Button variant="outline" size="sm" onClick={onClose}>{pushed ? "Close" : "Cancel"}</Button>
        {!pushed && pending > 0 && (
          <Button variant="outline" size="sm" disabled={busy} onClick={() => onRun({ dryRun: true, choices })}>
            Preview with choices
          </Button>
        )}
        {!pushed && syncable > 0 && (
          <Button size="sm" onClick={() => onRun({ dryRun: false, choices })} disabled={busy}>
            {busy ? "Syncing…" : `Sync ${syncable} insights`}
          </Button>
        )}
      </div>
    </div>
  );
}

/**
 * A sync spends its time in the catalog, one lookup per identity, and used to
 * show nothing at all until it finished. The server runs it as a task, so the
 * shared task view is the progress: same run, same phases, same bar the CLI
 * draws.
 */
function SyncProgress() {
  return (
    <div className="flex flex-col gap-2">
      <p className="text-sm text-muted-foreground">Resolving current states against the catalog…</p>
      <TaskManager basePath="/api/v1" kind={SYNC_TASK_KIND} pollMs={1000} className="max-h-48 overflow-y-auto" />
    </div>
  );
}
