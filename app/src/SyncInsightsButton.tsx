import { useCallback, useState } from "react";
import { Button, Modal } from "@flanksource/clicky-ui/components";
import type { InsightSync } from "./types";

export function SyncInsightsButton({ sync, disabled = false }: {
  sync: (dryRun: boolean) => Promise<InsightSync>;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [preview, setPreview] = useState<InsightSync | null>(null);
  const [pushed, setPushed] = useState<InsightSync | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = useCallback(async (dryRun: boolean) => {
    setBusy(true);
    setError(null);
    try {
      const result = await sync(dryRun);
      if (dryRun) setPreview(result);
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
    setError(null);
    setOpen(true);
    void run(true);
  }, [run]);

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
          onSync={() => void run(false)}
          onClose={() => setOpen(false)}
        />
      </Modal>
    </>
  );
}

function SyncBody({ busy, error, preview, pushed, onSync, onClose }: {
  busy: boolean;
  error: string | null;
  preview: InsightSync | null;
  pushed: InsightSync | null;
  onSync: () => void;
  onClose: () => void;
}) {
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

  const result = pushed ?? preview;
  if (busy && !result) {
    return <p className="text-sm text-muted-foreground">Resolving current states against the catalog…</p>;
  }
  if (!result) return null;
  const syncable = result.direct + result.rolledUp;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap gap-3">
        <Count label="Resources" value={result.matchedResources} />
        <Count label="States" value={result.matchedStates} />
        <Count label="Eligible" value={result.eligible} />
        <Count label="Skipped" value={result.skipped} />
      </div>
      <div className="flex flex-wrap gap-3">
        <Count label="Open" value={result.open} />
        <Count label="Resolved" value={result.resolved} />
        <Count label="Silenced" value={result.silenced} />
        <Count label="Direct" value={result.direct} />
        <Count label="Rolled up" value={result.rolledUp} />
        {pushed && <Count label="Pushed" value={pushed.pushed} />}
      </div>

      {result.server && (
        <p className="text-xs text-muted-foreground">
          {pushed ? "Synced to" : "Would sync to"} {result.server} as agent <code>{result.agent}</code>
        </p>
      )}
      {result.configs.length > 0 && <ConfigList configs={result.configs} />}
      {result.unresolved.length > 0 && <UnresolvedList unresolved={result.unresolved} />}
      {syncable === 0 && (
        <p className="text-sm text-muted-foreground">No resolvable insights match this selection.</p>
      )}
      {result.notes?.map((note) => (
        <p key={note} className="text-xs text-amber-600 dark:text-amber-400">{note}</p>
      ))}

      <div className="flex justify-end gap-2">
        <Button variant="outline" size="sm" onClick={onClose}>{pushed ? "Close" : "Cancel"}</Button>
        {!pushed && syncable > 0 && (
          <Button size="sm" onClick={onSync} disabled={busy}>
            {busy ? "Syncing…" : `Sync ${syncable} insights`}
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

function ConfigList({ configs }: { configs: InsightSync["configs"] }) {
  return (
    <div className="flex flex-col gap-1">
      <h3 className="text-xs font-medium text-muted-foreground">Config items</h3>
      <ul className="max-h-48 overflow-y-auto text-sm">
        {configs.map((config) => (
          <li key={config.id} className="flex items-baseline justify-between gap-2 py-0.5">
            <span className="truncate">
              {config.name || config.id}
              {config.type && <span className="text-muted-foreground"> · {config.type}</span>}
              {config.rolledUp && <span className="text-amber-600 dark:text-amber-400"> · rolled up</span>}
            </span>
            <span className="shrink-0 tabular-nums text-muted-foreground">{config.insights}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function UnresolvedList({ unresolved }: { unresolved: InsightSync["unresolved"] }) {
  return (
    <div className="flex flex-col gap-1">
      <h3 className="text-xs font-medium text-muted-foreground">Not synced — no matching catalog item</h3>
      <ul className="max-h-48 overflow-y-auto text-sm">
        {unresolved.map((item) => (
          <li key={item.finding} className="py-0.5">
            {item.host || item.finding}
            <span className="text-xs text-muted-foreground"> · tried {item.tried.join(", ")}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
