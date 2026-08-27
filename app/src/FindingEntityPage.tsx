import { useCallback, useEffect, useState } from "react";
import { Button } from "@flanksource/clicky-ui/components";
import { fetchFinding } from "./api-scans";
import { FindingDetail } from "./FindingDetail";
import { severityBadge } from "./scanColumns";
import { findingTitle, resourceLabel, severityOf, type Finding } from "./types";

/**
 * One finding: the evidence a single run recorded about a single resource.
 *
 * The generic entity surface used to render this, which titled the page with
 * the finding's UUID and listed `lineNo` and `targetId` beside the remediation
 * — the record's storage rather than what it says. `FindingDetail` is the same
 * component the scan results and the resource page already use, so a finding
 * reads the same wherever someone arrives at it from.
 */
export function FindingEntityPage({
  id,
  onBack,
  onMuteFinding,
}: {
  id: string;
  onBack: () => void;
  onMuteFinding?: (path: string) => void;
}) {
  const [finding, setFinding] = useState<Finding | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      setFinding(await fetchFinding(id));
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setBusy(false);
    }
  }, [id]);

  useEffect(() => { void load(); }, [load]);

  if (error) {
    return (
      <div className="p-6">
        <p role="alert" className="text-sm text-destructive">{error}</p>
        <div className="mt-3 flex gap-2">
          <Button size="sm" variant="outline" onClick={() => void load()}>Retry</Button>
          <Button size="sm" variant="outline" onClick={onBack}>Back to findings</Button>
        </div>
      </div>
    );
  }
  if (busy || !finding) {
    return <div className="p-6 text-sm text-muted-foreground">Loading finding…</div>;
  }

  const subject = finding.resources?.[0];
  return (
    <div className="flex h-full min-h-0 flex-col gap-4 overflow-auto p-4">
      <div className="flex items-center gap-3">
        <Button size="sm" variant="outline" onClick={onBack}>
          Back
        </Button>
        {severityBadge(severityOf(finding))}
        <h1 className="truncate text-lg font-semibold">{findingTitle(finding)}</h1>
        <span className="truncate text-sm text-muted-foreground">
          {subject ? resourceLabel(subject) : finding.matchedAt}
        </span>
      </div>
      <FindingDetail finding={finding} engine={finding.engine} onMute={onMuteFinding} />
    </div>
  );
}
