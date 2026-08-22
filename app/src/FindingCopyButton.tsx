import { useEffect, useState } from "react";
import { Button } from "@flanksource/clicky-ui/components";
import { UiCheck, UiCopy } from "@flanksource/clicky-ui/icons";
import { fetchScanParameters } from "./api";
import { formatFindingsMarkdown } from "./finding-markdown";
import type { FilterSelection, Finding, Scan } from "./types";

type CopyState = "idle" | "copying" | "copied" | "error";

export function FindingCopyButton({
  scan,
  findings,
  loadedFindingCount,
  selection,
  search,
  findingLimit,
  loading,
}: {
  scan: Scan | null;
  findings: Finding[];
  loadedFindingCount: number;
  selection: FilterSelection;
  search: string;
  findingLimit: number;
  loading: boolean;
}) {
  const [state, setState] = useState<CopyState>("idle");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setState("idle");
    setError(null);
  }, [findings, search, selection]);

  async function copy(): Promise<void> {
    if (!scan || loading || findings.length === 0) return;
    setState("copying");
    setError(null);
    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error("Clipboard access is unavailable in this browser");
      }
      const parameters = scan.resultPath
        ? await fetchScanParameters(scan.id)
        : undefined;
      await navigator.clipboard.writeText(
        formatFindingsMarkdown({
          scan,
          findings,
          loadedFindingCount,
          selection,
          search,
          sourceURL: window.location.href,
          findingLimit,
          parameters,
        }),
      );
      setState("copied");
    } catch (reason) {
      setState("error");
      setError(reason instanceof Error ? reason.message : String(reason));
    }
  }

  const label =
    state === "copying"
      ? "Copying…"
      : state === "copied"
        ? "Copied"
        : state === "error"
          ? "Copy failed"
          : "Copy";

  return (
    <>
      <Button
        variant="outline"
        size="sm"
        aria-label={state === "idle" ? "Copy visible findings for an LLM" : label}
        title={error ?? "Copy visible findings for an LLM"}
        disabled={loading || !scan || findings.length === 0 || state === "copying"}
        onClick={() => void copy()}
      >
        {state === "copied" ? <UiCheck /> : <UiCopy />}
        {label}
      </Button>
      {error && (
        <span role="alert" className="max-w-40 truncate text-xs text-destructive" title={error}>
          {error}
        </span>
      )}
    </>
  );
}
