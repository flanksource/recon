import { AnsiHtml } from "@flanksource/clicky-ui/data";
import type { Discover } from "./types";

export function DiscoveryRunSummary({
  result,
  running,
}: {
  result: Discover | null;
  running: boolean;
}) {
  if (running && !result) {
    return (
      <div className="flex min-h-0 flex-1 items-center justify-center rounded-md border border-border p-6 text-sm text-muted-foreground">
        Probing selected hosts…
      </div>
    );
  }
  if (!result) return null;
  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto rounded-md border border-border p-3">
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <span className="font-medium">
          {result.hosts.length} host{result.hosts.length === 1 ? "" : "s"}{" "}
          probed
        </span>
        {Object.entries(result.profiles)
          .sort(([left], [right]) => left.localeCompare(right))
          .map(([engine, profile]) => (
            <span
              key={engine}
              className="rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground"
            >
              {engine} · {profile}
            </span>
          ))}
        {result.error && (
          <span className="text-destructive">{result.error}</span>
        )}
      </div>
      <AnsiHtml
        as="pre"
        text={result.log}
        className="min-w-0 flex-1 overflow-y-auto whitespace-pre-wrap break-all rounded-md bg-muted/30 p-2 font-mono text-xs"
      />
    </div>
  );
}
