import { useEffect, useState } from "react";
import { fetchScanFiles, scanFileUrl } from "./api";
import { formatBytes } from "./format";
import type { ScanFiles } from "./types";

// What each artifact is, in the vocabulary of someone who has just opened the
// directory and wants to know which file to read first. Names not listed here
// still render — an engine may write more than recon knows about, and hiding a
// file because it is unfamiliar is the opposite of retaining evidence.
const DESCRIPTIONS: Record<string, string> = {
  "findings.jsonl": "The engine's own output, one result per line",
  "targets.txt": "The subjects the selector resolved to",
  "config.json": "The effective engine configuration, overrides included",
  "scan.json": "The run's record: timings, command, counts, statistics",
  "output.log": "The engine's log output",
  "inputs.yml": "The benchmark inputs this run was given",
};

// Some artifacts are named after what they describe rather than what they are,
// so their description has to be derived. Matched after the exact names above.
const PATTERNS: { match: RegExp; describe: (name: string) => string }[] = [
  {
    // inspec-<project>.json — the complete compliance report for one account,
    // including the controls that passed, which are counted but not stored as
    // findings.
    match: /^inspec-(.+)\.json$/,
    describe: (name) =>
      `Full InSpec report for ${name.replace(/^inspec-/, "").replace(/\.json$/, "")}, passes included`,
  },
];

function describe(name: string): string | undefined {
  if (DESCRIPTIONS[name]) return DESCRIPTIONS[name];
  return PATTERNS.find((pattern) => pattern.match.test(name))?.describe(name);
}

export function ScanArtifacts({ scanId, path }: { scanId: string; path?: string }) {
  const [listing, setListing] = useState<ScanFiles | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setListing(null);
    setError(null);
    if (!path) return;
    fetchScanFiles(scanId)
      .then((result) => !cancelled && setListing(result))
      .catch((reason) => !cancelled && setError((reason as Error).message));
    return () => {
      cancelled = true;
    };
  }, [scanId, path]);

  if (!path) {
    return (
      <p className="text-xs text-muted-foreground">
        This run kept no artifacts — it ran before results were retained on disk.
      </p>
    );
  }

  return (
    <div className="space-y-2">
      {/* The path is selectable text rather than a link: a browser cannot open a
          local directory, and a file:// anchor that silently does nothing is
          worse than a path someone can copy into a terminal. */}
      <code className="block min-w-0 select-all break-all rounded border bg-background px-2 py-1 text-xs">
        {path}
      </code>

      {error && (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      )}
      {!listing && !error && (
        <p className="text-xs text-muted-foreground">Reading the directory…</p>
      )}

      {listing && listing.files.length === 0 && (
        <p className="text-xs text-muted-foreground">The directory is empty.</p>
      )}
      {listing && listing.files.length > 0 && (
        <ul className="divide-y divide-border/60 overflow-hidden rounded border">
          {listing.files.map((file) => (
            <li
              key={file.name}
              className="grid min-w-0 grid-cols-[minmax(0,1fr)_auto] items-center gap-2 px-2 py-1.5"
            >
              <span className="min-w-0">
                <a
                  href={scanFileUrl(scanId, file.name)}
                  target="_blank"
                  rel="noreferrer"
                  className="truncate font-mono text-xs text-primary hover:underline"
                >
                  {file.name}
                </a>
                {describe(file.name) && (
                  <span className="block truncate text-[11px] text-muted-foreground">
                    {describe(file.name)}
                  </span>
                )}
              </span>
              <span className="text-xs tabular-nums text-muted-foreground">
                {formatBytes(file.size)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
