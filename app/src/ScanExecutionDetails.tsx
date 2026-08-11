import { AnsiHtml } from "@flanksource/clicky-ui";
import type { Scan } from "./types";

function duration(milliseconds: number): string {
  if (milliseconds < 1000) return `${milliseconds}ms`;
  const seconds = milliseconds / 1000;
  if (seconds < 60) return `${Number(seconds.toFixed(1))}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${Number((seconds % 60).toFixed(1))}s`;
}

function EvidenceStat({ label, value }: { label: string; value: string | number }) {
  return (
    <span className="flex items-baseline gap-1">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className="text-sm font-medium tabular-nums">{value}</span>
    </span>
  );
}

type CommandArgument = {
  id: string;
  flag?: string;
  value?: string;
};

function isFlag(argument: string): boolean {
  return /^--?[A-Za-z]/.test(argument);
}

function commandArguments(command: string[]): CommandArgument[] {
  const arguments_: CommandArgument[] = [];
  const occurrences = new Map<string, number>();
  for (let index = 1; index < command.length; index += 1) {
    const argument = command[index];
    let row: Omit<CommandArgument, "id">;
    if (isFlag(argument)) {
      const next = command[index + 1];
      if (next !== undefined && !isFlag(next)) {
        row = { flag: argument, value: next };
        index += 1;
      } else {
        row = { flag: argument };
      }
    } else {
      row = { value: argument };
    }
    const signature = JSON.stringify(row);
    const occurrence = (occurrences.get(signature) ?? 0) + 1;
    occurrences.set(signature, occurrence);
    arguments_.push({ id: `${signature}:${occurrence}`, ...row });
  }
  return arguments_;
}

function CommandLine({ command }: { command: string[] }) {
  if (command.length === 0) {
    return <p className="rounded border bg-background p-2 text-xs text-muted-foreground">No command recorded.</p>;
  }

  return (
    <div aria-label="Command and arguments" className="min-w-0 overflow-hidden rounded border bg-background font-mono text-xs">
      <div className="flex min-w-0 gap-2 border-b bg-muted/30 px-3 py-2">
        <span aria-hidden className="shrink-0 text-muted-foreground">$</span>
        <span data-command-part="executable" className="min-w-0 break-all font-semibold text-cyan-700 dark:text-cyan-300">
          {command[0]}
        </span>
      </div>
      <div className="divide-y divide-border/60">
        {commandArguments(command).map((argument) => (
          <div
            key={argument.id}
            className="grid min-w-0 gap-x-3 gap-y-1 px-3 py-1.5 sm:grid-cols-[minmax(8rem,auto)_minmax(0,1fr)]"
          >
            {argument.flag ? (
              <span data-command-part="flag" className="break-all font-medium text-violet-700 dark:text-violet-300">
                {argument.flag}
              </span>
            ) : (
              <span aria-hidden className="hidden sm:block" />
            )}
            {argument.value !== undefined && (
              <span data-command-part="value" className="min-w-0 break-all text-amber-700 dark:text-amber-300">
                {argument.value}
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function CapturedStream({
  label,
  text,
  truncated,
  error,
}: {
  label: string;
  text?: string;
  truncated?: boolean;
  error?: boolean;
}) {
  return (
    <div className="overflow-hidden rounded border bg-black">
      <div className="flex items-center justify-between border-b border-white/10 px-2 py-1 text-[10px] text-gray-400">
        <span>{label}</span>
        {truncated && <span>showing latest 1 MiB</span>}
      </div>
      {text ? (
        <AnsiHtml
          text={text}
          className={`max-h-52 overflow-auto whitespace-pre-wrap p-2 text-xs text-gray-100 ${error ? "text-red-300" : ""}`}
        />
      ) : (
        <p className="p-2 text-xs text-gray-500">No {label}.</p>
      )}
    </div>
  );
}

export function ScanExecutionDetails({ scan }: { scan: Scan }) {
  return (
    <section aria-label="Scan execution details" className="mb-3 space-y-3 rounded-md border bg-muted/20 p-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <EvidenceStat label="profile" value={scan.profile} />
        <EvidenceStat label="selector" value={scan.selectorLabel} />
        <EvidenceStat label="phase" value={scan.phase} />
        <EvidenceStat label="runtime" value={duration(scan.durationMs)} />
        <EvidenceStat label="targets" value={scan.endpointCount} />
        <EvidenceStat label="requests" value={scan.stats ? `${scan.stats.requests} / ${scan.stats.total}` : "—"} />
        <EvidenceStat label="templates" value={scan.stats?.templates ?? "—"} />
        <EvidenceStat label="matched" value={scan.stats?.matched ?? scan.findings} />
        <EvidenceStat label="errors" value={scan.stats?.errors ?? "—"} />
        <EvidenceStat label="rps" value={scan.stats?.rps ?? "—"} />
        <EvidenceStat label="findings" value={scan.findings} />
        <EvidenceStat label="affected hosts" value={scan.hosts.length} />
        <EvidenceStat label="exit" value={scan.exitCode ?? "—"} />
        {scan.engineVersion && <EvidenceStat label="engine" value={`${scan.engine} ${scan.engineVersion}`} />}
      </div>

      {scan.error && (
        <div role="alert" className="rounded border border-destructive/40 bg-destructive/5 p-2 text-sm text-destructive">
          {scan.error}
        </div>
      )}

      <div className="space-y-1">
        <div className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
          Command and arguments
        </div>
        <CommandLine command={scan.command ?? []} />
      </div>

      {scan.outputCaptured ? (
        <div className="grid gap-2 xl:grid-cols-2">
          <CapturedStream label="stdout" text={scan.stdout} truncated={scan.stdoutTruncated} />
          <CapturedStream label="stderr" text={scan.stderr} truncated={scan.stderrTruncated} error />
        </div>
      ) : (
        <p className="text-xs text-muted-foreground">Process output was not captured for this scan.</p>
      )}
    </section>
  );
}
