import { formatBytes } from "./format";
import type { HTTPStats } from "./types";

// Bars are coloured by what the number means, not by position in a legend: the
// question anyone asks of a status-code breakdown is "how much of this went
// wrong", and a categorical palette makes that a lookup rather than a glance.
// The classes match the severity bars the runs list already uses.
const NEUTRAL = "bg-neutral-400";
const OK = "bg-emerald-500";
const REDIRECT = "bg-sky-500";
const CLIENT_ERROR = "bg-amber-500";
const SERVER_ERROR = "bg-red-600";

function statusColor(code: string): string {
  switch (code[0]) {
    case "2":
      return OK;
    case "3":
      return REDIRECT;
    case "4":
      return CLIENT_ERROR;
    case "5":
      return SERVER_ERROR;
    default:
      return NEUTRAL;
  }
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <span className="flex items-baseline gap-1">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className="text-sm font-medium tabular-nums">{value}</span>
    </span>
  );
}

// Counts are shown as bars scaled to the largest one rather than to the total:
// a run where 99% of responses are 200 would otherwise render every other code
// as an invisible sliver, and those are the ones worth seeing.
function CountBars({
  title,
  counts,
  color,
  limit = 8,
}: {
  title: string;
  counts: Record<string, number>;
  color?: (key: string) => string;
  limit?: number;
}) {
  const rows = Object.entries(counts).sort(([, a], [, b]) => b - a);
  if (rows.length === 0) return null;

  const shown = rows.slice(0, limit);
  const hidden = rows.length - shown.length;
  const largest = shown[0][1] || 1;

  return (
    <div className="min-w-0 space-y-1">
      <div className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
        {title}
      </div>
      <ul className="space-y-1">
        {shown.map(([key, count]) => (
          <li key={key} className="grid grid-cols-[minmax(0,7rem)_minmax(0,1fr)_auto] items-center gap-2">
            <span className="truncate font-mono text-xs" title={key}>
              {key}
            </span>
            <span className="h-1.5 overflow-hidden rounded-full bg-muted">
              <span
                className={`block h-full rounded-full ${color?.(key) ?? NEUTRAL}`}
                style={{ width: `${Math.max((count / largest) * 100, 2)}%` }}
              />
            </span>
            <span className="text-xs font-medium tabular-nums">{count}</span>
          </li>
        ))}
      </ul>
      {hidden > 0 && (
        <p className="text-[11px] text-muted-foreground">
          +{hidden} more not shown
        </p>
      )}
    </div>
  );
}

// The traffic a run generated, as opposed to what it found. A scan that reports
// no findings and a scan whose every request was refused look identical on the
// findings tab; this is where they stop looking identical.
export function ScanTraffic({ http }: { http?: HTTPStats }) {
  if (!http || (http.requests === 0 && http.responses === 0 && http.failed === 0)) {
    return (
      <p className="text-xs text-muted-foreground">
        No traffic statistics were collected for this scan.
      </p>
    );
  }

  const failureRate = http.requests
    ? `${((http.failed / http.requests) * 100).toFixed(1)}%`
    : "—";

  return (
    <div aria-label="Scan traffic statistics" className="space-y-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <Stat label="requests" value={http.requests.toLocaleString()} />
        <Stat label="responses" value={http.responses.toLocaleString()} />
        <Stat label="failed" value={http.failed.toLocaleString()} />
        <Stat label="failure rate" value={failureRate} />
        <Stat label="received" value={formatBytes(http.bytes)} />
      </div>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <CountBars title="Status codes" counts={http.statusCodes} color={statusColor} />
        <CountBars title="Protocols" counts={http.protocols} color={() => REDIRECT} />
        <CountBars title="Errors" counts={http.errors} color={() => SERVER_ERROR} />
        <CountBars title="WAF detected" counts={http.waf} color={() => CLIENT_ERROR} />
      </div>
    </div>
  );
}
