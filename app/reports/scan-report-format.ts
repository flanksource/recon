// How a number or a timestamp becomes the string the report prints.
//
// Split out of scan-report-model.ts because these are the only functions there
// that know nothing about a scan — they are about rendering a quantity, and the
// model is about deciding which quantity is honest to render.
//
// The one rule they share: a value the engine did not report prints as an em
// dash, never as zero. "0 requests" and "this engine does not count requests"
// are different facts and must not print identically.

export function formatDuration(milliseconds: number): string {
  if (!Number.isFinite(milliseconds) || milliseconds <= 0) return "—";
  if (milliseconds < 1000) return `${Math.round(milliseconds)}ms`;
  const seconds = milliseconds / 1000;
  if (seconds < 60) return `${Number(seconds.toFixed(1))}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = Number((seconds % 60).toFixed(0));
  if (minutes < 60) return `${minutes}m ${rest}s`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${Number(value.toFixed(value < 10 && unit > 0 ? 1 : 0))} ${units[unit]}`;
}

export function formatDate(iso: string | undefined): string {
  if (!iso) return "—";
  const at = new Date(iso);
  return Number.isNaN(at.getTime()) ? iso : at.toISOString().replace("T", " ").slice(0, 19) + "Z";
}

/** A count the engine reported, or an em dash for one it never did. */
export function formatCount(value: number | undefined): string {
  return typeof value === "number" && Number.isFinite(value)
    ? Math.round(value).toLocaleString("en-US")
    : "—";
}
