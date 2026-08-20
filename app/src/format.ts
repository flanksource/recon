// Binary units, not decimal: the number this renders is a count of bytes read
// off sockets, and every tool anyone would compare it against — ls, du, curl —
// reports the same quantity in KiB.
const UNITS = ["KiB", "MiB", "GiB", "TiB"];

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  // One decimal below ten, none above: "3.5 GiB" is a useful distinction and
  // "1234.6 MiB" is six digits of precision nobody asked for.
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${UNITS[unit]}`;
}
