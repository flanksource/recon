export function boundedScanPercent(percent?: number): number {
  if (percent === undefined || !Number.isFinite(percent) || percent < 0 || percent > 100) {
    return 0;
  }
  return percent;
}
