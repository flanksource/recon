import { describe, expect, it } from "vitest";
import { formatBytes } from "./format";

describe("formatBytes", () => {
  it.each([
    [0, "0 B"],
    [512, "512 B"],
    // The boundary: 1024 is one KiB, not "1024 B".
    [1024, "1.0 KiB"],
    [2048, "2.0 KiB"],
    // Ten and above drops the decimal, so a scan does not report six digits of
    // precision nobody asked for.
    [1024 * 1024 * 20, "20 MiB"],
    [1024 ** 3 * 3.5, "3.5 GiB"],
    // Past the largest unit it keeps counting in TiB rather than inventing one.
    [1024 ** 5, "1024 TiB"],
  ])("renders %i bytes as %s", (bytes, expected) => {
    expect(formatBytes(bytes)).toBe(expected);
  });
});
