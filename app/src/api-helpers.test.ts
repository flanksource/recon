import { describe, expect, it } from "vitest";
import { overridePatch } from "./api-helpers";

describe("overridePatch", () => {
  it("names only what the run changes", () => {
    expect(
      overridePatch(
        { provider: "github", severities: ["high"] },
        { provider: "github", severities: ["high"], verbose: true },
      ),
    ).toEqual({ verbose: true });
  });

  // The server layers the override over the profile, so an omitted key means
  // "keep what the profile says". Choosing one member of a mutually exclusive
  // group removes its siblings; without the null the profile's member survives
  // the merge and the run fails on a combination nobody asked for.
  it("sends a removed key as null rather than leaving it out", () => {
    expect(
      overridePatch(
        { provider: "github", compliance: ["cis_1.0_github"] },
        { provider: "github", services: ["repository"] },
      ),
    ).toEqual({ compliance: null, services: ["repository"] });
  });

  it("is empty when nothing changed", () => {
    const config = { provider: "github", checks: ["one"] };

    expect(overridePatch(config, { ...config })).toEqual({});
  });

  it("compares by value, not identity", () => {
    expect(
      overridePatch({ checks: ["one", "two"] }, { checks: ["one", "two"] }),
    ).toEqual({});
    expect(overridePatch({ checks: ["one"] }, { checks: ["two"] })).toEqual({
      checks: ["two"],
    });
  });
});
