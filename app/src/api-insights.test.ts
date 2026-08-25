// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchFindingGroups, syncFindings, syncResources } from "./api-insights";

describe("insight sync API", () => {
  afterEach(() => vi.restoreAllMocks());

  it("pages grouped current findings through the grouped route", async () => {
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      data: [], page: { limit: 100, offset: 0, total: 0 },
    }), { status: 200 }));

    await fetchFindingGroups({ status: "open,resolved", limit: 100 });

    expect(fetch).toHaveBeenCalledWith(
      "/api/v1/finding-group?status=open%2Cresolved&limit=100",
      undefined,
    );
  });

  it.each([
    ["finding", syncFindings],
    ["resource", syncResources],
  ] as const)("posts the exact %s selector as a dry-run preview", async (entity, sync) => {
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      agent: "recon", matchedResources: 0, matchedStates: 0, eligible: 0, skipped: 0,
      open: 0, resolved: 0, silenced: 0, direct: 0, rolledUp: 0, pushed: 0,
      configs: [], unresolved: [],
    }), { status: 200 }));

    await sync({ provider: "gcp", status: "open" }, true);

    expect(fetch).toHaveBeenCalledWith(`/api/v1/${entity}/sync`, expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ provider: "gcp", status: "open", "dry-run": true }),
    }));
  });
});
