// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchResourceFindings } from "./api-resources";

describe("fetchResourceFindings", () => {
  afterEach(() => vi.restoreAllMocks());

  it("returns finding rows from the paged listing envelope", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      data: [{
        scanId: "scan-1",
        lineNo: 1,
        templateId: "gcp/bucket_public_access",
        name: "Bucket is publicly accessible",
        severity: "high",
        host: "flanksource-prod",
        matchedAt: "logs",
        tags: [],
      }],
      page: { limit: 500, offset: 0, total: 1 },
    }), { status: 200 }));

    const findings = await fetchResourceFindings("resource-1");

    expect(findings).toEqual([
      expect.objectContaining({ templateId: "gcp/bucket_public_access" }),
    ]);
  });
});
