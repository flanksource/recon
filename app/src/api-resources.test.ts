// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchResourceConfig, fetchResourceFindings, removeResourceConfig } from "./api-resources";

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

describe("fetchResourceConfig", () => {
  afterEach(() => vi.restoreAllMocks());

  it("reads the linked catalog item through the resource action", async () => {
    const response = {
      id: "fc3e34be-c311-e6e7-7b64-e29cfe90334e",
      name: "Production GCP",
      type: "GCP::Project",
      url: "https://beta.example.com/catalog/fc3e34be-c311-e6e7-7b64-e29cfe90334e",
    };
    const request = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify(response), { status: 200 }),
    );

    await expect(fetchResourceConfig("resource-1")).resolves.toEqual(response);
    expect(request).toHaveBeenCalledWith(
      "/api/v1/resource/resource-1/config",
      undefined,
    );
  });

  it("removes the stored link without deleting the catalog item", async () => {
    const request = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ resourceId: "resource-1" }), { status: 200 }),
    );

    await removeResourceConfig("resource-1");

    expect(request).toHaveBeenCalledWith(
      "/api/v1/resource/resource-1/unlink-config",
      { method: "POST" },
    );
  });
});
