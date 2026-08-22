import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchScanParameters, saveTarget } from "./api";

afterEach(() => vi.restoreAllMocks());

describe("target API", () => {
  it("sends an update to the collection route with its identity", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          $schema: "../target.schema.json",
          version: 2,
          id: "gcp production",
          kind: "provider-context",
          provider: "gcp",
          credentialMode: "ambient",
          class: "prod",
          profiles: ["scan:prowler:cis"],
          tags: [],
        }),
        { status: 200 },
      ),
    );

    await saveTarget("gcp production", {
      class: "prod",
      profiles: ["scan:prowler:cis"],
      tags: [],
      credentialMode: "ambient",
      arguments: { "project-ids": ["workload-prod-eu-02"] },
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/target",
      expect.objectContaining({
        method: "PUT",
        body: JSON.stringify({
          id: "gcp production",
          class: "prod",
          profiles: ["scan:prowler:cis"],
          tags: [],
          credentialMode: "ambient",
          arguments: { "project-ids": ["workload-prod-eu-02"] },
        }),
      }),
    );
  });

  it("serializes an explicit credential clear without response sentinels", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          $schema: "../target.schema.json",
          version: 2,
          id: "cloudflare",
          kind: "provider-context",
          provider: "cloudflare",
          credentialMode: "configured",
          class: "prod",
          profiles: ["scan:prowler:cloudflare"],
          tags: [],
        }),
        { status: 200 },
      ),
    );

    await saveTarget("cloudflare", {
      class: "prod",
      profiles: ["scan:prowler:cloudflare"],
      tags: [],
      credentials: null,
    });

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/v1/target");
    expect(JSON.parse(init.body as string)).toEqual({
      id: "cloudflare",
      class: "prod",
      profiles: ["scan:prowler:cloudflare"],
      tags: [],
      credentials: null,
    });
  });
});

describe("scan parameters API", () => {
  it("reads the effective config artifact retained with the run", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ "rate-limit": 50, headless: true }), {
        status: 200,
      }),
    );

    await expect(fetchScanParameters("scan one")).resolves.toEqual({
      "rate-limit": 50,
      headless: true,
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/scan/scan%20one/files/config.json",
      undefined,
    );
  });

  it("rejects a config artifact whose root is not an object", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify(["rate-limit", 50]), { status: 200 }),
    );

    await expect(fetchScanParameters("scan-1")).rejects.toThrow(
      "scan scan-1 config.json must contain a JSON object",
    );
  });
});
