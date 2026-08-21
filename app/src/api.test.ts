import { afterEach, describe, expect, it, vi } from "vitest";
import { saveTarget } from "./api";

afterEach(() => vi.restoreAllMocks());

describe("target API", () => {
  it("addresses an update by path without sending immutable identity fields", async () => {
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
      "/api/v1/target/gcp%20production",
      expect.objectContaining({
        method: "PUT",
        body: JSON.stringify({
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
          id: "cloudflare-production",
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

    await saveTarget("cloudflare-production", {
      class: "prod",
      profiles: ["scan:prowler:cloudflare"],
      tags: [],
      credentials: null,
    });

    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(init.body as string)).toEqual({
      class: "prod",
      profiles: ["scan:prowler:cloudflare"],
      tags: [],
      credentials: null,
    });
  });
});
