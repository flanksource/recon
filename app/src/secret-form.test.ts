import { afterEach, describe, expect, it, vi } from "vitest";
import { secretFormLoaders } from "./secret-form";

describe("secret metadata loaders", () => {
  afterEach(() => vi.restoreAllMocks());

  it("uses the recon metadata routes without inventing a target namespace", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async () =>
      new Response("[]", {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );

    await secretFormLoaders.loadResources("secret", "ignored");
    await secretFormLoaders.loadKeyPreview("helm", "prowler", "ignored");
    await secretFormLoaders.loadOnePasswordVaults();
    await secretFormLoaders.loadOnePasswordItems("vault/prod");
    await secretFormLoaders.loadOnePasswordFields("vault/prod", "prowler token");

    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "/api/v1/secrets?kind=secret",
      "/api/v1/secrets/preview?kind=helm&name=prowler",
      "/api/v1/secrets/onepassword/vaults",
      "/api/v1/secrets/onepassword/items?vault=vault%2Fprod",
      "/api/v1/secrets/onepassword/fields?vault=vault%2Fprod&item=prowler%20token",
    ]);
  });
});
