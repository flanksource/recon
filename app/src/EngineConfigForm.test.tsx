// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { EngineConfigForm, resolveEngineConfigSchema } from "./EngineConfigForm";
import type { LookupFetcher } from "@flanksource/clicky-ui/components";
import type { Engine } from "./types";

const prowler: Engine = {
  name: "prowler",
  kind: "scan",
  title: "Prowler",
  binary: "prowler",
  installed: true,
  managed: false,
  options: {
    discriminator: "provider",
    variants: [
      {
        id: "gcp",
        title: "Google Cloud",
        schema: {
          type: "object",
          additionalProperties: false,
          "x-sections": [
            { id: "selection", title: "Checks & frameworks" },
            { id: "scope", title: "Scope", description: "Projects to audit." },
          ],
          "x-order": ["provider", "compliance", "checks", "project-ids"],
          properties: {
            provider: {
              type: "string",
              const: "gcp",
              "x-section": "selection",
            },
            compliance: {
              type: "array",
              title: "Frameworks",
              "x-section": "selection",
              "x-clicky-lookup": {
                url: "/api/v1/profile",
                filter: "name",
                multi: true,
                scope: { param: "provider", from: "provider" },
              },
              items: { type: "string" },
            },
            checks: {
              type: "array",
              title: "Checks",
              "x-section": "selection",
              items: { type: "string" },
            },
            "project-ids": {
              type: "array",
              title: "Project IDs",
              default: ["upstream-default"],
              "x-section": "scope",
              items: { type: "string" },
            },
          },
        },
        contextSchema: {
          type: "object",
          additionalProperties: false,
          "x-sections": [{ id: "scope", title: "Scope" }],
          "x-order": ["project-ids", "credentials-file"],
          properties: {
            "project-ids": {
              type: "array",
              title: "Project IDs",
              "x-section": "scope",
              items: { type: "string" },
            },
            "credentials-file": {
              type: "string",
              title: "Credentials file",
              "x-credential-selector": true,
              "x-section": "scope",
            },
          },
        },
      },
      {
        id: "github",
        title: "GitHub",
        schema: {
          type: "object",
          "x-sections": [{ id: "scope", title: "Scope" }],
          "x-order": ["provider", "repositories"],
          properties: {
            provider: {
              type: "string",
              const: "github",
              "x-section": "scope",
            },
            repositories: {
              type: "array",
              title: "Repositories",
              "x-section": "scope",
              items: { type: "string" },
            },
          },
        },
      },
    ],
  },
};

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("EngineConfigForm", () => {
  it("renders the selected provider variant in generated section order without editing the provider", async () => {
    const lookupFetcher = vi.fn<LookupFetcher>(async () => [
      { value: "cis_5.0_gcp", label: "CIS Google Cloud 5.0" },
    ]);
    const onChange = vi.fn();
    render(
      <EngineConfigForm
        engine={prowler}
        identity="scan:prowler:cis"
        value={{ provider: "gcp", compliance: ["cis_5.0_gcp"] }}
        baseline={{ provider: "gcp", compliance: ["cis_5.0_gcp"] }}
        onChange={onChange}
        lookupFetcher={lookupFetcher}
      />,
    );

    expect(screen.getByText("Google Cloud")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Checks & frameworks" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Scope" })).toBeTruthy();
    expect(screen.queryByText("provider")).toBeNull();
    expect(screen.getByText("Frameworks")).toBeTruthy();
    await waitFor(() => expect(lookupFetcher).toHaveBeenCalled());
    expect(lookupFetcher.mock.calls[0]?.[0]).toEqual(
      expect.objectContaining({ rootValue: expect.objectContaining({ provider: "gcp" }) }),
    );

    fireEvent.click(screen.getByRole("button", { name: "Scope" }));
    expect(screen.getByText("Project IDs")).toBeTruthy();
    expect(screen.getByText("Projects to audit.")).toBeTruthy();
    expect(onChange).not.toHaveBeenCalled();
  });

  it("surfaces RFC 6901 errors on the matching field", () => {
    render(
      <EngineConfigForm
        engine={prowler}
        identity="scan:prowler:cis"
        value={{ provider: "gcp", "project-ids": [] }}
        onChange={vi.fn()}
        errors={[{ instancePath: "/project-ids", message: "Select at least one project" }]}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Scope" }));
    expect(screen.getByText("Select at least one project")).toBeTruthy();
  });

  it("preserves the complete root config when an active section changes", () => {
    const engine: Engine = {
      ...prowler,
      options: {
        discriminator: "provider",
        variants: [
          {
            id: "gcp",
            title: "Google Cloud",
            schema: {
              type: "object",
              "x-sections": [
                { id: "selection", title: "Selection" },
                { id: "runtime", title: "Runtime" },
              ],
              "x-order": ["provider", "checks", "verbose"],
              properties: {
                provider: { type: "string", const: "gcp", "x-section": "selection" },
                checks: {
                  type: "array",
                  items: { type: "string" },
                  "x-section": "selection",
                },
                verbose: { type: "boolean", title: "Verbose", "x-section": "runtime" },
              },
            },
          },
        ],
      },
    };
    const onChange = vi.fn();
    render(
      <EngineConfigForm
        engine={engine}
        identity="scan:prowler:root-update"
        value={{ provider: "gcp", checks: ["iam_1"] }}
        onChange={onChange}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Runtime" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Verbose" }));
    expect(onChange).toHaveBeenCalledWith({
      provider: "gcp",
      checks: ["iam_1"],
      verbose: true,
    });
  });

  it("selects a context variant without adding the provider to raw arguments", () => {
    const onChange = vi.fn();
    render(
      <EngineConfigForm
        engine={prowler}
        identity="gcp-production:context"
        schemaKind="context"
        variantId="gcp"
        value={{ "project-ids": ["workload-prod-eu-02"] }}
        onChange={onChange}
      />,
    );

    const projectInput = screen.getByRole("combobox", { name: "Project IDs" });
    fireEvent.change(projectInput, { target: { value: "flanksource-prod" } });
    fireEvent.keyDown(projectInput, { key: "Enter" });
    expect(onChange).toHaveBeenCalledWith({
      "project-ids": ["workload-prod-eu-02", "flanksource-prod"],
    });
  });

  it("hides and clears configured credential selectors in ambient mode", async () => {
    const onChange = vi.fn();
    render(
      <EngineConfigForm
        engine={prowler}
        identity="gcp-production:context"
        schemaKind="context"
        variantId="gcp"
        credentialMode="ambient"
        value={{
          "project-ids": ["workload-prod-eu-02"],
          "credentials-file": "/secrets/gcp.json",
        }}
        onChange={onChange}
      />,
    );

    expect(screen.queryByText("Credentials file")).toBeNull();
    await waitFor(() =>
      expect(onChange).toHaveBeenCalledWith({
        "project-ids": ["workload-prod-eu-02"],
      }),
    );
  });

  it("resolves lookup scope from the immutable provider", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({ filters: { name: { options: { cis_5_0_gcp: null } } } }),
        { status: 200 },
      ),
    );
    render(
      <EngineConfigForm
        engine={prowler}
        identity="scan:prowler:lookup"
        value={{ provider: "gcp" }}
        onChange={vi.fn()}
      />,
    );
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    const requested = new URL(String(fetchMock.mock.calls[0]?.[0]), "http://recon.test");
    expect(Object.fromEntries(requested.searchParams)).toEqual({
      __lookup: "filters",
      __lookup_filter: "name",
      provider: "gcp",
    });
  });

  it("removes defaults from referenced definitions before rendering", () => {
    const schema = prowler.options.variants[0].schema;
    const engine: Engine = {
      ...prowler,
      options: {
        ...prowler.options,
        variants: [
          {
            ...prowler.options.variants[0],
            schema: {
              ...schema,
              $defs: {
                outputFormat: {
                  type: "string",
                  enum: ["json", "csv"],
                  default: "json",
                },
              },
            },
          },
        ],
      },
    };

    expect(
      resolveEngineConfigSchema(engine, { provider: "gcp" }).sections[0].schema
        .$defs,
    ).toEqual({
      outputFormat: { type: "string", enum: ["json", "csv"] },
    });
  });

  it("fails explicitly for a missing or unknown provider", () => {
    expect(() => resolveEngineConfigSchema(prowler, {})).toThrow(
      'Prowler configuration requires "provider"',
    );
    expect(() => resolveEngineConfigSchema(prowler, { provider: "aws" })).toThrow(
      'Prowler does not define provider variant "aws"',
    );
  });

  it("does not apply Nuclei-only paired filter controls to Prowler", () => {
    const engine: Engine = {
      ...prowler,
      options: {
        variants: [
          {
            id: "default",
            title: "Prowler",
            schema: {
              type: "object",
              "x-sections": [{ id: "filters", title: "Filters" }],
              "x-order": ["tags", "exclude-tags"],
              properties: {
                tags: { type: "array", title: "Tags", "x-section": "filters", items: { type: "string" } },
                "exclude-tags": {
                  type: "array",
                  title: "Excluded tags",
                  "x-section": "filters",
                  items: { type: "string" },
                },
              },
            },
          },
        ],
      },
    };
    render(
      <EngineConfigForm
        engine={engine}
        identity="scan:prowler:filters"
        value={{}}
        onChange={vi.fn()}
      />,
    );
    expect(screen.getByText("Tags")).toBeTruthy();
    expect(screen.getByText("Excluded tags")).toBeTruthy();
  });

  it("renders enum-backed include and exclude nargs as multi-selects", () => {
    const engine: Engine = {
      ...prowler,
      options: {
        variants: [
          {
            id: "gcp",
            title: "Google Cloud",
            schema: {
              type: "object",
              "x-sections": [
                { id: "include", title: "Include" },
                { id: "exclude", title: "Exclude" },
              ],
              "x-order": ["provider", "checks", "excluded-checks"],
              properties: {
                provider: { type: "string", const: "gcp", "x-section": "include" },
                checks: {
                  type: "array",
                  title: "Checks",
                  items: { type: "string", enum: ["iam_1", "storage_1"] },
                  "x-prowler-nargs": "+",
                  "x-section": "include",
                },
                "excluded-checks": {
                  type: "array",
                  title: "Excluded checks",
                  items: { type: "string", enum: ["iam_1", "storage_1"] },
                  "x-prowler-nargs": "+",
                  "x-section": "exclude",
                },
              },
            },
          },
        ],
      },
    };
    const onChange = vi.fn();
    render(
      <EngineConfigForm
        engine={engine}
        identity="scan:prowler:enum-arrays"
        value={{ provider: "gcp", checks: ["iam_1"] }}
        onChange={onChange}
      />,
    );

    const checks = screen.getByRole("combobox", { name: "Checks" });
    expect(screen.queryByRole("button", { name: "Add item" })).toBeNull();
    fireEvent.focus(checks);
    fireEvent.mouseDown(screen.getByRole("option", { name: "storage_1" }));
    expect(onChange).toHaveBeenCalledWith({
      provider: "gcp",
      checks: ["iam_1", "storage_1"],
    });

    fireEvent.click(screen.getByRole("button", { name: "Exclude" }));
    expect(screen.getByRole("combobox", { name: "Excluded checks" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Add item" })).toBeNull();
  });
});
