// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { TargetView } from "./TargetView";
import * as api from "./api";
import type { Engine, Profile, Target, TargetCredentials } from "./types";

const credentials: TargetCredentials = {
  envVars: [{ name: "CLOUDFLARE_API_TOKEN", configured: true as const }],
};

const target: Target = {
  $schema: "../target.schema.json",
  version: 2,
  id: "cloudflare-production",
  kind: "provider-context",
  provider: "cloudflare",
  credentialMode: "configured",
  arguments: { "account-ids": ["account-a"] },
  credentials,
  class: "prod",
  profiles: ["scan:prowler:cloudflare"],
  tags: ["cloud"],
};

const targetSchema = {
  type: "object" as const,
  properties: {
    id: { type: "string" as const, readOnly: true },
    kind: { type: "string" as const, readOnly: true },
    provider: { type: "string" as const, readOnly: true },
    credentialMode: {
      type: "string" as const,
      enum: ["ambient", "configured"],
    },
    arguments: { type: "object" as const },
    credentials: { type: "object" as const, readOnly: true },
    class: { type: "string" as const, enum: ["prod", "non-prod"] },
    profiles: { type: "array" as const, items: { type: "string" as const } },
    tags: { type: "array" as const, items: { type: "string" as const } },
  },
};

const credentialSchema = {
  type: "object",
  title: "Cloudflare credentials",
  properties: {
    envVars: {
      type: "array",
      minItems: 1,
      maxItems: 1,
      items: {
        type: "object",
        properties: {
          name: { type: "string", const: "CLOUDFLARE_API_TOKEN" },
          value: { type: "string", writeOnly: true },
          valueFrom: { type: "object" },
          configured: { type: "boolean", const: true, readOnly: true },
        },
      },
    },
  },
};

const engine: Engine = {
  name: "prowler",
  kind: "scan",
  title: "Prowler",
  binary: "prowler",
  subject: "provider-contexts",
  installed: true,
  managed: false,
  options: {
    discriminator: "provider",
    variants: [
      {
        id: "cloudflare",
        title: "Cloudflare",
        schema: { type: "object" },
        contextSchema: {
          type: "object",
          properties: {
            "account-ids": {
              type: "array",
              title: "Account IDs",
              items: { type: "string" },
              "x-section": "scope",
            },
          },
          "x-order": ["account-ids"],
          "x-sections": [{ id: "scope", title: "Scope" }],
        },
        credentialSchema,
      },
    ],
  },
};

const profile: Profile = {
  kind: "scan",
  engine: "prowler",
  name: "cloudflare",
  config: { provider: "cloudflare" },
};

vi.mock("./api", () => ({
  fetchTarget: vi.fn(),
  fetchTargetSchema: vi.fn(),
  saveTarget: vi.fn(),
  fetchProfiles: vi.fn(),
  fetchEngines: vi.fn(),
  fetchScanStatus: vi.fn(),
  startScan: vi.fn(),
  runDiscovery: vi.fn(),
  saveProfile: vi.fn(),
  cancelScan: vi.fn(),
}));

function mockApi() {
  vi.mocked(api.fetchTarget).mockResolvedValue(target);
  vi.mocked(api.fetchTargetSchema).mockResolvedValue(targetSchema);
  vi.mocked(api.fetchProfiles).mockResolvedValue([profile]);
  vi.mocked(api.fetchEngines).mockResolvedValue([engine]);
  vi.mocked(api.fetchScanStatus).mockResolvedValue({ phase: "idle" } as never);
  vi.mocked(api.saveTarget).mockImplementation(async (_id, update) => {
    const updatedCredentials = update.credentials ?? credentials;
    return {
      ...target,
      ...update,
      credentials:
        update.credentials === null
          ? undefined
          : updatedCredentials.envVars?.[0]?.value !== undefined
            ? {
                envVars: [
                  {
                    name: updatedCredentials.envVars[0].name,
                    configured: true as const,
                  },
                ],
              }
            : updatedCredentials,
    };
  });
}

describe("provider target credentials", () => {
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("preserves, replaces without redisplay, and explicitly clears a redacted token", async () => {
    mockApi();
    render(<TargetView id={target.id} onBack={vi.fn()} />);

    fireEvent.click(await screen.findByRole("button", { name: "Edit target" }));
    expect(await screen.findByText(/configured value is hidden/i)).toBeInTheDocument();

    const accountIDs = screen.getByRole("combobox", { name: "Account IDs" });
    fireEvent.change(accountIDs, { target: { value: "account-b" } });
    fireEvent.keyDown(accountIDs, { key: "Enter" });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => expect(api.saveTarget).toHaveBeenCalledTimes(1));
    expect(vi.mocked(api.saveTarget).mock.calls[0][1]).not.toHaveProperty(
      "credentials",
    );

    fireEvent.click(await screen.findByRole("button", { name: "Edit target" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Static value" }), {
      target: { value: "replacement-token" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => expect(api.saveTarget).toHaveBeenCalledTimes(2));
    expect(vi.mocked(api.saveTarget).mock.calls[1]).toEqual([
      target.id,
      expect.objectContaining({
        credentials: {
          envVars: [
            { name: "CLOUDFLARE_API_TOKEN", value: "replacement-token" },
          ],
        },
      }),
    ]);

    fireEvent.click(await screen.findByRole("button", { name: "Edit target" }));
    expect(screen.getByRole("textbox", { name: "Static value" })).toHaveValue("");
    fireEvent.click(screen.getByRole("button", { name: "Clear credential" }));
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => expect(api.saveTarget).toHaveBeenCalledTimes(3));
    expect(vi.mocked(api.saveTarget).mock.calls[2]).toEqual([
      target.id,
      expect.objectContaining({ credentials: null }),
    ]);
  });
});
