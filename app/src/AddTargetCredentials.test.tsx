// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AddTargetDialog } from "./AddTargetDialog";
import * as api from "./api";
import type { Engine, Profile, Target } from "./types";

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
        credentialSchema: {
          type: "object",
          title: "Cloudflare credentials",
          properties: {
            envVars: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  name: { type: "string", const: "CLOUDFLARE_API_TOKEN" },
                },
              },
            },
          },
        },
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

const created: Target = {
  $schema: "../target.schema.json",
  version: 2,
  id: "cloudflare-production",
  kind: "provider-context",
  provider: "cloudflare",
  credentialMode: "configured",
  arguments: {},
  class: "prod",
  profiles: ["scan:prowler:cloudflare"],
  tags: [],
};

vi.mock("./api", () => ({
  addTarget: vi.fn(),
  fetchEngines: vi.fn(),
  fetchProfiles: vi.fn(),
}));

describe("adding a provider credential", () => {
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("creates a configured Cloudflare context with an API token EnvVar", async () => {
    vi.mocked(api.fetchEngines).mockResolvedValue([engine]);
    vi.mocked(api.fetchProfiles).mockResolvedValue([profile]);
    vi.mocked(api.addTarget).mockResolvedValue(created);
    render(
      <AddTargetDialog
        open
        onClose={vi.fn()}
        onCreated={vi.fn()}
        tagVocabulary={[]}
      />,
    );

    fireEvent.click(screen.getByRole("radio", { name: /Provider context/ }));
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    fireEvent.change(screen.getByRole("textbox", { name: /^Id / }), {
      target: { value: "cloudflare-production" },
    });
    await waitFor(() =>
      expect(screen.getByRole("combobox", { name: "Provider" })).toHaveValue(""),
    );
    fireEvent.change(screen.getByRole("combobox", { name: "Provider" }), {
      target: { value: "cloudflare" },
    });
    fireEvent.click(screen.getByRole("radio", { name: "Configured" }));
    fireEvent.click(screen.getByRole("button", { name: "Next" }));

    fireEvent.change(
      await screen.findByRole("textbox", { name: "Static value" }),
      { target: { value: "cloudflare-token" } },
    );
    fireEvent.click(screen.getByRole("checkbox", { name: /cloudflare/ }));
    fireEvent.click(screen.getByRole("button", { name: "Add target" }));

    await waitFor(() =>
      expect(api.addTarget).toHaveBeenCalledWith(
        expect.objectContaining({
          id: "cloudflare-production",
          provider: "cloudflare",
          credentialMode: "configured",
          credentials: {
            envVars: [
              { name: "CLOUDFLARE_API_TOKEN", value: "cloudflare-token" },
            ],
          },
        }),
      ),
    );
  });
});
