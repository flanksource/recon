// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CredentialConfigForm, envVarFromSecretRef, secretRefFromEnvVar } from "./CredentialConfigForm";
import type { EngineOptionSchema, TargetCredentials } from "./types";

const credentialSchema: EngineOptionSchema = {
  type: "object",
  title: "Cloudflare credentials",
  properties: {
    envVars: {
      type: "array",
      minItems: 1,
      maxItems: 1,
      items: {
        type: "object",
        required: ["name"],
        properties: {
          name: {
            type: "string",
            const: "CLOUDFLARE_API_TOKEN",
            readOnly: true,
          },
          value: { type: "string", format: "password", writeOnly: true },
          valueFrom: {
            type: "object",
            properties: {
              secretKeyRef: { type: "object" },
              configMapKeyRef: { type: "object" },
              helmRef: { type: "object" },
              onePassword: { type: "string" },
            },
          },
          configured: { type: "boolean", const: true, readOnly: true },
        },
      },
    },
  },
};

describe("credential EnvVar projection", () => {
  it.each([
    [
      "literal",
      "cloudflare-token",
      { name: "CLOUDFLARE_API_TOKEN", value: "cloudflare-token" },
    ],
    [
      "Secret",
      "secret://prowler/cloudflare-token",
      {
        name: "CLOUDFLARE_API_TOKEN",
        valueFrom: {
          secretKeyRef: { name: "prowler", key: "cloudflare-token" },
        },
      },
    ],
    [
      "ConfigMap",
      "configmap://prowler/cloudflare-token",
      {
        name: "CLOUDFLARE_API_TOKEN",
        valueFrom: {
          configMapKeyRef: { name: "prowler", key: "cloudflare-token" },
        },
      },
    ],
    [
      "Helm",
      "helm://prowler/cloudflare.apiToken",
      {
        name: "CLOUDFLARE_API_TOKEN",
        valueFrom: {
          helmRef: { name: "prowler", key: "cloudflare.apiToken" },
        },
      },
    ],
    [
      "1Password",
      "op://Production/Prowler/API token",
      {
        name: "CLOUDFLARE_API_TOKEN",
        valueFrom: { onePassword: "op://Production/Prowler/API token" },
      },
    ],
  ])("round-trips a %s source", (_label, reference, envVar) => {
    expect(envVarFromSecretRef("CLOUDFLARE_API_TOKEN", reference)).toEqual(envVar);
    expect(secretRefFromEnvVar(envVar)).toBe(reference);
  });

  it("does not reveal configured inline values", () => {
    expect(
      secretRefFromEnvVar({
        name: "CLOUDFLARE_API_TOKEN",
        configured: true,
      }),
    ).toBeUndefined();
  });
});

describe("CredentialConfigForm", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("preserves a redacted inline token until it is changed or explicitly cleared", async () => {
    const onChange = vi.fn();
    render(
      <CredentialConfigForm
        schema={credentialSchema}
        value={{
          envVars: [{ name: "CLOUDFLARE_API_TOKEN", configured: true }],
        }}
        onChange={onChange}
      />,
    );

    expect(screen.getByText(/configured value is hidden/i)).toBeInTheDocument();
    expect(onChange).not.toHaveBeenCalled();
    expect(screen.getByRole("textbox", { name: "Static value" })).toHaveValue("");

    const source = screen.getByRole("combobox", {
      name: "Secret value source",
    });
    fireEvent.focus(source);
    expect(await screen.findByRole("option", { name: "Value" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Secret" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "ConfigMap" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Helm" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "1Password" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "Service Account" })).toBeNull();

    await act(async () => {
      fireEvent.mouseDown(screen.getByRole("option", { name: "Value" }));
    });
    fireEvent.change(screen.getByRole("textbox", { name: "Static value" }), {
      target: { value: "replacement-token" },
    });
    expect(onChange).toHaveBeenLastCalledWith({
      envVars: [
        { name: "CLOUDFLARE_API_TOKEN", value: "replacement-token" },
      ],
    } satisfies TargetCredentials);

    fireEvent.click(screen.getByRole("button", { name: "Clear credential" }));
    expect(onChange).toHaveBeenLastCalledWith(null);
  });
});
