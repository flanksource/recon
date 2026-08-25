// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { JsonSchemaObject } from "@flanksource/clicky-ui/components";
import { EngineConfigForm } from "./EngineConfigForm";
import { applySelection, sectionMutexGroups, valueIsActive } from "./MutualExclusions";
import type { Engine } from "./types";

const describe_ = (message: string) => `Prowler configuration schema ${message}`;

const groupsOf = (
  root: JsonSchemaObject,
  sectionKeys: string[],
  sectionTitle = "Outputs",
) => sectionMutexGroups({ root, sectionTitle, sectionKeys, describe: describe_ });

const selectionSchema: JsonSchemaObject = {
  type: "object",
  additionalProperties: false,
  "x-sections": [
    { id: "selection", title: "Specify checks/services to run" },
    { id: "outputs", title: "Outputs" },
  ],
  "x-order": ["provider", "checks", "services", "severities", "verbose"],
  "x-mutual-exclusions": [
    {
      id: "common-mutex-1",
      title: "Specify checks/services to run",
      keys: ["checks", "services"],
    },
  ],
  properties: {
    provider: { type: "string", const: "github", "x-section": "selection" },
    checks: {
      type: "array",
      title: "Checks",
      "x-section": "selection",
      items: { type: "string", enum: ["repository_secret_scanning_enabled"] },
    },
    services: {
      type: "array",
      title: "Services",
      "x-section": "selection",
      items: { type: "string", enum: ["organization", "repository"] },
    },
    severities: {
      type: "array",
      title: "Severities",
      "x-section": "selection",
      items: { type: "string", enum: ["high", "critical"] },
    },
    verbose: { type: "boolean", title: "Verbose", "x-section": "outputs" },
  },
};

const authSchema: JsonSchemaObject = {
  type: "object",
  additionalProperties: false,
  "x-sections": [{ id: "auth", title: "Authentication Modes" }],
  "x-order": ["az-cli-auth", "sp-env-auth"],
  "x-mutual-exclusions": [
    {
      id: "azure-mutex-1",
      title: "Authentication Modes",
      keys: ["az-cli-auth", "sp-env-auth"],
    },
  ],
  properties: {
    "az-cli-auth": {
      type: "boolean",
      title: "Az Cli Auth",
      "x-section": "auth",
      "x-credential-selector": true,
    },
    "sp-env-auth": {
      type: "boolean",
      title: "Sp Env Auth",
      "x-section": "auth",
      "x-credential-selector": true,
    },
  },
};

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
        id: "github",
        title: "GitHub",
        schema: selectionSchema,
        contextSchema: authSchema,
      },
    ],
  },
};

const scopeGroup = () => groupsOf(selectionSchema, ["checks", "services", "severities"])[0];

afterEach(cleanup);

describe("sectionMutexGroups", () => {
  it("claims a group for the section holding every one of its keys", () => {
    const groups = groupsOf(selectionSchema, ["provider", "checks", "services", "severities"]);

    expect(groups).toEqual([
      {
        id: "common-mutex-1",
        title: "Specify checks/services to run",
        label: "Specify checks/services to run",
        members: [
          { key: "checks", label: "Checks" },
          { key: "services", label: "Services" },
        ],
        flag: false,
        credentialSelector: false,
      },
    ]);
  });

  // argparse names a group after the section it was declared in, so a section
  // holding one group would otherwise print the same sentence twice.
  it("drops the row label when the section heading already asks the question", () => {
    const [group] = groupsOf(
      selectionSchema,
      ["checks", "services"],
      "Specify checks/services to run",
    );

    expect(group.title).toBe("Specify checks/services to run");
    expect(group.label).toBe("");
  });

  it("leaves a group to the section that owns it", () => {
    expect(groupsOf(selectionSchema, ["verbose"])).toEqual([]);
  });

  it("reads store_true members as flags and credential selectors as such", () => {
    const [group] = groupsOf(authSchema, ["az-cli-auth", "sp-env-auth"]);

    expect(group.flag).toBe(true);
    expect(group.credentialSelector).toBe(true);
  });

  // A control governing fields the reader cannot see would be a question with
  // half its answers off-screen.
  it("refuses a group split across two sections", () => {
    expect(() => groupsOf(selectionSchema, ["checks", "verbose"])).toThrow(
      /spans more than one section/,
    );
  });

  it("refuses a group naming a property the schema does not declare", () => {
    const schema = {
      ...selectionSchema,
      "x-mutual-exclusions": [{ id: "broken", keys: ["checks", "absent"] }],
    } as JsonSchemaObject;

    expect(() => groupsOf(schema, ["checks", "absent"])).toThrow(
      /references unknown property "absent"/,
    );
  });
});

describe("applySelection", () => {
  it("removes the members it is not selecting rather than emptying them", () => {
    const next = applySelection(
      { provider: "github", checks: ["one"], services: ["repository"], severities: ["high"] },
      scopeGroup(),
      "services",
    );

    expect(next).toEqual({ provider: "github", severities: ["high"] });
  });

  it("clears every member when nothing is selected", () => {
    const next = applySelection({ provider: "github", checks: ["one"] }, scopeGroup(), "__none");

    expect(next).toEqual({ provider: "github" });
  });

  it("writes the flag itself when the segment is the whole answer", () => {
    const [group] = groupsOf(authSchema, ["az-cli-auth", "sp-env-auth"]);

    expect(applySelection({ "sp-env-auth": true }, group, "az-cli-auth")).toEqual({
      "az-cli-auth": true,
    });
  });
});

describe("valueIsActive", () => {
  it("counts a selection the way the engine counts it", () => {
    expect([undefined, null, [], false, "", 0, ["one"], true].map(valueIsActive)).toEqual([
      false,
      false,
      false,
      false,
      true,
      true,
      true,
      true,
    ]);
  });
});

describe("EngineConfigForm with mutually exclusive groups", () => {
  it("offers the group as one choice and leaves ungrouped fields alone", () => {
    render(
      <EngineConfigForm
        engine={prowler}
        identity="scan:prowler:default"
        value={{ provider: "github" }}
        onChange={vi.fn()}
      />,
    );

    expect(
      screen.getByRole("radiogroup", { name: "Specify checks/services to run" }),
    ).toBeTruthy();
    expect(screen.getByRole("radio", { name: "Everything" }).getAttribute("aria-checked")).toBe(
      "true",
    );
    expect(screen.getByRole("radio", { name: "Checks" })).toBeTruthy();
    expect(screen.getByText("Severities")).toBeTruthy();
    // The row asks the group's question, so it never carries a member's title —
    // and here the section heading already asks it, so it carries no label at
    // all rather than printing the same sentence twice.
    expect(screen.queryByText("Checks", { selector: "label *" })).toBeNull();
    expect(
      screen
        .getAllByText("Specify checks/services to run")
        .every((node) => node.closest("label") === null),
    ).toBe(true);
  });

  it("marks the member the config actually sets", () => {
    render(
      <EngineConfigForm
        engine={prowler}
        identity="scan:prowler:default"
        value={{ provider: "github", services: ["repository"] }}
        onChange={vi.fn()}
      />,
    );

    expect(screen.getByRole("radio", { name: "Services" }).getAttribute("aria-checked")).toBe(
      "true",
    );
    expect(screen.getByRole("radio", { name: "Everything" }).getAttribute("aria-checked")).toBe(
      "false",
    );
  });

  it("drops the other members when a segment is chosen", () => {
    const onChange = vi.fn();
    render(
      <EngineConfigForm
        engine={prowler}
        identity="scan:prowler:default"
        value={{ provider: "github", checks: ["repository_secret_scanning_enabled"] }}
        onChange={onChange}
      />,
    );

    fireEvent.click(screen.getByRole("radio", { name: "Services" }));

    expect(onChange).toHaveBeenCalledWith({ provider: "github" });
  });

  // The config that produced the engine error already sets two members. Hiding
  // one behind a segment would hide the value that breaks the scan.
  it("shows every member of a conflicting group and says so", () => {
    render(
      <EngineConfigForm
        engine={prowler}
        identity="scan:prowler:default"
        value={{
          provider: "github",
          checks: ["repository_secret_scanning_enabled"],
          services: ["repository"],
        }}
        onChange={vi.fn()}
      />,
    );

    expect(screen.queryByRole("radiogroup")).toBeNull();
    expect(screen.getByText("Checks")).toBeTruthy();
    expect(screen.getByText("Services")).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toContain(
      "accepts only one of checks, services",
    );
  });

  it("writes the flag directly for a store_true auth group", () => {
    const onChange = vi.fn();
    render(
      <EngineConfigForm
        engine={prowler}
        identity="target:github"
        schemaKind="context"
        variantId="github"
        value={{}}
        onChange={onChange}
      />,
    );

    expect(screen.getByRole("radio", { name: "Credentials" }).getAttribute("aria-checked")).toBe(
      "true",
    );
    fireEvent.click(screen.getByRole("radio", { name: "Sp Env Auth" }));

    expect(onChange).toHaveBeenCalledWith({ "sp-env-auth": true });
  });
});
