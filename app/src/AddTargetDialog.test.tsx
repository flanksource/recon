import { describe, expect, it } from "vitest";
import { offeredProfiles, providerOptions } from "./AddTargetDialog";
import type { Engine, Profile } from "./types";

function engine(overrides: Partial<Engine> = {}): Engine {
  return {
    name: "nuclei",
    kind: "scan",
    title: "Nuclei",
    binary: "nuclei",
    installed: true,
    managed: true,
    options: { variants: [] },
    ...overrides,
  } as Engine;
}

// Audits a cloud account and declares no providers. It is the reason the host
// filter reads `subject` rather than inferring from the provider discriminator.
const inspec = engine({ name: "inspec", title: "InSpec", subject: "accounts" });

const prowler = engine({
  name: "prowler",
  title: "Prowler",
  subject: "provider-contexts",
  options: {
    discriminator: "provider",
    variants: [
      { id: "gcp", title: "Google Cloud", schema: {}, contextSchema: { type: "object" } },
      { id: "aws", title: "AWS", schema: {}, contextSchema: { type: "object" } },
      // No context schema: nothing can be scoped to it, so it must not be
      // offered as somewhere a target could live.
      { id: "iac", title: "IaC", schema: {} },
    ],
  },
});

function profile(engineName: string, name: string, provider?: string): Profile {
  return {
    kind: "scan",
    engine: engineName,
    name,
    config: provider ? { provider } : {},
  };
}

describe("the provider picker", () => {
  it("offers every provider a scan engine can scope a target to", () => {
    expect(providerOptions([engine(), prowler])).toEqual([
      { value: "aws", label: "AWS" },
      { value: "gcp", label: "Google Cloud" },
    ]);
  });

  it("leaves out a variant with no context schema", () => {
    // A variant recon cannot describe a scope for is one no target can name,
    // and offering it would produce a target the server then refuses.
    expect(providerOptions([prowler]).map((option) => option.value)).not.toContain("iac");
  });

  it("offers nothing when no engine declares providers", () => {
    expect(providerOptions([engine()])).toEqual([]);
  });
});

describe("the profiles a new target is offered", () => {
  const catalogue = [
    profile("nuclei", "safe"),
    profile("nuclei", "full"),
    profile("inspec", "gcp-cis"),
    profile("prowler", "gcp-cis-5-0-gcp", "gcp"),
    profile("prowler", "aws-cis-4-0-aws", "aws"),
  ];
  const installed = [engine(), inspec, prowler];

  it("gives a host only the engines whose subject is an address", () => {
    // Both of the others reach an account through an API and have nothing to do
    // with a hostname, so neither may appear against one.
    expect(offeredProfiles(catalogue, installed, "host", "").map((p) => p.name)).toEqual(
      ["safe", "full"],
    );
  });

  it("keeps an account-auditing engine away from a host even with no providers", () => {
    // The regression this reads for: inspec declares no provider variants, so a
    // filter that inferred "scans hosts" from that offered its GCP compliance
    // profile against a hostname.
    expect(
      offeredProfiles(catalogue, installed, "host", "").map((p) => p.engine),
    ).not.toContain("inspec");
  });

  it("gives a provider context only the profiles written for its provider", () => {
    // Prowler ships well over a hundred profiles across every provider it
    // supports; offering all of them would bury the handful that apply.
    expect(
      offeredProfiles(catalogue, installed, "provider-context", "gcp").map((p) => p.name),
    ).toEqual(["gcp-cis-5-0-gcp"]);
  });

  it("offers nothing until a provider is chosen", () => {
    expect(offeredProfiles(catalogue, installed, "provider-context", "")).toEqual([]);
  });
});
