// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ResourceView, frameworkRollup } from "./ResourceView";
import { fetchResource, fetchResourceFindings } from "./api-resources";
import type { Resource } from "./api-resources";
import type { Finding } from "./types";

vi.mock("./api-resources", () => ({
  fetchResource: vi.fn(),
  fetchResourceFindings: vi.fn(),
}));

const fetchResourceMock = vi.mocked(fetchResource);
const fetchFindingsMock = vi.mocked(fetchResourceFindings);

function stubMatchMedia() {
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    value: vi.fn().mockReturnValue({
      matches: false,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    }),
  });
}

function resource(overrides: Partial<Resource> = {}): Resource {
  return {
    id: "01JRESOURCE",
    provider: "gcp",
    scope: "flanksource-prod",
    uid: "logs",
    kind: "cloud-resource",
    type: "storage.googleapis.com/Bucket",
    name: "logs",
    service: "storage",
    region: "eu",
    state: "present",
    configType: "GCP::Bucket",
    externalIds: ["logs"],
    findings: 0,
    ...overrides,
  };
}

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    scanId: "scan-1",
    lineNo: 1,
    templateId: "gcp/bucket_public_access",
    name: "Bucket is publicly accessible",
    severity: "high",
    host: "flanksource-prod",
    matchedAt: "logs",
    tags: [],
    ...overrides,
  } as Finding;
}

describe("ResourceView", () => {
  beforeEach(() => stubMatchMedia());
  afterEach(cleanup);

  it("shows the config-db identity a Mission Control lookup would use", async () => {
    fetchResourceMock.mockResolvedValue(resource());
    fetchFindingsMock.mockResolvedValue([]);

    render(<ResourceView id="01JRESOURCE" onBack={() => {}} />);

    await waitFor(() => expect(screen.getByText("GCP::Bucket")).toBeInTheDocument());
  });

  // The payoff of recording passes: a resource with no findings is a statement,
  // not an absence of one.
  it("says nothing is open rather than showing an empty table", async () => {
    fetchResourceMock.mockResolvedValue(resource());
    fetchFindingsMock.mockResolvedValue([]);

    render(<ResourceView id="01JRESOURCE" onBack={() => {}} />);

    await waitFor(() =>
      expect(
        screen.getByText("Nothing is currently open against this resource."),
      ).toBeInTheDocument(),
    );
  });

  it("lists the checks that are failing", async () => {
    fetchResourceMock.mockResolvedValue(
      resource({ findings: 1, severities: { high: 1 } }),
    );
    fetchFindingsMock.mockResolvedValue([finding()]);

    render(<ResourceView id="01JRESOURCE" onBack={() => {}} />);

    await waitFor(() =>
      expect(screen.getByText("gcp/bucket_public_access")).toBeInTheDocument(),
    );
    expect(screen.getByText("Bucket is publicly accessible")).toBeInTheDocument();
  });

  it("reports a lookup failure instead of an empty resource", async () => {
    fetchResourceMock.mockRejectedValue(new Error("resource not found"));
    fetchFindingsMock.mockResolvedValue([]);

    render(<ResourceView id="nope" onBack={() => {}} />);

    await waitFor(() => expect(screen.getByText("resource not found")).toBeInTheDocument());
  });
});

// Read from the tags the checks already carry rather than from a framework
// catalogue recon would have to maintain: a roll-up derived from anything else
// would disagree with the findings printed underneath it.
describe("frameworkRollup", () => {
  it("counts failing controls per framework", () => {
    const rollup = frameworkRollup([
      finding({ tags: ["compliance:CIS-5.0:1.13", "storage"] }),
      finding({ tags: ["compliance:CIS-5.0:2.1"] }),
      finding({ tags: ["compliance:PCI-4.0:3.2"] }),
    ]);

    expect(rollup).toEqual([
      ["CIS-5.0", 2],
      ["PCI-4.0", 1],
    ]);
  });

  // One finding tagged with three sections of one benchmark is one failing
  // control, not three — otherwise the roll-up exceeds the number of findings
  // it is summarising and reads as a worse posture than the data shows.
  it("counts a finding once per framework however many sections it cites", () => {
    expect(
      frameworkRollup([
        finding({
          tags: ["compliance:CIS-5.0:1.13", "compliance:CIS-5.0:2.1", "compliance:CIS-5.0:5.3"],
        }),
      ]),
    ).toEqual([["CIS-5.0", 1]]);
  });

  it("ignores findings that cite no framework", () => {
    expect(frameworkRollup([finding({ tags: ["storage", "gcp"] })])).toEqual([]);
  });
});
