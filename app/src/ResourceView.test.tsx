// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ResourceView } from "./ResourceView";
import {
  fetchResource,
  fetchResourceConfig,
  fetchResourceFindings,
  removeResourceConfig,
} from "./api-resources";
import type { Resource } from "./api-resources";
import type { Finding } from "./types";

vi.mock("./api-resources", () => ({
  fetchResource: vi.fn(),
  fetchResourceConfig: vi.fn(),
  fetchResourceFindings: vi.fn(),
  removeResourceConfig: vi.fn(),
}));

const fetchResourceMock = vi.mocked(fetchResource);
const fetchResourceConfigMock = vi.mocked(fetchResourceConfig);
const fetchFindingsMock = vi.mocked(fetchResourceFindings);
const removeResourceConfigMock = vi.mocked(removeResourceConfig);

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
  beforeEach(() => {
    stubMatchMedia();
    fetchResourceConfigMock.mockResolvedValue(null);
  });
  afterEach(cleanup);

  it("shows the linked Mission Control config name, type, and id", async () => {
    const configId = "fc3e34be-c311-e6e7-7b64-e29cfe90334e";
    fetchResourceMock.mockResolvedValue(resource({ configId }));
    fetchResourceConfigMock.mockResolvedValue({
      id: configId,
      name: "Production GCP",
      type: "GCP::Project",
      url: `https://beta.example.com/catalog/${configId}`,
    });
    fetchFindingsMock.mockResolvedValue([]);

    render(<ResourceView id="01JRESOURCE" onBack={() => {}} />);

    const link = await screen.findByRole("link", { name: "Production GCP" });
    expect(link).toHaveAttribute(
      "href",
      `https://beta.example.com/catalog/${configId}`,
    );
    expect(screen.getByText("GCP::Project")).toBeInTheDocument();
    expect(screen.getByText(configId)).toBeInTheDocument();
    expect(screen.queryByText("External IDs")).not.toBeInTheDocument();
  });

  it("removes the stored config link after confirmation", async () => {
    const configId = "fc3e34be-c311-e6e7-7b64-e29cfe90334e";
    fetchResourceMock.mockResolvedValue(resource({ configId }));
    fetchResourceConfigMock.mockResolvedValue({
      id: configId,
      name: "Production GCP",
      type: "GCP::Project",
      url: `https://beta.example.com/catalog/${configId}`,
    });
    fetchFindingsMock.mockResolvedValue([]);
    removeResourceConfigMock.mockResolvedValue(undefined);
    vi.spyOn(window, "confirm").mockReturnValue(true);

    render(<ResourceView id="01JRESOURCE" onBack={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: "Remove link" }));

    await waitFor(() => expect(removeResourceConfigMock).toHaveBeenCalledWith("01JRESOURCE"));
    expect(screen.queryByRole("link", { name: "Production GCP" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remove link" })).not.toBeInTheDocument();
  });

  it("does not render the compliance summary", async () => {
    fetchResourceMock.mockResolvedValue(
      resource({ findings: 1, severities: { high: 1 } }),
    );
    fetchFindingsMock.mockResolvedValue([
      finding({ tags: ["compliance:CIS-5.0:1.13"] }),
    ]);

    render(<ResourceView id="01JRESOURCE" onBack={() => {}} />);

    await waitFor(() => expect(screen.getByText("Identity")).toBeInTheDocument());
    expect(screen.queryByText("Compliance")).not.toBeInTheDocument();
    expect(screen.queryByText("CIS-5.0")).not.toBeInTheDocument();
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
