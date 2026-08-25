// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FindingsView } from "./FindingsView";
import { fetchFindingGroups, fetchFindingStates, syncFindings } from "./api-insights";
import { fetchFilterOptions, fetchFilters } from "./api";
import type { FindingGroup, FindingState } from "./types";

vi.mock("./api-insights", () => ({
  fetchFindingGroups: vi.fn(),
  fetchFindingStates: vi.fn(),
  syncFindings: vi.fn(),
}));
vi.mock("./api", () => ({
  fetchFilters: vi.fn(() => Promise.resolve([])),
  fetchFilterOptions: vi.fn(() => Promise.resolve([])),
}));

const fetchFindingGroupsMock = vi.mocked(fetchFindingGroups);
const fetchFindingStatesMock = vi.mocked(fetchFindingStates);

function group(overrides: Partial<FindingGroup> = {}): FindingGroup {
  return {
    engine: "prowler",
    checkId: "cloudstorage_bucket_public_access",
    name: "Cloud Storage bucket is not publicly accessible",
    severity: "critical",
    affected: 2,
    statuses: { open: 2 },
    lastSeen: "2026-08-24T12:00:00Z",
    ...overrides,
  };
}

function state(): FindingState {
  return {
    id: "01JSTATE",
    resourceId: "01JRESOURCE",
    engine: "prowler",
    checkId: "cloudstorage_bucket_public_access",
    status: "open",
    severity: "critical",
    firstSeen: "2026-08-23T12:00:00Z",
    lastSeen: "2026-08-24T12:00:00Z",
    occurrences: 2,
    findingId: "01JFINDING",
    resource: {
      id: "01JRESOURCE",
      provider: "gcp",
      scope: "acme-platform",
      uid: "1429543158501771126",
      name: "audit-logs",
      type: "storage.googleapis.com/Bucket",
      service: "cloudstorage",
      region: "europe-west1",
      findings: 1,
    },
    finding: {
      id: "01JFINDING",
      scanId: "01JSCAN",
      lineNo: 7,
      targetId: "gcp-prod",
      templateId: "cloudstorage_bucket_public_access",
      name: "Cloud Storage bucket is not publicly accessible",
      severity: "critical",
      host: "acme-platform",
      matchedAt: "1429543158501771126",
      tags: [],
      resources: [{
        id: "01JRESOURCE",
        provider: "gcp",
        scope: "acme-platform",
        uid: "1429543158501771126",
        name: "audit-logs",
      }],
    },
  };
}

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

describe("FindingsView", () => {
  beforeEach(() => {
    stubMatchMedia();
    vi.mocked(fetchFilters).mockResolvedValue([]);
    vi.mocked(fetchFilterOptions).mockResolvedValue([]);
    fetchFindingGroupsMock.mockResolvedValue({
      data: [group()],
      page: { limit: 100, offset: 0, total: 620 },
    });
    fetchFindingStatesMock.mockResolvedValue({
      data: [state()],
      page: { limit: 100, offset: 0, total: 1 },
    });
    vi.mocked(syncFindings).mockResolvedValue({
      agent: "recon", matchedResources: 1, matchedStates: 1, eligible: 1, skipped: 0,
      open: 1, resolved: 0, silenced: 0, direct: 1, rolledUp: 0, pushed: 0,
      configs: [], unresolved: [],
    });
  });
  afterEach(cleanup);

  it("asks the server for grouped open and manual current states", async () => {
    render(<FindingsView />);

    await waitFor(() => expect(fetchFindingGroupsMock).toHaveBeenCalled());
    expect(fetchFindingGroupsMock.mock.calls[0]?.[0]).toMatchObject({
      limit: 100,
      offset: 0,
      sort: "severity",
      order: "asc",
      status: "open",
    });
  });

  it("expands a check into its affected resources", async () => {
    render(<FindingsView />);

    const check = await screen.findByText("Cloud Storage bucket is not publicly accessible");
    const checkID = screen.getByText("cloudstorage_bucket_public_access");
    expect(check.parentElement).toContainElement(checkID);

    fireEvent.click(check.closest("tr")!);
    expect(await screen.findByText("audit-logs")).toBeInTheDocument();
    expect(fetchFindingStatesMock).toHaveBeenCalledWith(expect.objectContaining({
      engine: "prowler",
      check: "cloudstorage_bucket_public_access",
      status: "open",
    }));
    expect(screen.getByRole("link", { name: "View finding" })).toHaveAttribute(
      "href",
      "/findings/01JFINDING",
    );
    expect(screen.getByRole("img", { name: "open" })).toBeInTheDocument();
  });

  it("does not link a state without persisted finding evidence", async () => {
    fetchFindingStatesMock.mockResolvedValue({
      data: [{ ...state(), findingId: undefined, finding: undefined }],
      page: { limit: 100, offset: 0, total: 1 },
    });
    render(<FindingsView />);

    fireEvent.click((await screen.findByText("Cloud Storage bucket is not publicly accessible")).closest("tr")!);
    expect(await screen.findByText("Finding unavailable")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "View finding" })).not.toBeInTheDocument();
  });

  it("adds resolved and muted states only when their toggles are selected", async () => {
    render(<FindingsView />);
    await waitFor(() => expect(fetchFindingGroupsMock).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: "Resolved" }));
    await waitFor(() => expect(fetchFindingGroupsMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ status: "open,resolved" }),
    ));

    fireEvent.click(screen.getByRole("button", { name: "Muted" }));
    await waitFor(() => expect(fetchFindingGroupsMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ status: "open,resolved,muted" }),
    ));
  });
});
