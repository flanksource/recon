// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FindingGroupView } from "./FindingGroupView";
import { fetchFindingGroups, fetchFindingStates } from "./api-insights";
import type { FindingGroup, FindingState } from "./types";

vi.mock("./api-insights", () => ({
  fetchFindingGroups: vi.fn(),
  fetchFindingStates: vi.fn(),
}));

const fetchFindingGroupsMock = vi.mocked(fetchFindingGroups);
const fetchFindingStatesMock = vi.mocked(fetchFindingStates);

const ENGINE = "prowler";
const CHECK_ID = "gcp/bigquery_dataset_cmk_encryption";
const CHECK_NAME = "BigQuery dataset is encrypted with Customer-Managed Keys";

function group(overrides: Partial<FindingGroup> = {}): FindingGroup {
  return {
    engine: ENGINE,
    checkId: CHECK_ID,
    name: CHECK_NAME,
    severity: "high",
    affected: 2,
    statuses: { open: 2 },
    lastSeen: "2026-08-24T12:00:00Z",
    ...overrides,
  };
}

function state(overrides: Partial<FindingState> = {}): FindingState {
  return {
    id: "01JSTATE",
    resourceId: "01JRESOURCE",
    engine: ENGINE,
    checkId: CHECK_ID,
    status: "open",
    severity: "high",
    firstSeen: "2026-08-23T12:00:00Z",
    lastSeen: "2026-08-24T12:00:00Z",
    occurrences: 2,
    findingId: "01JFINDING",
    resource: {
      id: "01JRESOURCE",
      provider: "gcp",
      scope: "workload-prod-eu-02",
      uid: "workload-prod-eu-02:default",
      name: "default",
      type: "bigquery.googleapis.com/Dataset",
      service: "bigquery",
      region: "US",
      findings: 1,
    },
    finding: {
      id: "01JFINDING",
      scanId: "01JSCAN",
      lineNo: 2,
      targetId: "gcp-prod",
      checkId: CHECK_ID,
      host: "workload-prod-eu-02",
      matchedAt: "workload-prod-eu-02:default",
      tags: [],
    },
    ...overrides,
  };
}

function statePage(data: FindingState[], total = data.length) {
  return { data, page: { limit: 100, offset: 0, total } };
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

function renderView() {
  return render(
    <FindingGroupView engine={ENGINE} checkId={CHECK_ID} onBack={vi.fn()} onMuteCheck={vi.fn()} />,
  );
}

describe("FindingGroupView", () => {
  beforeEach(() => {
    stubMatchMedia();
    fetchFindingGroupsMock.mockResolvedValue({
      data: [group()],
      page: { limit: 1, offset: 0, total: 1 },
    });
    fetchFindingStatesMock.mockResolvedValue(statePage([state()]));
  });
  afterEach(cleanup);

  it("reads the header from the one group the engine and check name", async () => {
    renderView();

    await waitFor(() => expect(fetchFindingGroupsMock).toHaveBeenCalled());
    expect(fetchFindingGroupsMock).toHaveBeenCalledWith({
      engine: ENGINE,
      check: CHECK_ID,
      status: "open",
      limit: 1,
    });
    expect(await screen.findByRole("heading", { name: CHECK_NAME })).toBeInTheDocument();
  });

  it("summarises the check's reach beside its identity", async () => {
    renderView();

    // How much of the estate this check affects is the question the page
    // exists to answer, so it belongs in the header rather than only in the
    // table's row count.
    const terms = await screen.findAllByRole("term");
    // Severity is deliberately absent: its badge sits inches away in the page
    // heading, and repeating it here says nothing the reader has not just read.
    expect(terms.map((term) => term.textContent)).toEqual([
      "Engine", "Check ID", "Affected resources", "States", "Last seen",
    ]);
    expect(screen.getByText("2 open")).toBeInTheDocument();
  });

  it("shows the loading skeleton rather than the empty message while states are in flight", async () => {
    let release: (page: ReturnType<typeof statePage>) => void = () => {};
    fetchFindingStatesMock.mockReturnValue(
      new Promise((resolve) => { release = resolve; }),
    );
    renderView();

    // The defect this guards: with no `loading` passed, an unresolved fetch
    // renders `data=[]` and the table claims there is nothing to show.
    await waitFor(() => expect(screen.getByText("Loading results…")).toBeInTheDocument());
    expect(
      screen.queryByText("This check has no affected resources in the selected states."),
    ).not.toBeInTheDocument();

    release(statePage([state()]));
    expect(await screen.findByText("default")).toBeInTheDocument();
  });

  it("links an affected resource to the evidence a run recorded", async () => {
    renderView();

    const link = await screen.findByRole("link", { name: /default/ });
    expect(link).toHaveAttribute("href", "/findings/01JFINDING");
  });

  it("links to the resource when no evidence was persisted, and says so", async () => {
    fetchFindingStatesMock.mockResolvedValue(
      statePage([state({ findingId: undefined, finding: undefined })]),
    );
    renderView();

    const link = await screen.findByRole("link", { name: /default/ });
    expect(link).toHaveAttribute("href", "/resources/01JRESOURCE");
    expect(screen.getByText("no evidence")).toBeInTheDocument();
  });

  it("hides the status column until a state other than open can appear", async () => {
    renderView();

    await screen.findByText("default");
    expect(screen.queryByRole("columnheader", { name: /Status/ })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Resolved" }));
    expect(await screen.findByRole("columnheader", { name: /Status/ })).toBeInTheDocument();
  });

  it("re-queries both header and states when a status toggle changes", async () => {
    renderView();
    await waitFor(() => expect(fetchFindingStatesMock).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: "Muted" }));
    await waitFor(() => expect(fetchFindingStatesMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ status: "open,muted", engine: ENGINE, check: CHECK_ID }),
    ));
    expect(fetchFindingGroupsMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ status: "open,muted" }),
    );
  });

  it("keeps the page and offers a retry when the query fails", async () => {
    fetchFindingStatesMock.mockRejectedValueOnce(new Error("finding-state query failed"));
    renderView();

    expect(await screen.findByRole("alert")).toHaveTextContent("finding-state query failed");
    expect(screen.getByRole("heading", { name: CHECK_ID })).toBeInTheDocument();

    fetchFindingStatesMock.mockResolvedValue(statePage([state()]));
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("default")).toBeInTheDocument();
  });
});
