// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ResourcesView } from "./ResourcesView";
import { fetchResources } from "./api-resources";
import { fetchFilterOptions, fetchFilters } from "./api";
import type { Resource, ResourcePage } from "./api-resources";
import { syncResources } from "./api-insights";

vi.mock("./api-resources", () => ({ fetchResources: vi.fn() }));
vi.mock("./api-insights", () => ({ syncResources: vi.fn() }));
vi.mock("./api", () => ({
  fetchFilters: vi.fn(() => Promise.resolve([])),
  fetchFilterOptions: vi.fn(() => Promise.resolve([])),
}));

const fetchResourcesMock = vi.mocked(fetchResources);

function resource(overrides: Partial<Resource> = {}): Resource {
  return {
    id: "01JRESOURCE",
    provider: "gcp",
    scope: "flanksource-prod",
    uid: "1429543158501771126",
    kind: "cloud-resource",
    type: "compute.googleapis.com/Firewall",
    name: "tailscale-router",
    service: "compute",
    region: "global",
    state: "present",
    lastSeen: "2026-08-22T09:00:00",
    findings: 0,
    ...overrides,
  };
}

function page(rows: Resource[], total = rows.length): ResourcePage {
  return { data: rows, page: { limit: 100, offset: 0, total } };
}

// DataTable resolves its theme from the colour-scheme media query, which jsdom
// does not implement.
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

describe("ResourcesView", () => {
  beforeEach(() => {
    stubMatchMedia();
    vi.mocked(fetchFilters).mockResolvedValue([]);
    vi.mocked(fetchFilterOptions).mockResolvedValue([]);
    vi.mocked(syncResources).mockResolvedValue({
      agent: "recon", matchedResources: 1, matchedStates: 1, eligible: 1, skipped: 0,
      open: 1, resolved: 0, silenced: 0, direct: 1, rolledUp: 0, pushed: 0,
      configs: [], unresolved: [],
    });
  });
  afterEach(cleanup);

  it("keeps the human name and opaque uid on one line", async () => {
    // The case the old matchedAt column got wrong: a GCP firewall's uid is a
    // number and its name is what an operator recognises, so a table showing
    // only the uid is unreadable and one showing only the name is unqueryable.
    fetchResourcesMock.mockResolvedValue(page([resource()]));

    render(<ResourcesView onOpenResource={() => {}} />);

    const name = await screen.findByText("tailscale-router");
    const uid = screen.getByText("1429543158501771126");
    const identity = name.parentElement;
    expect(identity).toContainElement(uid);
    expect(identity).toHaveClass("flex", "items-baseline");
  });

  it("links each row to the resource it names", async () => {
    fetchResourcesMock.mockResolvedValue(page([resource()]));

    render(<ResourcesView onOpenResource={() => {}} />);

    await waitFor(() => expect(screen.getByText("tailscale-router")).toBeInTheDocument());
    const link = screen
      .getAllByRole("link")
      .find((a) => a.getAttribute("href") === "/resources/01JRESOURCE");
    expect(link).toBeDefined();
  });

  // The empty state that is not an empty result. A tab that opens on "no
  // resources match these filters" when no scan has ever run reads as broken,
  // and the fix is not an emptyMessage — the table is the wrong place to
  // explain that nothing has been recorded.
  it("explains an estate nothing has recorded yet", async () => {
    fetchResourcesMock.mockResolvedValue(page([], 0));

    render(<ResourcesView onOpenResource={() => {}} />);

    await waitFor(() => expect(screen.getByText("No resources yet")).toBeInTheDocument());
    expect(screen.queryByText(/No resources match/)).not.toBeInTheDocument();
  });

  it("asks the server for the page rather than slicing one in the browser", async () => {
    fetchResourcesMock.mockResolvedValue(page([resource()], 940));

    render(<ResourcesView onOpenResource={() => {}} />);

    await waitFor(() => expect(fetchResourcesMock).toHaveBeenCalled());
    const params = fetchResourcesMock.mock.calls[0]?.[0] ?? {};
    // Both, because a page without a limit is the whole estate and a limit
    // without an offset can only ever show the first page.
    expect(params).toMatchObject({
      limit: 100,
      offset: 0,
      sort: "worst",
      order: "asc",
    });
  });

  it("previews a sync of the filtered set without carrying page controls", async () => {
    fetchResourcesMock.mockResolvedValue(page([resource()]));
    render(<ResourcesView onOpenResource={() => {}} />);

    fireEvent.change(await screen.findByRole("searchbox"), { target: { value: "tailscale" } });
    await waitFor(() => expect(fetchResourcesMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ search: "tailscale" }),
    ));
    fireEvent.click(screen.getByRole("button", { name: "Sync insights" }));

    await waitFor(() => expect(syncResources).toHaveBeenCalledWith({ search: "tailscale" }, true));
  });

  it("renders a compact severity bar and total", async () => {
    fetchResourcesMock.mockResolvedValue(
      page([resource({ findings: 3, severities: { high: 2, low: 1 } })]),
    );

    render(<ResourcesView onOpenResource={() => {}} />);

    expect(await screen.findByRole("img", { name: "2 high, 1 low" })).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
  });

  // A resource a covering run no longer sees. Reported as an observation, not
  // as a conclusion: recon cannot tell a decommission from an API error.
  it("says a vanished resource was last seen rather than deleted", async () => {
    fetchResourcesMock.mockResolvedValue(page([resource({ state: "absent" })]));

    render(<ResourcesView onOpenResource={() => {}} />);

    await waitFor(() => expect(screen.getByText("last seen")).toBeInTheDocument());
    expect(screen.queryByText(/deleted/i)).not.toBeInTheDocument();
  });

  it("surfaces a failure instead of rendering an empty estate", async () => {
    fetchResourcesMock.mockRejectedValue(new Error("resource listing unavailable"));

    render(<ResourcesView onOpenResource={() => {}} />);

    await waitFor(() =>
      expect(screen.getByText("resource listing unavailable")).toBeInTheDocument(),
    );
    // The distinction that matters: a request that failed must not look like
    // an estate with nothing in it.
    expect(screen.queryByText("No resources yet")).not.toBeInTheDocument();
  });
});
