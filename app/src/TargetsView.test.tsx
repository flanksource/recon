// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { InventoryView } from "./TargetsView";
import type { Target } from "./types";

const idleScan = {
  id: "scan-idle",
  _id: "scan-idle",
  phase: "idle" as const,
  running: false,
  log: "",
  output: [],
  name: "",
  engine: "",
  profile: "",
  selector: {},
  selectorLabel: "",
  endpointCount: 0,
  startedAt: "",
  findings: 0,
  severities: {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    unknown: 0,
  },
  hosts: [],
};

const target: Target = {
  $schema: "../target.schema.json",
  version: 1,
  _id: "api.example.com",
  host: "api.example.com",
  class: "prod",
  profiles: ["safe"],
  tags: [],
  network: { open_ports: [443, 8443] },
  http: {
    status_code: 200,
    response_time: "125ms",
    known_paths: ["/", "/login"],
    login_methods: ["Basic", "Web login"],
  },
};

vi.mock("./api", () => ({
  fetchTargets: vi.fn(async () => [target]),
  saveTargets: vi.fn(async () => [target]),
  fetchFilters: vi.fn(async () => [
    {
      key: "class",
      label: "Class",
      options: ["prod", "non-prod"],
      total: 2,
      truncated: false,
    },
    {
      key: "tags",
      label: "Tags",
      options: ["http"],
      total: 1,
      truncated: false,
    },
  ]),
  fetchFilterOptions: vi.fn(async () => []),
  fetchZones: vi.fn(async () => []),
  fetchTargetSchema: vi.fn(async () => ({})),
  fetchProfiles: vi.fn(async () => []),
  fetchScanStatus: vi.fn(async () => idleScan),
  fetchDiscoveries: vi.fn(async () => []),
  fetchLatestDiscovery: vi.fn(async () => null),
  runDiscovery: vi.fn(async () => ({
    id: "discover-1",
    _id: "discover-1",
    chain: "",
    profile: "default",
    input: {},
    ranAt: "",
    durationMs: 0,
    failed: false,
    hosts: [],
    log: "",
  })),
  startScan: vi.fn(async () => idleScan),
  cancelScan: vi.fn(async () => idleScan),
  SCAN_EVENTS_URL: "/api/scan/events",
}));

describe("InventoryView", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("shows discovery status, latency, ports, paths, and login methods", async () => {
    stubMatchMedia();

    render(<InventoryView onOpenScan={vi.fn()} onOpenTarget={vi.fn()} />);

    expect(await screen.findByText("api.example.com")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Status" })).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Response" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Open ports" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Known paths" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Login methods" }),
    ).toBeInTheDocument();
    expect(screen.getByText("200")).toBeInTheDocument();
    expect(screen.getByText("125ms")).toBeInTheDocument();
    expect(screen.getByText("8443")).toBeInTheDocument();
    expect(screen.getByText("/login")).toBeInTheDocument();
    expect(screen.getByText("Web login")).toBeInTheDocument();
  });

  // The controls used to be written out here, which meant the browser held its
  // own idea of what a class or a tag could be. They now come from the entity's
  // filter declaration, so a filter the server does not offer cannot appear and
  // one it does cannot be forgotten.
  it("builds its filter controls from what the listing says it offers", async () => {
    stubMatchMedia();
    render(<InventoryView onOpenScan={vi.fn()} onOpenTarget={vi.fn()} />);

    expect(
      await screen.findByRole("combobox", { name: /Class/ }),
    ).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: /Tags/ })).toBeInTheDocument();
  });

  it("asks the server for the narrowed list rather than narrowing what it has", async () => {
    stubMatchMedia();
    const { fetchTargets } = await import("./api");
    render(<InventoryView onOpenScan={vi.fn()} onOpenTarget={vi.fn()} />);

    fireEvent.click(await screen.findByRole("combobox", { name: /Class/ }));
    // The combobox commits on mousedown, not click.
    fireEvent.mouseDown(await screen.findByRole("option", { name: "prod" }));

    await waitFor(() =>
      expect(fetchTargets).toHaveBeenLastCalledWith({ class: "prod" }),
    );
  });

  // Filtering, reloading and a finishing scan all refetch, and the rows they
  // return are the database's. An edit is held separately and re-applied over
  // them, so none of those can silently discard typing — which is what the old
  // "don't reload while dirty" guard was working around.
  it("keeps an unsaved edit when the list is refetched", async () => {
    stubMatchMedia();
    render(<InventoryView onOpenScan={vi.fn()} onOpenTarget={vi.fn()} />);

    fireEvent.click(
      await screen.findByRole("checkbox", { name: /api\.example\.com/ }),
    );
    fireEvent.change(screen.getByPlaceholderText("tag…"), {
      target: { value: "reviewed" },
    });
    fireEvent.click(screen.getByRole("button", { name: "+ Add tag" }));
    expect(await screen.findByText("reviewed")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Reload" }));

    // The refetched row carries no tags at all, so the tag is only still on
    // screen if the edit outlived the fetch.
    expect(await screen.findByText("reviewed")).toBeInTheDocument();
    expect(screen.getByText("Unsaved changes")).toBeInTheDocument();
  });
});

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
