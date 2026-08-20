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
import type { ProbeResult, ProbeRun, Target } from "./types";

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

const other: Target = {
  $schema: "../target.schema.json",
  version: 1,
  _id: "docs.example.com",
  host: "docs.example.com",
  class: "prod",
  profiles: ["safe"],
  tags: [],
};

// What the server returns for docs.example.com once a probe has been merged into
// it. The browser never builds this from the ProbeResult — observe.ApplyProbe
// does the merge server-side, so the row is refetched rather than patched.
//
// It carries both a status code and a failure on purpose: a failed probe keeps
// the code from the host's last good probe, so this is the shape that used to
// leave a dead host looking answered.
const probedOther: Target = {
  ...other,
  http: { status_code: 503, response_time: "88ms" },
  observed: {
    last_attempt: "2026-08-11T09:00:00",
    error: 'Get "https://docs.example.com": dial tcp: lookup docs.example.com: no such host',
    failure: "dns",
  },
};

function probeResult(host: string, responseTimeMs: number): ProbeResult {
  // Deliberately without a status code: the dialog's own table would otherwise
  // render numbers that collide with the inventory table behind it.
  return { host, up: true, responseTimeMs, updated: true };
}

const finishedRun: ProbeRun = {
  id: "01JPROBE",
  selector: {},
  selectorLabel: "2 hosts",
  phase: "done",
  ranAt: "2026-08-11T09:00:00",
  durationMs: 49,
  total: 2,
  live: 2,
  updated: 2,
  results: [
    probeResult("api.example.com", 42),
    probeResult("docs.example.com", 7),
  ],
};

vi.mock("./api", () => ({
  fetchTargets: vi.fn(async (selector?: Record<string, unknown>) =>
    selector && "hosts" in selector ? [probedOther] : [target, other],
  ),
  saveTargets: vi.fn(async () => [target]),
  probeTargets: vi.fn(async () => finishedRun),
  fetchProbe: vi.fn(async () => finishedRun),
  fetchProbes: vi.fn(async () => []),
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
    // The view mirrors its query and selection into the URL, and jsdom keeps
    // that URL for the whole file — so without this a spec that selects a row
    // hands the next one a pre-selected table.
    window.history.replaceState(null, "", "/");
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

  // A sweep reports hosts as they answer, so the inventory refetches exactly
  // those rows instead of reloading the estate once per batch. The unsaved edit
  // is laid back over the refreshed rows by the same memo the reload path uses,
  // so following a probe cannot cost the user their typing either.
  it("refreshes only the hosts a probe reported, keeping an unsaved edit", async () => {
    stubMatchMedia();
    const { fetchTargets } = await import("./api");
    render(<InventoryView onOpenScan={vi.fn()} onOpenTarget={vi.fn()} />);

    fireEvent.click(
      await screen.findByRole("checkbox", { name: /api\.example\.com/ }),
    );
    fireEvent.change(await screen.findByPlaceholderText("tag…"), {
      target: { value: "reviewed" },
    });
    fireEvent.click(screen.getByRole("button", { name: "+ Add tag" }));
    expect(await screen.findByText("reviewed")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Ping hosts" }));
    fireEvent.click(await screen.findByRole("radio", { name: "All targets (2)" }));
    fireEvent.click(screen.getByRole("button", { name: "Ping 2 hosts" }));

    // One targeted refetch naming the probed hosts — not the unfiltered listing
    // the Reload button asks for.
    await waitFor(() =>
      expect(fetchTargets).toHaveBeenLastCalledWith({
        hosts: "api.example.com,docs.example.com",
      }),
    );

    // docs.example.com carried no HTTP state before the sweep, so this is on
    // screen only if the refetched row replaced it.
    expect(await screen.findByText("88ms")).toBeInTheDocument();

    // And the row says the host is down now rather than showing the 503 the
    // refetched document still carries from its last good probe.
    expect(screen.getByText("DNS")).toBeInTheDocument();
    expect(screen.queryByText("503")).not.toBeInTheDocument();
    expect(screen.getByText(/no such host/)).toBeInTheDocument();

    expect(screen.getByText("reviewed")).toBeInTheDocument();
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
