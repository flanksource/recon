// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
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
    startedAt: "",
    hosts: [],
    newCount: 0,
    log: "",
  })),
  startScan: vi.fn(async () => idleScan),
  cancelScan: vi.fn(async () => idleScan),
  SCAN_EVENTS_URL: "/api/scan/events",
}));

describe("InventoryView", () => {
  afterEach(() => {
    cleanup();
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it("shows discovery status, latency, ports, paths, and login methods", async () => {
    Object.defineProperty(window, "matchMedia", {
      configurable: true,
      value: vi.fn().mockReturnValue({
        matches: false,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
      }),
    });

    render(<InventoryView onOpenScan={vi.fn()} onOpenTarget={vi.fn()} />);

    expect(await screen.findByText("api.example.com")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Status" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Response" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open ports" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Known paths" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Login methods" })).toBeInTheDocument();
    expect(screen.getByText("200")).toBeInTheDocument();
    expect(screen.getByText("125ms")).toBeInTheDocument();
    expect(screen.getByText("8443")).toBeInTheDocument();
    expect(screen.getByText("/login")).toBeInTheDocument();
    expect(screen.getByText("Web login")).toBeInTheDocument();
  });
});
