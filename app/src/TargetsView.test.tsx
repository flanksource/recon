// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { InventoryView } from "./TargetsView";

const idleScan = {
  phase: "idle",
  profile: null,
  group: null,
  hosts: [],
  file: null,
  startedAt: null,
  finishedAt: null,
  stats: null,
  findings: [],
  log: "",
  error: null,
  command: null,
  exitCode: null,
  observations: null,
  output: [],
};

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
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      if (String(input) === "/api/scan") {
        return new Response(JSON.stringify(idleScan), { status: 200 });
      }
      if (String(input) === "/api/inventory") {
        return new Response(
          JSON.stringify({
            version: 1,
            zones: ["example.com"],
            tagVocabulary: [],
            rows: [
              {
                $schema: "../target.schema.json",
                version: 1,
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
              },
            ],
          }),
          { status: 200 },
        );
      }
      throw new Error(`unexpected request: ${String(input)}`);
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
