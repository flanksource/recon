// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";

const activeRun = {
  id: "scan-1",
  name: "nuclei-safe-1",
  kind: "scan",
  status: "running",
  total: 1,
  completed: 0,
  failed: 0,
  running: 1,
};

describe("App routes", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    window.history.replaceState(null, "", "/");
  });

  it("renders a deep-linked inventory target with Inventory navigation active", async () => {
    window.history.replaceState(null, "", "/inventory/api.example.com");
    vi.stubGlobal("EventSource", undefined);
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const path = String(input);
      if (path === "/api/v1/tasks") {
        return new Response(JSON.stringify([activeRun]), { status: 200 });
      }
      if (path === "/api/schema/target") {
        return new Response(JSON.stringify({ type: "object", properties: {} }), { status: 200 });
      }
      if (path === "/api/v1/target/api.example.com") {
        return new Response(
          JSON.stringify({
            $schema: "../target.schema.json",
            version: 1,
            host: "api.example.com",
            class: "prod",
            profiles: ["safe"],
            tags: [],
          }),
          { status: 200 },
        );
      }
      throw new Error(`unexpected request: ${path}`);
    });

    render(<App />);

    expect(await screen.findByRole("heading", { name: "api.example.com" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Inventory" })).toHaveAttribute("href", "/inventory");
    const tasksButton = await screen.findByRole("button", { name: "Tasks (1 active)" });
    expect(tasksButton.querySelector("svg")).not.toBeNull();
  });

  it("expands a deep-linked background task on the tasks page", async () => {
    window.history.replaceState(null, "", "/tasks/scan-1");
    vi.stubGlobal("EventSource", undefined);
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const path = String(input);
      if (path === "/api/v1/tasks") {
        return new Response(JSON.stringify([{ ...activeRun, status: "success", completed: 1, running: 0 }]), {
          status: 200,
        });
      }
      if (path === "/api/v1/tasks/scan-1") {
        return new Response(
          JSON.stringify([
            { id: "nuclei-safe-1", groupId: "scan-1", name: "nuclei-safe-1", type: "group", status: "success", total: 1 },
            {
              id: "engine-1",
              groupId: "scan-1",
              name: "run nuclei",
              type: "task",
              status: "running",
              progress: 25,
              maxValue: 100,
              controls: ["stop"],
              stdout: "scanning api.example.com",
            },
          ]),
          { status: 200 },
        );
      }
      throw new Error(`unexpected request: ${path}`);
    });

    render(<App />);

    expect(await screen.findByRole("heading", { name: "Tasks" })).toBeInTheDocument();
    expect(await screen.findByText("run nuclei")).toBeInTheDocument();
    expect(screen.getByText(/25\/100 · 25%/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Stop run nuclei" })).toBeInTheDocument();
  });

  it("renders a deep-linked scan with findings, and its execution evidence behind a tab", async () => {
    window.history.replaceState(null, "", "/scans/scan-1");
    vi.stubGlobal("EventSource", undefined);
    Object.defineProperty(window, "matchMedia", {
      configurable: true,
      value: vi.fn().mockReturnValue({
        matches: false,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
      }),
    });
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const path = String(input);
      if (path === "/api/v1/tasks") {
        return new Response(JSON.stringify([]), { status: 200 });
      }
      if (path === "/api/v1/finding?__lookup=filters") {
        return new Response(JSON.stringify({ filters: {} }), { status: 200 });
      }
      if (path === "/api/v1/finding?scan=scan-1") {
        return new Response(JSON.stringify([]), { status: 200 });
      }
      if (path === "/api/v1/scan/scan-1") {
        return new Response(
          JSON.stringify({
            id: "scan-1",
            name: "nuclei-safe-1",
            engine: "nuclei",
            engineVersion: "3.4.10",
            profile: "safe",
            selector: { hosts: ["api.example.test"] },
            selectorLabel: "host api.example.test",
            endpointCount: 3,
            phase: "done",
            startedAt: "2026-08-10T12:00:00",
            finishedAt: "2026-08-10T12:00:02",
            durationMs: 2500,
            command: ["/opt/recon/bin/nuclei", "-target", "api.example.test", "-stats"],
            exitCode: 0,
            findings: 0,
            severities: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
            stats: { requests: 40, total: 60, templates: 18, matched: 0, errors: 2, rps: 12 },
            hosts: [],
            outputCaptured: false,
          }),
          { status: 200 },
        );
      }
      throw new Error(`unexpected request: ${path}`);
    });

    render(<App />);

    expect(await screen.findByRole("heading", { name: "nuclei-safe-1" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Back to scans" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Scans" })).toHaveAttribute("href", "/scans");
    expect(screen.getByText("No findings in this scan.")).toBeInTheDocument();

    // The run's own evidence lives on the Execution tab so the findings table
    // owns the height; it is one click away, not gone.
    fireEvent.click(screen.getByRole("tab", { name: "Execution" }));
    expect(await screen.findByText("templates")).toBeInTheDocument();
    expect(screen.getByText("templates").parentElement).toHaveTextContent("18");
    expect(screen.getByText("errors").parentElement).toHaveTextContent("2");
  });
});
