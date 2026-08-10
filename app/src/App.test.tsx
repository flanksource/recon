// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
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
});
