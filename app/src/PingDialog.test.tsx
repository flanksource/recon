// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PingDialog } from "./PingDialog";
import type { ProbeRun, TargetRow } from "./types";

const rows: TargetRow[] = [
  {
    $schema: "../target.schema.json",
    version: 1,
    host: "api.example.com",
    class: "non-prod",
    profiles: ["safe"],
    tags: [],
  },
  {
    $schema: "../target.schema.json",
    version: 1,
    host: "docs.example.com",
    class: "public",
    profiles: ["safe"],
    tags: [],
  },
];

const run: ProbeRun = {
  ranAt: "2026-08-11T09:00:00Z",
  durationMs: 42,
  live: 1,
  updated: 2,
  results: [
    {
      host: "api.example.com",
      url: "https://api.example.com",
      up: true,
      statusCode: 200,
      responseTimeMs: 125,
      ip: "192.0.2.10",
    },
    {
      host: "docs.example.com",
      up: false,
      responseTimeMs: 3000,
      error: "connection refused",
    },
  ],
};

function stubFetch(body: unknown = run) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async () =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
  );
}

describe("PingDialog", () => {
  beforeEach(() => {
    Object.defineProperty(window, "matchMedia", {
      configurable: true,
      value: vi.fn().mockReturnValue({
        matches: false,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
      }),
    });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("probes only the selected hosts", async () => {
    const fetchMock = stubFetch();
    const onProbed = vi.fn();

    render(
      <PingDialog
        open
        onClose={vi.fn()}
        rows={rows}
        selectedHosts={["api.example.com"]}
        onProbed={onProbed}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Ping 1 host" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/v1/probe",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ host: ["api.example.com"] }),
        }),
      ),
    );
    // The probe rewrote what the table shows, so the inventory has to reload.
    await waitFor(() => expect(onProbed).toHaveBeenCalledOnce());
  });

  it("widens to every target when the scope is changed", async () => {
    const fetchMock = stubFetch();

    render(
      <PingDialog
        open
        onClose={vi.fn()}
        rows={rows}
        selectedHosts={["api.example.com"]}
        onProbed={vi.fn()}
      />,
    );

    fireEvent.click(screen.getByRole("radio", { name: "All targets (2)" }));
    fireEvent.click(screen.getByRole("button", { name: "Ping 2 hosts" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/v1/probe",
        expect.objectContaining({
          body: JSON.stringify({
            host: ["api.example.com", "docs.example.com"],
          }),
        }),
      ),
    );
  });

  it("reports what answered and what did not", async () => {
    stubFetch();

    render(
      <PingDialog
        open
        onClose={vi.fn()}
        rows={rows}
        selectedHosts={[]}
        onProbed={vi.fn()}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Ping 2 hosts" }));

    expect(
      await screen.findByText(/1 of 2 answered · 2 targets updated · 42ms/),
    ).toBeInTheDocument();
    expect(await screen.findByText("connection refused")).toBeInTheDocument();
    expect(screen.getByText("125ms")).toBeInTheDocument();
  });

  it("surfaces a refused probe rather than reporting success", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ error: "no targets match: nothing to probe" }), {
        status: 422,
        headers: { "content-type": "application/json" },
      }),
    );
    const onProbed = vi.fn();

    render(
      <PingDialog
        open
        onClose={vi.fn()}
        rows={rows}
        selectedHosts={[]}
        onProbed={onProbed}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Ping 2 hosts" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "no targets match: nothing to probe",
    );
    expect(onProbed).not.toHaveBeenCalled();
  });
});
