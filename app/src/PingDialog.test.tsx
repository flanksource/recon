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
import type { ProbeResult, ProbeRun, TargetRow } from "./types";

const rows: TargetRow[] = [
  {
    $schema: "../target.schema.json",
    version: 1,
    id: "api.example.com",
    host: "api.example.com",
    class: "non-prod",
    profiles: ["safe"],
    tags: [],
  },
  {
    $schema: "../target.schema.json",
    version: 1,
    id: "docs.example.com",
    host: "docs.example.com",
    class: "public",
    profiles: ["safe"],
    tags: [],
  },
];

const answered: ProbeResult = {
  host: "api.example.com",
  url: "https://api.example.com",
  up: true,
  statusCode: 200,
  responseTimeMs: 125,
  ip: "192.0.2.10",
  updated: true,
};

const refused: ProbeResult = {
  host: "docs.example.com",
  up: false,
  responseTimeMs: 3000,
  error: "connection refused",
  updated: true,
};

function makeRun(overrides: Partial<ProbeRun> = {}): ProbeRun {
  return {
    id: "01JPROBE",
    selector: {},
    selectorLabel: "2 hosts",
    phase: "done",
    ranAt: "2026-08-11T09:00:00",
    durationMs: 42,
    total: 2,
    live: 1,
    updated: 2,
    results: [answered, refused],
    ...overrides,
  };
}

// Routes by URL rather than answering everything the same way: the dialog now
// POSTs to start a sweep and then polls the run, so a single stub would make
// "the run was created" and "the run finished" indistinguishable.
function stubFetch(snapshots: ProbeRun[]) {
  let poll = 0;
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = typeof input === "string" ? input : (input as Request).url;
    const body =
      init?.method === "POST"
        ? snapshots[0]
        : snapshots[Math.min(poll++, snapshots.length - 1)];
    expect(url).toMatch(/^\/api\/v1\/probe/);
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  });
}

function open(props: Partial<Parameters<typeof PingDialog>[0]> = {}) {
  return render(
    <PingDialog
      open
      onClose={vi.fn()}
      rows={rows}
      selectedHosts={[]}
      onProbed={vi.fn()}
      {...props}
    />,
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

  it("probes only the selected hosts, and does not hold the request open", async () => {
    const fetchMock = stubFetch([makeRun()]);
    open({ selectedHosts: ["api.example.com"] });

    fireEvent.click(screen.getByRole("button", { name: "Ping 1 host" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/v1/probe",
        expect.objectContaining({
          method: "POST",
          // wait:false is what makes live progress possible at all — a sweep of
          // the estate outlasts any sensible request timeout.
          body: JSON.stringify({ host: ["api.example.com"], wait: false }),
        }),
      ),
    );
  });

  it("widens to every target when the scope is changed", async () => {
    const fetchMock = stubFetch([makeRun()]);
    open({ selectedHosts: ["api.example.com"] });

    fireEvent.click(screen.getByRole("radio", { name: "All targets (2)" }));
    fireEvent.click(screen.getByRole("button", { name: "Ping 2 hosts" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/v1/probe",
        expect.objectContaining({
          body: JSON.stringify({
            host: ["api.example.com", "docs.example.com"],
            wait: false,
          }),
        }),
      ),
    );
  });

  // The point of following the run rather than awaiting it: a host shows up as
  // soon as it answers, instead of the estate appearing all at once at the end.
  it("fills the table while the sweep is still running", async () => {
    stubFetch([
      makeRun({ phase: "running", live: 1, updated: 1, results: [answered] }),
      makeRun(),
    ]);
    open();

    fireEvent.click(screen.getByRole("button", { name: "Ping 2 hosts" }));

    expect(await screen.findByText("125ms")).toBeInTheDocument();
    expect(screen.getByText(/1 of 2 checked, 1 answered/)).toBeInTheDocument();
    expect(await screen.findByText("connection refused")).toBeInTheDocument();
  });

  it("refreshes each host's inventory row as its result lands", async () => {
    const onProbed = vi.fn();
    stubFetch([
      makeRun({ phase: "running", live: 1, updated: 1, results: [answered] }),
      makeRun(),
    ]);
    open({ onProbed });

    fireEvent.click(screen.getByRole("button", { name: "Ping 2 hosts" }));

    // Once per host, as it finishes — not once for the whole sweep, and never
    // twice for a host already reported.
    await waitFor(() => expect(onProbed).toHaveBeenCalledWith(["api.example.com"]));
    await waitFor(() => expect(onProbed).toHaveBeenCalledWith(["docs.example.com"]));
  });

  it("reports what answered and what did not once the sweep finishes", async () => {
    stubFetch([makeRun()]);
    open();

    fireEvent.click(screen.getByRole("button", { name: "Ping 2 hosts" }));

    expect(
      await screen.findByText(/1 of 2 answered · 2 targets updated · 42ms/),
    ).toBeInTheDocument();
  });

  it("surfaces a refused probe rather than reporting success", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ error: "no targets match: nothing to probe" }), {
        status: 422,
        headers: { "content-type": "application/json" },
      }),
    );
    const onProbed = vi.fn();
    open({ onProbed });

    fireEvent.click(screen.getByRole("button", { name: "Ping 2 hosts" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "no targets match: nothing to probe",
    );
    expect(onProbed).not.toHaveBeenCalled();
  });
});
