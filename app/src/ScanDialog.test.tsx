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
import { ScanDialog } from "./ScanDialog";
import type { Discover, Engine, Profile, Scan, TargetRow } from "./types";

const rows: TargetRow[] = [
  {
    $schema: "../target.schema.json",
    version: 1,
    host: "api.example.com",
    class: "non-prod",
    profiles: ["safe"],
    tags: ["api"],
  },
  {
    $schema: "../target.schema.json",
    version: 1,
    host: "docs.example.com",
    class: "public",
    profiles: ["safe"],
    tags: ["docs"],
  },
];

const nucleiEngine: Engine = {
  _id: "scan:nuclei",
  name: "nuclei",
  kind: "scan",
  title: "Nuclei",
  binary: "nuclei",
  installed: true,
  managed: true,
  sections: [
    {
      id: "scan",
      title: "Scan",
      properties: {
        dast: { type: "boolean", title: "DAST" },
      },
    },
  ],
};

const safeProfile: Profile = {
  _id: "scan:nuclei:safe",
  kind: "scan",
  engine: "nuclei",
  name: "safe",
  config: {},
  intrusive: false,
};

// The engine reports its own verdict on a configuration, and the confirm gate
// keys off that rather than off the profile's name.
const intrusiveProfile: Profile = {
  _id: "scan:nuclei:full",
  kind: "scan",
  engine: "nuclei",
  name: "full",
  config: { dast: true },
  intrusive: true,
  reason: "DAST sends active payloads",
};

const createdScan: Scan = {
  _id: "scan-1",
  id: "scan-1",
  name: "run-1",
  engine: "nuclei",
  profile: "safe",
  selector: { hosts: ["api.example.com"] },
  selectorLabel: "hosts api.example.com",
  endpointCount: 1,
  phase: "running",
  startedAt: "2026-08-09T08:00:00.000Z",
  findings: 0,
  severities: {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    unknown: 0,
  },
  hosts: ["api.example.com"],
};

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function mockFetch(handlers: Record<string, unknown>) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = typeof input === "string" ? input : (input as Request).url;
    const path = url.replace(/^https?:\/\/[^/]+/, "");
    const match = Object.entries(handlers).find(([prefix]) =>
      path.startsWith(prefix),
    );
    if (!match) throw new Error(`unexpected fetch: ${path}`);
    return jsonResponse(match[1]);
  });
}

describe("ScanDialog", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("starts a scan against the selected targets", async () => {
    const fetchMock = mockFetch({
      "/api/v1/engine": [nucleiEngine],
      "/api/v1/profile": [safeProfile],
      "/api/v1/scan": createdScan,
    });
    const onStatus = vi.fn();

    render(
      <ScanDialog
        open
        onClose={vi.fn()}
        rows={rows}
        savedHosts={rows.map((row) => row.host)}
        selectedHosts={["api.example.com"]}
        status={null}
        onStatus={onStatus}
      />,
    );

    // Wait for the engine/profile catalog to load before the run starts.
    await screen.findByText("safe");
    fireEvent.click(screen.getByRole("button", { name: "Scan 1 host" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/v1/scan",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            host: ["api.example.com"],
            engine: "nuclei",
            profile: "safe",
            "discovery-profile": "default",
            confirm: false,
            wait: false,
          }),
        }),
      ),
    );
  });

  it("offers every stored profile for a manual run regardless of target assignments", async () => {
    const fetchMock = mockFetch({
      "/api/v1/engine": [nucleiEngine],
      "/api/v1/profile": [safeProfile, intrusiveProfile],
      "/api/v1/scan": createdScan,
    });

    render(
      <ScanDialog
        open
        onClose={vi.fn()}
        rows={rows}
        savedHosts={rows.map((row) => row.host)}
        selectedHosts={["api.example.com"]}
        status={null}
        onStatus={vi.fn()}
        editableProfile
      />,
    );

    const profile = await screen.findByRole("combobox", { name: "Profile" });
    expect(screen.getByRole("option", { name: "safe" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "full" })).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/profile?kind=scan&engine=nuclei",
      undefined,
    );

    fireEvent.change(profile, { target: { value: "full" } });
    fireEvent.click(screen.getByRole("button", { name: "Scan 1 host" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/v1/scan",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            host: ["api.example.com"],
            engine: "nuclei",
            profile: "full",
            "discovery-profile": "default",
            confirm: false,
            wait: false,
          }),
        }),
      ),
    );
    expect(rows[0].profiles).toEqual(["safe"]);
  });

  it("requires confirmation for an intrusive scan of a prod or public host", async () => {
    const fetchMock = mockFetch({
      "/api/v1/engine": [nucleiEngine],
      "/api/v1/profile": [intrusiveProfile],
      "/api/v1/scan": createdScan,
    });

    render(
      <ScanDialog
        open
        onClose={vi.fn()}
        rows={rows}
        savedHosts={rows.map((row) => row.host)}
        selectedHosts={["docs.example.com"]}
        status={null}
        onStatus={vi.fn()}
      />,
    );

    await screen.findByText("full");
    expect(screen.getByRole("button", { name: "Scan 1 host" })).toBeDisabled();
    expect(
      screen.getByText(/prod\/public or unsaved host/),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "Scan 1 host" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/v1/scan",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            host: ["docs.example.com"],
            engine: "nuclei",
            profile: "full",
            "discovery-profile": "default",
            confirm: true,
            wait: false,
          }),
        }),
      ),
    );
  });

  it("does not ask for confirmation when the profile is not intrusive", async () => {
    // The server would run this without complaint, so requiring a checkbox
    // would be friction the rule does not call for.
    mockFetch({
      "/api/v1/engine": [nucleiEngine],
      "/api/v1/profile": [safeProfile],
      "/api/v1/scan": createdScan,
    });

    render(
      <ScanDialog
        open
        onClose={vi.fn()}
        rows={rows}
        savedHosts={rows.map((row) => row.host)}
        selectedHosts={["docs.example.com"]}
        status={null}
        onStatus={vi.fn()}
      />,
    );

    await screen.findByText("safe");
    expect(screen.getByRole("button", { name: "Scan 1 host" })).toBeEnabled();
    expect(screen.queryByRole("checkbox")).toBeNull();
  });

  it("allows discovery to auto-inventory an unsaved explicit host", async () => {
    const result: Discover = {
      id: "discover-new",
      chain: "explicit",
      profile: "default",
      input: { hosts: ["api.example.com"] },
      ranAt: "2026-08-10T09:00:00",
      durationMs: 10,
      failed: false,
      hosts: [],
      log: "",
    };
    const fetchMock = mockFetch({ "/api/v1/discover": result });

    render(
      <ScanDialog
        open
        onClose={vi.fn()}
        rows={rows}
        savedHosts={[]}
        selectedHosts={["api.example.com"]}
        status={null}
        onStatus={vi.fn()}
        discoveryOnly
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Rescan 1 host" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/v1/discover",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ host: ["api.example.com"] }),
        }),
      ),
    );
  });

  it("rescans saved hosts via discovery instead of a scan engine", async () => {
    const result: Discover = {
      _id: "discover-1",
      id: "discover-1",
      chain: "targeted",
      profile: "default",
      input: { hosts: ["api.example.com"] },
      ranAt: "2026-08-09T08:00:00",
      durationMs: 10,
      failed: false,
      hosts: [],
      log: ">>> rescanning 1 host\n",
    };
    const fetchMock = mockFetch({
      "/api/v1/discover": result,
    });

    render(
      <ScanDialog
        open
        onClose={vi.fn()}
        rows={rows}
        savedHosts={rows.map((row) => row.host)}
        selectedHosts={["api.example.com"]}
        status={null}
        onStatus={vi.fn()}
        discoveryOnly
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Rescan 1 host" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/v1/discover",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ host: ["api.example.com"] }),
        }),
      ),
    );
    await screen.findByText("0 hosts probed");
  });
});
