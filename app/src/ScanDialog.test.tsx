// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ScanDialog } from "./ScanDialog";
import type {
  Discover,
  Engine,
  Profile,
  Scan,
  TargetRow,
  TemplatePreview,
} from "./types";

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

// Every run in this dialog sweeps before it scans, so the dialog also loads the
// discovery catalog. Naabu has a second profile so an override can be chosen.
const naabuEngine: Engine = {
  _id: "discovery:naabu",
  name: "naabu",
  kind: "discovery",
  title: "Naabu",
  binary: "naabu",
  installed: true,
  managed: true,
  sections: [
    {
      id: "ports",
      title: "Ports",
      properties: { "top-ports": { type: "string", title: "Top ports" } },
    },
  ],
};

const discoveryProfiles: Profile[] = [
  {
    _id: "discovery:naabu:default",
    kind: "discovery",
    engine: "naabu",
    name: "default",
    config: { "top-ports": "100" },
  },
  {
    _id: "discovery:naabu:full-ports",
    kind: "discovery",
    engine: "naabu",
    name: "full-ports",
    config: { "top-ports": "65535" },
  },
];

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

// What the chosen profile would run. A profile name says nothing about how much
// it checks, so the dialog previews it before the scan starts.
const templatePreview: TemplatePreview = {
  engine: "nuclei",
  total: 4314,
  bySeverity: { critical: 96, high: 803 },
  byType: { http: 4314 },
  byTag: [{ tag: "panel", count: 1200 }],
  maxRequests: 9000,
  templates: [],
  truncated: true,
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
  durationMs: 0,
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

// The discovery catalog is served first so the kind-qualified prefixes win over
// the bare ones — the two listings differ only by query string.
function mockFetch(handlers: Record<string, unknown>) {
  const routes: Record<string, unknown> = {
    "/api/v1/engine?kind=discovery": [naabuEngine],
    "/api/v1/profile?kind=discovery": discoveryProfiles,
    "/api/template/preview": templatePreview,
    // The scan profile form is editable in this dialog, and it reads the
    // template vocabulary to offer the include/exclude filter pairs.
    "/api/v1/template": { filters: {} },
    ...handlers,
  };
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = typeof input === "string" ? input : (input as Request).url;
    const path = url.replace(/^https?:\/\/[^/]+/, "");
    const match = Object.entries(routes).find(([prefix]) =>
      path.startsWith(prefix),
    );
    if (!match) throw new Error(`unexpected fetch: ${path}`);
    // A route may answer the request rather than name a fixed body, which is
    // how a spec reads what a run actually sent.
    const body = match[1];
    return jsonResponse(
      typeof body === "function"
        ? (body as (path: string, init?: RequestInit) => unknown)(path, init)
        : body,
    );
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

    // The run carries the profile's configuration, so the button stays
    // disabled until the catalog it is read from has arrived.
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Scan 1 host" })).toBeEnabled(),
    );
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
            "discovery-profile": ["default"],
            confirm: false,
            wait: false,
          }),
        }),
      ),
    );
  });

  // The alternative was writing the tweak into the profile every other target
  // scans with, so a one-off custom run silently redefined "safe".
  it("carries a tweaked scan configuration with the run instead of saving it", async () => {
    const saved: RequestInit[] = [];
    let sent: Record<string, unknown> = {};
    mockFetch({
      "/api/v1/engine": [nucleiEngine],
      "/api/v1/profile": (_path: string, init?: RequestInit) => {
        if (init?.method !== "POST") return [safeProfile];
        saved.push(init);
        return safeProfile;
      },
      "/api/v1/scan": (_path: string, init?: RequestInit) => {
        sent = JSON.parse(String(init?.body));
        return createdScan;
      },
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
      />,
    );

    fireEvent.click(await screen.findByLabelText("DAST"));
    fireEvent.click(screen.getByRole("button", { name: "Scan 1 host" }));

    await waitFor(() => expect(sent.override).toEqual({ dast: true }));
    expect(sent.profile).toBe("safe");
    expect(saved).toHaveLength(0);
  });

  it("keeps a tweak as a new profile rather than redefining the one it came from", async () => {
    const saved: RequestInit[] = [];
    mockFetch({
      "/api/v1/engine": [nucleiEngine],
      "/api/v1/profile": (_path: string, init?: RequestInit) => {
        if (init?.method !== "POST") return [safeProfile];
        saved.push(init);
        return { ...safeProfile, name: "app-deep", config: { dast: true } };
      },
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
      />,
    );

    // The control only exists once there is something to keep.
    expect(screen.queryByLabelText("New scan profile name")).toBeNull();
    fireEvent.click(await screen.findByLabelText("DAST"));

    fireEvent.change(screen.getByLabelText("New scan profile name"), {
      target: { value: "app-deep" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save as" }));

    await waitFor(() => expect(saved).toHaveLength(1));
    expect(JSON.parse(String(saved[0].body))).toEqual({
      kind: "scan",
      engine: "nuclei",
      name: "app-deep",
      config: { dast: true },
    });
  });

  it("shows how much the chosen profile would check before the scan starts", async () => {
    const fetchMock = mockFetch({
      "/api/v1/engine": [nucleiEngine],
      "/api/v1/profile": [safeProfile],
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
      />,
    );

    const summary = await screen.findByLabelText("Templates this scan will run");
    expect(summary).toHaveTextContent("4,314 templates");
    expect(summary).toHaveTextContent("96 critical");
    expect(summary).toHaveTextContent("803 high");

    // The count describes the scan engine's own configuration, so the preview
    // is asked for that engine and that profile's config.
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/template/preview",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ engine: "nuclei", config: safeProfile.config }),
      }),
    );
  });

  it("allows another scan to be queued while one is running", async () => {
    mockFetch({
      "/api/v1/engine": [nucleiEngine],
      "/api/v1/profile": [safeProfile, intrusiveProfile],
      "/api/v1/scan": createdScan,
    });
    const status = {
      ...createdScan,
      running: true,
      log: "running",
      output: [],
    };

    render(
      <ScanDialog
        open
        onClose={vi.fn()}
        rows={rows}
        savedHosts={rows.map((row) => row.host)}
        selectedHosts={["api.example.com"]}
        status={status}
        onStatus={vi.fn()}
        editableProfile
      />,
    );

    const profile = await screen.findByRole("combobox", { name: "Profile" });
    expect(profile).toBeEnabled();
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Queue scan 1 host" }),
      ).toBeEnabled(),
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
            "discovery-profile": ["default"],
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

    const authorisation = await screen.findByText(
      /prod\/public or unsaved host/,
    );
    expect(screen.getByRole("button", { name: "Scan 1 host" })).toBeDisabled();

    // Scoped to the authorisation banner: the profile form has checkboxes of
    // its own, and none of them authorise anything.
    fireEvent.click(
      within(authorisation.closest("label") as HTMLElement).getByRole(
        "checkbox",
      ),
    );
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
            "discovery-profile": ["default"],
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

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Scan 1 host" })).toBeEnabled(),
    );
    expect(screen.queryByText(/prod\/public or unsaved host/)).toBeNull();
  });

  it("allows discovery to auto-inventory an unsaved explicit host", async () => {
    const result: Discover = {
      id: "discover-new",
      chain: "explicit",
      profiles: { naabu: "default", httpx: "default" },
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
          body: JSON.stringify({
            host: ["api.example.com"],
            profile: ["default"],
          }),
        }),
      ),
    );
  });

  it("rescans saved hosts via discovery instead of a scan engine", async () => {
    const result: Discover = {
      _id: "discover-1",
      id: "discover-1",
      chain: "targeted",
      profiles: { naabu: "default", httpx: "default" },
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
          body: JSON.stringify({
            host: ["api.example.com"],
            profile: ["default"],
          }),
        }),
      ),
    );
    await screen.findByText("0 hosts probed");
  });

  it("sends the pre-scan sweep the discovery profile chosen for that engine", async () => {
    const fetchMock = mockFetch({
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
        selectedHosts={["api.example.com"]}
        status={null}
        onStatus={vi.fn()}
      />,
    );

    await screen.findByText("safe");
    const editProfiles = screen.getByRole("button", { name: "Edit profiles" });
    await waitFor(() => expect(editProfiles).toBeEnabled());
    fireEvent.click(editProfiles);
    fireEvent.change(await screen.findByLabelText("Naabu profile"), {
      target: { value: "full-ports" },
    });
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
            "discovery-profile": ["default", "naabu=full-ports"],
            confirm: false,
            wait: false,
          }),
        }),
      ),
    );
  });
});
