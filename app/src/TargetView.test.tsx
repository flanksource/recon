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
import { TargetView } from "./TargetView";
import * as api from "./api";
import type { Profile, Target } from "./types";

const target: Target = {
  $schema: "../target.schema.json",
  version: 2,
  id: "api.example.com",
  _id: "api.example.com",
  host: "api.example.com",
  class: "prod",
  profiles: ["scan:nuclei:safe"],
  tags: ["api"],
  observed: { last_seen: "2026-08-09T08:00:00.000Z" },
  http: {
    status_code: 200,
    title: "API",
    response_time: "125ms",
    known_paths: ["/", "/login"],
    login_methods: ["Basic", "Web login"],
  },
  network: { ip: "192.0.2.10", open_ports: [443, 8443] },
  tech: { names: ["Go"] },
};

const schema = {
  type: "object" as const,
  required: ["host", "class", "profiles", "tags"],
  properties: {
    host: { type: "string" as const, readOnly: true },
    class: { type: "string" as const, enum: ["prod", "non-prod"] },
    profiles: { type: "array" as const, items: { type: "string" as const } },
    tags: { type: "array" as const, items: { type: "string" as const } },
    reason: { type: "string" as const },
    observed: { type: "object" as const, readOnly: true },
    http: { type: "object" as const, readOnly: true },
  },
};

const providerTargetSchema = {
  ...schema,
  required: ["id", "kind", "provider", "credentialMode", "class", "profiles", "tags"],
  properties: {
    ...schema.properties,
    id: { type: "string" as const, readOnly: true },
    kind: { type: "string" as const, readOnly: true },
    provider: { type: "string" as const, readOnly: true },
    credentialMode: {
      type: "string" as const,
      title: "Credential mode",
      enum: ["ambient", "configured"],
    },
    arguments: { type: "object" as const },
  },
};

const profiles: Profile[] = [
  {
    _id: "nuclei:full",
    kind: "scan",
    engine: "nuclei",
    name: "full",
    config: { dast: true, timeout: 10, severity: ["critical", "high"] },
  },
  {
    _id: "nuclei:safe",
    kind: "scan",
    engine: "nuclei",
    name: "safe",
    config: { timeout: 10, severity: ["critical", "high"] },
  },
  {
    _id: "scan:prowler:cis",
    kind: "scan",
    engine: "prowler",
    name: "cis",
    config: { provider: "gcp", compliance: ["cis_5.0_gcp"] },
  },
];

const engines = [
  {
    _id: "nuclei",
    name: "nuclei",
    kind: "scan",
    title: "Nuclei",
    binary: "nuclei",
    installed: true,
    managed: false,
    options: {
      variants: [
        {
          id: "default",
          title: "Nuclei",
          schema: {
            type: "object",
            "x-sections": [{ id: "performance", title: "Performance" }],
            "x-order": ["timeout"],
            properties: {
              timeout: {
                type: "integer",
                title: "Request timeout",
                "x-section": "performance",
              },
            },
          },
        },
      ],
    },
  },
  {
    _id: "prowler",
    name: "prowler",
    kind: "scan",
    title: "Prowler",
    binary: "prowler",
    installed: true,
    managed: false,
    options: {
      discriminator: "provider",
      variants: [
        {
          id: "gcp",
          title: "Google Cloud",
          schema: {
            type: "object",
            required: ["provider"],
            "x-sections": [{ id: "checks", title: "Checks" }],
            "x-order": ["provider", "compliance"],
            properties: {
              provider: {
                type: "string",
                const: "gcp",
                readOnly: true,
                "x-section": "checks",
              },
              compliance: {
                type: "array",
                items: { type: "string" },
                "x-section": "checks",
              },
            },
          },
          contextSchema: {
            type: "object",
            "x-sections": [
              { id: "scope", title: "Scope", description: "Projects to audit." },
            ],
            "x-order": ["project-ids"],
            properties: {
              "project-ids": {
                type: "array",
                title: "Project IDs",
                items: { type: "string" },
                "x-section": "scope",
              },
            },
          },
        },
      ],
    },
  },
];

const providerTarget: Target = {
  $schema: "../target.schema.json",
  version: 2,
  id: "gcp-production",
  kind: "provider-context",
  provider: "gcp",
  credentialMode: "ambient",
  arguments: { "project-ids": ["workload-prod-eu-02"] },
  class: "prod",
  profiles: ["scan:prowler:cis"],
  tags: ["cloud"],
};

// The scan dialog also loads the discovery catalog, because every run sweeps
// before it scans.
const discoveryEngines = [
  {
    _id: "naabu",
    name: "naabu",
    kind: "discovery",
    title: "Naabu",
    binary: "naabu",
    installed: true,
    managed: true,
    options: {
      variants: [
        {
          id: "default",
          title: "Naabu",
          schema: {
            type: "object",
            "x-sections": [{ id: "ports", title: "Ports" }],
            "x-order": ["top-ports"],
            properties: {
              "top-ports": {
                type: "string",
                title: "Top ports",
                "x-section": "ports",
              },
            },
          },
        },
      ],
    },
  },
];

const discoveryProfiles: Profile[] = [
  {
    _id: "discovery:naabu:default",
    kind: "discovery",
    engine: "naabu",
    name: "default",
    config: { "top-ports": "100" },
  },
];

const discoverResult = {
  _id: "sweep-1",
  id: "sweep-1",
  chain: "targeted",
  profiles: { naabu: "default", httpx: "default" },
  input: { hosts: ["api.example.com"] },
  ranAt: "2026-08-09T08:00:00",
  durationMs: 10,
  failed: false,
  hosts: [],
  log: "",
};

const idleStatus = {
  id: "scan-idle",
  _id: "scan-idle",
  phase: "idle" as const,
  running: false,
  log: "",
  output: [],
  name: "",
  engine: "",
  profile: null,
  selector: {},
  selectorLabel: "",
  endpointCount: 0,
  startedAt: null,
  finishedAt: null,
  command: null,
  exitCode: null,
  error: null,
  findings: [],
  severities: {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    unknown: 0,
  },
  stats: null,
  hosts: [],
};

function runningStatus(profile: string) {
  return {
    ...idleStatus,
    id: "scan-1",
    _id: "scan-1",
    phase: "running" as const,
    running: true,
    profile,
    hosts: [target.host],
    startedAt: "2026-08-09T08:00:00.000Z",
    log: ">>> httpx discovery rescan of 1 host\n",
    command:
      profile === "discovery"
        ? ["httpx", "-config", "config/discovery.httpx.yaml"]
        : ["nuclei", "-config", ".gen/app-scan-profile.yaml"],
    findings: [],
    output: [
      {
        sequence: 1,
        timestamp: "2026-08-09T08:00:00.000Z",
        stream: "system" as const,
        text: `>>> ${profile} scan of 1 host\n`,
      },
    ],
  };
}

vi.mock("./api", () => ({
  fetchTarget: vi.fn(),
  fetchTargetSchema: vi.fn(),
  saveTarget: vi.fn(),
  fetchProfiles: vi.fn(),
  fetchEngines: vi.fn(),
  fetchScanStatus: vi.fn(),
  startScan: vi.fn(),
  runDiscovery: vi.fn(),
  saveProfile: vi.fn(),
  cancelScan: vi.fn(),
}));

describe("TargetView", () => {
  afterEach(() => {
    cleanup();
    // restoreAllMocks does not reset the call history of a vi.fn() created in a
    // module factory, so without this a "was not called" assertion can pass on
    // the previous test's calls.
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  function mockTargetApi() {
    vi.mocked(api.fetchTarget).mockResolvedValue(target);
    vi.mocked(api.fetchTargetSchema).mockResolvedValue(schema);
    vi.mocked(api.saveTarget).mockResolvedValue(target);
    vi.mocked(api.fetchProfiles).mockImplementation(
      async (params) =>
        (params?.kind === "discovery" ? discoveryProfiles : profiles) as never,
    );
    vi.mocked(api.fetchEngines).mockImplementation(
      async (kind) => (kind === "discovery" ? discoveryEngines : engines) as never,
    );
    vi.mocked(api.fetchScanStatus).mockResolvedValue(idleStatus as never);
    vi.mocked(api.startScan).mockImplementation(
      async (args) => runningStatus(args.profile) as never,
    );
    vi.mocked(api.runDiscovery).mockResolvedValue(discoverResult as never);
    vi.mocked(api.saveProfile).mockResolvedValue(profiles[1] as never);
    vi.mocked(api.cancelScan).mockResolvedValue(idleStatus as never);
  }

  it("opens as a read-only preview and switches to the curated schema editor", async () => {
    mockTargetApi();

    render(<TargetView id="api.example.com" onBack={vi.fn()} />);

    expect(
      await screen.findByRole("heading", { name: "api.example.com" }),
    ).toBeInTheDocument();
    expect(screen.getByText("192.0.2.10")).toBeInTheDocument();
    expect(screen.getByText("125ms")).toBeInTheDocument();
    expect(screen.getByText("443, 8443")).toBeInTheDocument();
    expect(screen.getByText("/, /login")).toBeInTheDocument();
    expect(screen.getByText("Basic, Web login")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Save changes" }),
    ).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Edit target" }));

    expect(
      screen.getByRole("button", { name: "Save changes" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("textbox", { name: "Host" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("textbox", { name: "reason" }),
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(
      screen.queryByRole("button", { name: "Save changes" }),
    ).not.toBeInTheDocument();
  });

  // Discovery is no longer a scan profile: re-probing a host is a separate
  // operation, so this must not reach startScan at all.
  it("re-probes the current target through discovery, not through a scan", async () => {
    mockTargetApi();
    render(<TargetView id="api.example.com" onBack={vi.fn()} />);

    fireEvent.click(
      await screen.findByRole("button", { name: "Rescan discovery" }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Rescan 1 host" }),
    );

    await waitFor(() =>
      expect(api.runDiscovery).toHaveBeenCalledWith({
        host: [target.host],
        profile: ["default"],
      }),
    );
    expect(api.startScan).not.toHaveBeenCalled();
  });

  // What this view owns is which mode the dialog opens in. The payload a scan
  // is started with is ScanDialog's contract and is asserted there.
  it("opens the dialog in scan mode, offering the engine's stored profiles", async () => {
    mockTargetApi();
    render(<TargetView id="api.example.com" onBack={vi.fn()} />);

    // The button stays disabled until the scan profiles load, so clicking any
    // earlier is a no-op that leaves the dialog closed.
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Run scan" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Run scan" }));

    // "Scan", not "Rescan": the same dialog re-probes through discovery in its
    // other mode, and the two must not be wired to the same button.
    expect(
      await screen.findByRole("button", { name: "Scan 1 host" }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Rescan 1 host" })).toBeNull();

    // The target is prod, but `safe` is not intrusive and the server would run
    // it without complaint, so the dialog does not ask for confirmation either.
    expect(screen.queryByRole("checkbox", { name: /I authorise/ })).toBeNull();
    expect(api.runDiscovery).not.toHaveBeenCalled();
  });

  it("edits provider-context arguments through the selected provider schema", async () => {
    mockTargetApi();
    vi.mocked(api.fetchTarget).mockResolvedValue(providerTarget);
    vi.mocked(api.fetchTargetSchema).mockResolvedValue(providerTargetSchema);
    vi.mocked(api.saveTarget).mockImplementation(async (_id, update) => ({
      ...providerTarget,
      ...update,
      credentials:
        update.credentials === null
          ? undefined
          : update.credentials ?? providerTarget.credentials,
    }));

    render(<TargetView id="gcp-production" onBack={vi.fn()} />);
    expect(await screen.findByText(/workload-prod-eu-02/)).toBeInTheDocument();
    expect(screen.getByText("gcp")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Rescan discovery" }),
    ).toBeDisabled();

    fireEvent.click(screen.getByRole("button", { name: "Edit target" }));
    expect(await screen.findByText("Projects to audit.")).toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: "Provider" })).toBeNull();
    const projectInput = screen.getByRole("combobox", { name: "Project IDs" });
    fireEvent.change(projectInput, { target: { value: "flanksource-prod" } });
    fireEvent.keyDown(projectInput, { key: "Enter" });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() =>
      expect(api.saveTarget).toHaveBeenCalledWith(
        "gcp-production",
        expect.objectContaining({
          class: "prod",
          profiles: ["scan:prowler:cis"],
          credentialMode: "ambient",
          arguments: {
            "project-ids": ["workload-prod-eu-02", "flanksource-prod"],
          },
        }),
      ),
    );
    const update = vi.mocked(api.saveTarget).mock.calls[0][1];
    expect(update).not.toHaveProperty("id");
    expect(update).not.toHaveProperty("kind");
    expect(update).not.toHaveProperty("provider");

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Run scan" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Run scan" }));
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Scan 1 target" }),
      ).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Scan 1 target" }));
    await waitFor(() =>
      expect(api.startScan).toHaveBeenCalledWith(
        expect.objectContaining({
          target: { id: ["gcp-production"] },
          engine: "prowler",
          profile: "cis",
        }),
      ),
    );
  });
});
