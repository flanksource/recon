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

const target = {
  $schema: "../target.schema.json" as const,
  version: 1 as const,
  host: "api.example.com",
  class: "prod" as const,
  profiles: ["safe"],
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

const profiles = [
  {
    id: "nuclei:full",
    engine: "nuclei" as const,
    name: "full",
    filename: "full.yaml",
    config: { dast: true, timeout: 10, severity: ["critical", "high"] },
  },
  {
    id: "nuclei:safe",
    engine: "nuclei" as const,
    name: "safe",
    filename: "safe.yaml",
    config: { timeout: 10, severity: ["critical", "high"] },
  },
];

describe("TargetView", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  function mockTargetApi() {
    return vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (input, init) => {
        const path = String(input);
        if (path === "/api/inventory/api.example.com") {
          return new Response(JSON.stringify(target), { status: 200 });
        }
        if (path === "/api/inventory/schema/target") {
          return new Response(JSON.stringify(schema), { status: 200 });
        }
        if (path === "/api/profiles") {
          return new Response(JSON.stringify({ profiles }), { status: 200 });
        }
        if (path === "/api/scan" && init?.method === "POST") {
          const request = JSON.parse(String(init.body)) as {
            profile: string;
          };
          return new Response(
            JSON.stringify({
              phase: "running",
              profile: request.profile,
              group: "prod",
              hosts: [target.host],
              file: null,
              startedAt: "2026-08-09T08:00:00.000Z",
              finishedAt: null,
              stats: null,
              findings: [],
              log: ">>> httpx discovery rescan of 1 host\n",
              error: null,
              command:
                request.profile === "discovery"
                  ? ["httpx", "-config", "config/discovery.httpx.yaml"]
                  : ["nuclei", "-config", ".gen/app-scan-profile.yaml"],
              exitCode: null,
              observations: null,
              output: [
                {
                  sequence: 1,
                  timestamp: "2026-08-09T08:00:00.000Z",
                  stream: "system",
                  text: `>>> ${request.profile} scan of 1 host\n`,
                },
              ],
            }),
            { status: 200 },
          );
        }
        if (path === "/api/scan") {
          return new Response(
            JSON.stringify({
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
            }),
            { status: 200 },
          );
        }
        throw new Error(`unexpected request: ${path}`);
      });
  }

  it("opens as a read-only preview and switches to the curated schema editor", async () => {
    mockTargetApi();

    render(<TargetView host="api.example.com" onBack={vi.fn()} />);

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

  it("rescans the current target with the discovery profile", async () => {
    const fetchMock = mockTargetApi();
    render(<TargetView host="api.example.com" onBack={vi.fn()} />);

    fireEvent.click(
      await screen.findByRole("button", { name: "Rescan discovery" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Rescan 1 host" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/scan",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            hosts: [target.host],
            profile: "discovery",
            confirm: false,
          }),
        }),
      ),
    );
  });

  it("runs Nuclei from selected profile defaults with run-only tweaks", async () => {
    const fetchMock = mockTargetApi();
    render(<TargetView host="api.example.com" onBack={vi.fn()} />);

    fireEvent.click(
      await screen.findByRole("button", { name: "Run Nuclei scan" }),
    );
    fireEvent.change(screen.getByLabelText("Profile defaults"), {
      target: { value: "full" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Performance" }));
    fireEvent.change(
      screen.getByRole("spinbutton", { name: "Request timeout" }),
      { target: { value: "20" } },
    );
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /I authorise this scan/,
      }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Scan 1 host" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/scan",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            hosts: [target.host],
            profile: "full",
            confirm: true,
            config: {
              dast: true,
              timeout: 20,
              severity: ["critical", "high"],
            },
          }),
        }),
      ),
    );
  });
});
