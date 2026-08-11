// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ProfilesView } from "./ProfilesView";
import type { Engine, Profile, TemplatePreview } from "./types";

const engines: Engine[] = [
  {
    _id: "scan:nuclei",
    name: "nuclei",
    kind: "scan",
    title: "Nuclei",
    binary: "nuclei",
    installed: true,
    managed: true,
    sections: [
      {
        id: "performance",
        title: "Performance",
        description: "Rate limiting and concurrency.",
        properties: {
          "rate-limit": {
            type: "integer",
            title: "Requests per second",
            minimum: 1,
            multipleOf: 1,
          },
        },
      },
    ],
  },
  {
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
        title: "Ports & targets",
        description: "Which ports and hosts to probe.",
        properties: {
          "top-ports": { type: "string", title: "Top ports" },
        },
      },
    ],
  },
];

const profiles: Profile[] = [
  {
    _id: "scan:nuclei:safe",
    kind: "scan",
    engine: "nuclei",
    name: "safe",
    config: { "rate-limit": 50, severity: ["critical", "high"] },
  },
  {
    _id: "discovery:naabu:discovery",
    kind: "discovery",
    engine: "naabu",
    name: "discovery",
    config: { "top-ports": "100", rate: 250 },
  },
];

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

const preview: TemplatePreview = {
  engine: "nuclei",
  total: 1452,
  bySeverity: { critical: 210, high: 1242 },
  byType: { http: 1452 },
  byTag: [{ tag: "kev", count: 640 }],
  maxRequests: 2900,
  templates: [],
  truncated: true,
};

// The scan profile panel previews its draft, so every render here issues a
// preview alongside the listing. Prefix matching keeps the two independent —
// with an ordered queue the debounced preview would consume a listing response.
function mockFetch(handlers: Record<string, unknown> = {}) {
  const routes: Record<string, unknown> = {
    ...handlers,
    "/api/template/preview": preview,
    "/api/v1/profile": profiles,
    "/api/v1/engine": engines,
  };
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const path = String(input).replace(/^https?:\/\/[^/]+/, "");
    const match = Object.entries(routes).find(([prefix]) => path.startsWith(prefix));
    if (!match) throw new Error(`unexpected fetch: ${path}`);
    return jsonResponse(match[1]);
  });
}

function previewBodies(fetchMock: ReturnType<typeof mockFetch>): unknown[] {
  return fetchMock.mock.calls
    .filter(([input]) => String(input) === "/api/template/preview")
    .map(([, init]) => JSON.parse(String((init as RequestInit).body)));
}

describe("ProfilesView", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("edits a selected profile through its schema and saves the complete config", async () => {
    const fetchMock = mockFetch();
    render(<ProfilesView />);

    fireEvent.click(
      await screen.findByRole("button", { name: /safe.*nuclei/i }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Performance" }));
    fireEvent.change(
      screen.getByRole("spinbutton", { name: "Requests per second" }),
      { target: { value: "75" } },
    );
    expect(screen.getByText("Unsaved changes")).toBeInTheDocument();

    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        ...profiles[0],
        config: { ...profiles[0].config, "rate-limit": 75 },
      }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Save profile" }));

    // Not `toHaveBeenLastCalledWith`: the debounced preview also fires, and
    // which of the two lands last is a race the assertion should not depend on.
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/v1/profile",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            kind: "scan",
            engine: "nuclei",
            name: "safe",
            config: { "rate-limit": 75, severity: ["critical", "high"] },
          }),
        }),
      ),
    );
  });

  it("previews the edit in front of you, not the profile last saved", async () => {
    // Without this the only way to learn what a tag change selected was to save
    // the profile and run a scan.
    const fetchMock = mockFetch();
    render(<ProfilesView />);

    fireEvent.click(await screen.findByRole("button", { name: /safe.*nuclei/i }));
    expect(await screen.findByLabelText("Templates selected")).toHaveTextContent("1,452");

    fireEvent.click(screen.getByRole("button", { name: "Performance" }));
    fireEvent.change(
      screen.getByRole("spinbutton", { name: "Requests per second" }),
      { target: { value: "75" } },
    );

    await waitFor(() =>
      expect(previewBodies(fetchMock)).toContainEqual({
        engine: "nuclei",
        config: { "rate-limit": 75, severity: ["critical", "high"] },
      }),
    );
  });

  it("does not offer a template preview for a discovery profile", async () => {
    // Discovery engines have no template catalogue, so a panel there would
    // either be empty or answer for the wrong engine.
    mockFetch();
    render(<ProfilesView />);

    fireEvent.click(await screen.findByRole("button", { name: /safe.*nuclei/i }));
    expect(screen.getByLabelText("Templates this profile runs")).toBeInTheDocument();

    fireEvent.click(await screen.findByRole("button", { name: /discovery.*naabu/i }));
    expect(screen.queryByLabelText("Templates this profile runs")).not.toBeInTheDocument();
  });

  it("exposes the Naabu discovery profile through its generated schema", async () => {
    mockFetch();
    render(<ProfilesView />);

    fireEvent.click(
      await screen.findByRole("button", { name: /discovery.*naabu/i }),
    );

    expect(screen.getByText("Naabu profile")).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Ports & targets" }),
    ).toBeInTheDocument();
  });
});
