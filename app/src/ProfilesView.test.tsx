// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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
    options: {
      variants: [
        {
          id: "default",
          title: "Nuclei",
          schema: {
            type: "object",
            "x-sections": [
              {
                id: "performance",
                title: "Performance",
                description: "Rate limiting and concurrency.",
              },
            ],
            "x-order": ["rate-limit"],
            properties: {
              "rate-limit": {
                type: "integer",
                title: "Requests per second",
                minimum: 1,
                multipleOf: 1,
                "x-section": "performance",
              },
            },
          },
        },
      ],
    },
  },
  {
    _id: "discovery:naabu",
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
            "x-sections": [
              {
                id: "ports",
                title: "Ports & targets",
                description: "Which ports and hosts to probe.",
              },
            ],
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
  {
    _id: "scan:prowler",
    name: "prowler",
    kind: "scan",
    title: "Prowler",
    binary: "prowler",
    installed: true,
    managed: true,
    options: {
      variants: [
        { id: "aws", title: "AWS", schema: {} },
        { id: "kubernetes", title: "Kubernetes", schema: {} },
      ],
    },
  },
  {
    _id: "scan:trivy",
    name: "trivy",
    kind: "scan",
    title: "Trivy",
    binary: "trivy",
    installed: true,
    managed: true,
    options: {
      variants: [
        { id: "container-image", title: "Container image", schema: {} },
        { id: "git-repository", title: "Git repository", schema: {} },
      ],
    },
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
  {
    _id: "scan:prowler:aws-cis-5-0-aws",
    kind: "scan",
    engine: "prowler",
    name: "aws-cis-5-0-aws",
    config: { provider: "aws", compliance: ["cis_5.0_aws"] },
  },
  {
    _id: "scan:prowler:kubernetes-cis-1-12-kubernetes",
    kind: "scan",
    engine: "prowler",
    name: "kubernetes-cis-1-12-kubernetes",
    config: { provider: "kubernetes", compliance: ["cis_1.12_kubernetes"] },
  },
  {
    _id: "scan:trivy:image-vulnerabilities",
    kind: "scan",
    engine: "trivy",
    name: "image-vulnerabilities",
    config: { provider: "container-image", scanners: ["vuln", "secret"] },
  },
  {
    _id: "scan:trivy:repository-secrets",
    kind: "scan",
    engine: "trivy",
    name: "repository-secrets",
    config: { provider: "git-repository", scanners: ["secret"] },
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

async function clickTreeItem(name: string) {
  const item = await screen.findByRole("treeitem", { name });
  const row = item.firstElementChild;
  if (!(row instanceof HTMLElement)) throw new Error(`tree item has no row: ${name}`);
  fireEvent.click(row);
}

async function expandTreeItem(name: string) {
  const item = await screen.findByRole("treeitem", { name });
  fireEvent.click(within(item).getByRole("button", { name: "Expand" }));
}

describe("ProfilesView", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("groups profiles by kind, engine, and provider with provider icons", async () => {
    mockFetch();
    render(<ProfilesView />);

    const tree = await screen.findByRole("tree", { name: "Profiles" });
    expect(
      within(tree).getByRole("treeitem", { name: "Discovery profiles" }),
    ).toHaveAttribute("aria-expanded", "true");
    expect(
      within(tree).getByRole("treeitem", { name: "Scan profiles" }),
    ).toHaveAttribute("aria-expanded", "true");
    expect(
      within(tree).getByRole("treeitem", { name: "Nuclei profiles" }),
    ).toHaveAttribute("aria-expanded", "true");
    const selectedProfile = within(tree).getByRole("treeitem", {
      name: "safe Nuclei profile",
    });
    expect(selectedProfile).toHaveAttribute("aria-selected", "true");
    expect(
      selectedProfile.querySelector("svg[aria-hidden='true']"),
    ).toBeInTheDocument();

    await expandTreeItem("Naabu profiles");
    expect(
      within(tree).getByRole("treeitem", { name: "discovery Naabu profile" }),
    ).toBeInTheDocument();

    await expandTreeItem("Prowler profiles");
    const prowler = within(tree).getByRole("treeitem", { name: "Prowler profiles" });
    expect(within(prowler).getByRole("img", { name: "Prowler" })).toBeInTheDocument();
    const aws = within(tree).getByRole("treeitem", { name: "AWS profiles" });
    const kubernetes = within(tree).getByRole("treeitem", {
      name: "Kubernetes profiles",
    });
    expect(within(aws).getByRole("img", { name: "AWS" })).toBeInTheDocument();
    expect(
      within(kubernetes).getByRole("img", { name: "Kubernetes" }),
    ).toBeInTheDocument();
    await expandTreeItem("AWS profiles");
    expect(
      within(tree).getByRole("treeitem", { name: "aws-cis-5-0-aws Prowler profile" }),
    ).toBeInTheDocument();

    await expandTreeItem("Trivy profiles");
    const trivy = within(tree).getByRole("treeitem", { name: "Trivy profiles" });
    expect(within(trivy).getByRole("img", { name: "Trivy" })).toBeInTheDocument();
    expect(
      within(tree).getByRole("treeitem", { name: "Container image profiles" }),
    ).toBeInTheDocument();
    expect(
      within(tree).getByRole("treeitem", { name: "Git repository profiles" }),
    ).toBeInTheDocument();
  });

  it("edits a selected profile through its schema and saves the complete config", async () => {
    const fetchMock = mockFetch();
    render(<ProfilesView />);

    await clickTreeItem("safe Nuclei profile");
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

    await clickTreeItem("safe Nuclei profile");
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

    await clickTreeItem("safe Nuclei profile");
    expect(screen.getByLabelText("Templates this profile runs")).toBeInTheDocument();

    await expandTreeItem("Naabu profiles");
    await clickTreeItem("discovery Naabu profile");
    expect(screen.queryByLabelText("Templates this profile runs")).not.toBeInTheDocument();
  });

  it("exposes the Naabu discovery profile through its generated schema", async () => {
    mockFetch();
    render(<ProfilesView />);

    await expandTreeItem("Naabu profiles");
    await clickTreeItem("discovery Naabu profile");

    expect(screen.getByText("Naabu profile")).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Ports & targets" }),
    ).toBeInTheDocument();
  });
});
