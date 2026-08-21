// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TemplatesView } from "./TemplatesView";
import type { Engine, Profile, Template } from "./types";

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

const templates: Template[] = [
  {
    _id: "nuclei:http/misconfiguration/kubernetes-kubelet.yaml",
    id: "kubelet-metrics",
    name: "Kubelet Metrics Exposure",
    engine: "nuclei",
    severity: "high",
    type: "http",
    tags: ["k8s", "kubelet", "exposure"],
    authors: ["pdteam"],
    path: "http/misconfiguration/kubernetes-kubelet.yaml",
    maxRequests: 2,
    description: "The kubelet read-only port serves metrics without auth.",
    requires: ["self-contained"],
  },
  {
    _id: "nuclei:dns/caa-fingerprint.yaml",
    id: "caa-fingerprint",
    name: "CAA Record Fingerprint",
    engine: "nuclei",
    severity: "info",
    type: "dns",
    tags: ["dns", "caa"],
    authors: ["pdteam"],
    path: "dns/caa-fingerprint.yaml",
    maxRequests: 1,
  },
];

const prowlerTemplate: Template = {
  _id: "prowler:gcp:iam_1",
  id: "iam_1",
  name: "Ensure corporate login credentials are used",
  engine: "prowler",
  provider: "gcp",
  severity: "high",
  type: "iam",
  tags: ["provider:gcp", "category:identity-access"],
  authors: [],
  path: "prowler/providers/gcp/services/iam/iam_1/iam_1.py",
  description: "Checks the configured identity policy.",
  risk: "Personal credentials can outlive employment.",
  resourceType: "iam.googleapis.com/ServiceAccount",
  remediation: "Use dedicated audit service accounts.",
  metadata: {
    aliases: ["gcp_iam_1"],
    subService: "service-accounts",
    resourceGroup: "IAM",
    resourceIdTemplate: "projects/{project}/serviceAccounts/{email}",
    categories: ["identity-access"],
    checkTypes: ["preventive", "detective"],
    remediation: {
      text: "Use dedicated audit service accounts.",
      url: "https://cloud.google.com/iam/docs/service-accounts",
      code: { gcloud: "gcloud iam service-accounts create prowler-audit" },
    },
    dependsOn: ["iam_0"],
    relatedTo: ["iam_2"],
    notes: "Review inherited organization policy before changing access.",
  },
};

const profiles: Profile[] = [
  {
    _id: "scan:nuclei:k8s",
    kind: "scan",
    engine: "nuclei",
    name: "k8s",
    config: { tags: ["k8s"] },
  },
  {
    _id: "scan:nuclei:dns",
    kind: "scan",
    engine: "nuclei",
    name: "dns",
    config: { type: ["dns"] },
  },
  {
    _id: "scan:prowler:gcp-cis-5-0-gcp",
    kind: "scan",
    engine: "prowler",
    name: "gcp-cis-5-0-gcp",
    config: { provider: "gcp", compliance: ["cis_5.0_gcp"] },
  },
];

const engines: Engine[] = [
  {
    name: "nuclei",
    kind: "scan",
    title: "Nuclei",
    binary: "nuclei",
    installed: true,
    managed: true,
    templates: { count: 13_000, itemLabel: "template", profileLabel: "profile" },
    options: { variants: [] },
  },
  {
    name: "prowler",
    kind: "scan",
    title: "Prowler",
    binary: "prowler",
    installed: true,
    managed: false,
    templates: { count: 1_586, itemLabel: "check", profileLabel: "compliance framework" },
    options: { variants: [] },
  },
  {
    name: "inspec",
    kind: "scan",
    title: "InSpec",
    binary: "inspec",
    installed: true,
    managed: true,
    options: { variants: [] },
  },
];

const vocabulary = {
  filters: {
    severity: { label: "Severity", options: { high: "high", info: "info" } },
    type: { label: "Service / protocol", options: { http: "http", dns: "dns" } },
    // Excluded by the view: a profile Select already owns this value, and two
    // controls over one value disagree the moment either is used.
    profile: { label: "Profile", options: { k8s: "k8s" } },
  },
};

// Prefix-matched in declaration order: overrides come first so a longer prefix
// wins, and the lookup route precedes the listing route that shares its path.
function mockFetch(handlers: Record<string, unknown> = {}) {
  const defaults: Record<string, unknown> = {
    "/api/v1/template?__lookup": vocabulary,
    "/api/v1/engine": engines,
    "/api/v1/profile": profiles,
    "/api/v1/template": templates,
  };
  const routes = [
    ...Object.entries(handlers),
    ...Object.entries(defaults).filter(([prefix]) => !(prefix in handlers)),
  ];
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = typeof input === "string" ? input : (input as Request).url;
    const path = url.replace(/^https?:\/\/[^/]+/, "");
    const match = routes.find(([prefix]) => path.startsWith(prefix));
    if (!match) throw new Error(`unexpected fetch: ${path}`);
    return jsonResponse(match[1]);
  });
}

function templateRequests(fetchMock: ReturnType<typeof mockFetch>): string[] {
  return fetchMock.mock.calls
    .map(([input]) => String(input))
    .filter((url) => url.startsWith("/api/v1/template") && !url.includes("__lookup"));
}

// DataTable resolves its theme from the colour-scheme media query, which jsdom
// does not implement.
function stubMatchMedia() {
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    value: vi.fn().mockReturnValue({
      matches: false,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    }),
  });
}

describe("TemplatesView", () => {
  beforeEach(stubMatchMedia);

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("lists what a scan could run, with its severity, protocol and cost", async () => {
    mockFetch();

    render(<TemplatesView />);

    expect(await screen.findByText("Kubelet Metrics Exposure")).toBeInTheDocument();
    const row = screen.getByText("Kubelet Metrics Exposure").closest("tr");
    expect(row).toHaveTextContent("high");
    expect(row).toHaveTextContent("http");
    expect(row).toHaveTextContent("kubelet-metrics");
    expect(row).toHaveTextContent("http/misconfiguration/kubernetes-kubelet.yaml");
    expect(screen.getByText("2 catalog items shown")).toBeInTheDocument();
  });

  it("asks the server for a bounded page rather than the whole catalogue", async () => {
    const fetchMock = mockFetch();

    render(<TemplatesView />);

    await waitFor(() => expect(templateRequests(fetchMock)).not.toHaveLength(0));
    expect(templateRequests(fetchMock)[0]).toContain("limit=500");
  });

  it("shows Prowler provider/resource columns and its complete check metadata", async () => {
    mockFetch({ "/api/v1/template?limit": [prowlerTemplate] });

    render(<TemplatesView />);

    const check = await screen.findByText("Ensure corporate login credentials are used");
    const row = check.closest("tr");
    expect(row).toHaveTextContent("gcp");
    expect(row).toHaveTextContent("iam.googleapis.com/ServiceAccount");
    expect(screen.getByText("Provider")).toBeInTheDocument();
    expect(screen.getByText("Resource")).toBeInTheDocument();

    fireEvent.click(check);
    expect(await screen.findByText("Personal credentials can outlive employment.")).toBeInTheDocument();
    expect(screen.getByText("gcp_iam_1")).toBeInTheDocument();
    expect(screen.getByText("service-accounts")).toBeInTheDocument();
    expect(screen.getByText("projects/{project}/serviceAccounts/{email}")).toBeInTheDocument();
    expect(screen.getByText("Categories")).toBeInTheDocument();
    expect(screen.getAllByText("identity-access")).toHaveLength(2);
    expect(screen.getByText("preventive, detective")).toBeInTheDocument();
    expect(screen.getByText("gcloud iam service-accounts create prowler-audit")).toBeInTheDocument();
    expect(screen.getByText("iam_0")).toBeInTheDocument();
    expect(screen.getByText("iam_2")).toBeInTheDocument();
    expect(
      screen.getByText("Review inherited organization policy before changing access."),
    ).toBeInTheDocument();
  });

  it("scopes Prowler checks and compliance frameworks as one catalogue", async () => {
    const fetchMock = mockFetch({ "/api/v1/template?engine=prowler": [prowlerTemplate] });

    render(<TemplatesView engine="prowler" />);

    expect(await screen.findByLabelText("Catalogue")).toHaveDisplayValue("Prowler checks");
    expect(screen.getByLabelText("Compliance framework")).toHaveDisplayValue(
      "All compliance frameworks",
    );
    expect(
      screen.getByRole("option", { name: "gcp-cis-5-0-gcp (gcp)" }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "k8s (nuclei)" })).not.toBeInTheDocument();
    expect(await screen.findByRole("columnheader", { name: /Check/ })).toBeInTheDocument();
    expect(screen.getByText("1 check shown")).toBeInTheDocument();
    expect(templateRequests(fetchMock)[0]).toContain("engine=prowler");
  });

  it("uses engine catalogue labels for future rule and policy types", async () => {
    const customEngine: Engine = {
      name: "custom",
      kind: "scan",
      title: "Custom",
      binary: "custom",
      installed: true,
      managed: false,
      templates: { count: 1, itemLabel: "rule", profileLabel: "policy" },
      options: { variants: [] },
    };
    mockFetch({ "/api/v1/engine": [...engines, customEngine] });

    render(<TemplatesView />);

    expect(await screen.findByRole("option", { name: "Custom rules" })).toBeInTheDocument();
  });

  it("reports catalogue selection upward so the route can persist it", async () => {
    const onSelectEngine = vi.fn();
    mockFetch();

    render(<TemplatesView onSelectEngine={onSelectEngine} />);

    await screen.findByRole("option", { name: "Prowler checks" });
    fireEvent.change(screen.getByLabelText("Catalogue"), { target: { value: "prowler" } });

    expect(onSelectEngine).toHaveBeenCalledWith("prowler");
  });

  it("narrows the listing to a profile server-side, not by hiding rows", async () => {
    // The profile decides which templates exist for the question being asked, so
    // it has to reach the query — filtering the loaded page would silently drop
    // everything past the cap.
    const fetchMock = mockFetch({ "/api/v1/template?profile": [templates[0]] });

    render(<TemplatesView profile="scan:nuclei:k8s" />);

    await waitFor(() => expect(templateRequests(fetchMock)).not.toHaveLength(0));
    expect(templateRequests(fetchMock)[0]).toContain("profile=scan%3Anuclei%3Ak8s");
    expect(await screen.findByText("Kubelet Metrics Exposure")).toBeInTheDocument();
  });

  it("reports the profile selection upwards rather than owning it", async () => {
    // The profile lives in the route (/templates/:profile), so the Select tells
    // the router and the view re-renders from the new prop.
    const onSelectProfile = vi.fn();
    mockFetch();

    render(<TemplatesView onSelectProfile={onSelectProfile} />);

    await waitFor(() =>
      expect(screen.getByRole("option", { name: "dns (nuclei)" })).toBeInTheDocument(),
    );
    fireEvent.change(screen.getByLabelText("Profile"), {
      target: { value: "scan:nuclei:dns" },
    });

    expect(onSelectProfile).toHaveBeenCalledWith("scan:nuclei:dns");
  });

  it("offers every scan profile the server has, not a hardcoded pair", async () => {
    mockFetch();

    render(<TemplatesView />);

    await waitFor(() =>
      expect(
        screen.getByRole("option", { name: "k8s (nuclei)" }),
      ).toBeInTheDocument(),
    );
    expect(screen.getByRole("option", { name: "dns (nuclei)" })).toBeInTheDocument();
  });

  it("says a profile selects nothing instead of looking like a failed load", async () => {
    mockFetch({ "/api/v1/template?": [] });

    render(<TemplatesView profile="scan:nuclei:k8s" />);

    expect(
      await screen.findByText("This profile selects no templates."),
    ).toBeInTheDocument();
  });

  it("surfaces a failed listing rather than showing an empty catalogue", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const path = String(input);
      if (path.startsWith("/api/v1/template") && !path.includes("__lookup")) {
        return new Response(JSON.stringify({ error: "nuclei templates are not installed" }), {
          status: 503,
          headers: { "content-type": "application/json" },
        });
      }
      if (path.startsWith("/api/v1/profile")) return jsonResponse(profiles);
      if (path.startsWith("/api/v1/engine")) return jsonResponse(engines);
      return jsonResponse(vocabulary);
    });

    render(<TemplatesView />);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "nuclei templates are not installed",
    );
  });
});
