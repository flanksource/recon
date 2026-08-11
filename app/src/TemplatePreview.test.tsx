// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { TemplatePreviewPanel, TemplateSummary, usePreview } from "./TemplatePreview";
import type { TemplatePreview } from "./types";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const preview: TemplatePreview = {
  engine: "nuclei",
  total: 152,
  bySeverity: { critical: 4, high: 21, medium: 60, info: 67 },
  byType: { http: 140, ssl: 12 },
  byTag: [
    { tag: "kubernetes", count: 121 },
    { tag: "k8s", count: 77 },
  ],
  maxRequests: 318,
  templates: [],
  truncated: true,
};

// A component is needed to exercise the hook, since a hook cannot be rendered
// on its own and what matters is what reaches the panel.
function Harness({ config }: { config: Record<string, unknown> | null }) {
  const { preview: result, error, loading } = usePreview(config);
  return <TemplatePreviewPanel preview={result} error={error} loading={loading} />;
}

describe("TemplateSummary", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("leads with the number of templates and the severities that matter", () => {
    render(<TemplateSummary preview={preview} error={null} loading={false} />);

    const summary = screen.getByLabelText("Templates this scan will run");
    expect(summary).toHaveTextContent("152");
    expect(summary).toHaveTextContent("4 critical");
    expect(summary).toHaveTextContent("21 high");
  });

  it("says outright when a scan would check nothing", () => {
    // A profile that selects no templates reports a clean scan, which reads as
    // good news. It is the one outcome worth spelling out.
    render(
      <TemplateSummary
        preview={{ ...preview, total: 0, bySeverity: {} }}
        error={null}
        loading={false}
      />,
    );

    expect(screen.getByLabelText("Templates this scan will run")).toHaveTextContent(
      "would check nothing",
    );
  });

  it("shows the engine's own complaint about an invalid configuration", () => {
    render(
      <TemplateSummary
        preview={null}
        error="automatic-scan cannot be combined with dast"
        loading={false}
      />,
    );

    expect(screen.getByRole("alert")).toHaveTextContent(
      "automatic-scan cannot be combined with dast",
    );
  });
});

describe("TemplatePreviewPanel", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("breaks the selection down by severity, protocol and tag", () => {
    const { container } = render(
      <TemplatePreviewPanel preview={preview} error={null} loading={false} />,
    );

    expect(screen.getByLabelText("Templates selected")).toHaveTextContent("152");
    // One assertion over the whole panel: each part is only meaningful next to
    // the others — 4 critical out of 152, over http, mostly kubernetes.
    expect(container.textContent).toContain("up to 318 requests per target");
    expect(container.textContent).toContain("critical4");
    expect(container.textContent).toContain("high21");
    expect(container.textContent).toContain("http 140");
    expect(container.textContent).toContain("ssl 12");
    expect(container.textContent).toContain("kubernetes 121");
  });

  it("orders severities worst-first rather than by count", () => {
    // The panel is read to judge blast radius, so 4 critical has to come before
    // 67 info even though info dominates the selection.
    const { container } = render(
      <TemplatePreviewPanel preview={preview} error={null} loading={false} />,
    );

    const text = container.textContent ?? "";
    expect(text.indexOf("critical")).toBeLessThan(text.indexOf("high"));
    expect(text.indexOf("high")).toBeLessThan(text.indexOf("info"));
  });

  it("warns when the configuration selects nothing", () => {
    render(
      <TemplatePreviewPanel
        preview={{ ...preview, total: 0, bySeverity: {}, byType: {}, byTag: [] }}
        error={null}
        loading={false}
      />,
    );

    expect(screen.getByRole("alert")).toHaveTextContent("selects no templates");
  });

  it("reports the caveats rather than presenting the count as exact", () => {
    render(
      <TemplatePreviewPanel
        preview={{ ...preview, caveats: ["template-condition is not evaluated"] }}
        error={null}
        loading={false}
      />,
    );

    expect(screen.getByText("template-condition is not evaluated")).toBeInTheDocument();
  });
});

describe("usePreview", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("previews the draft configuration rather than a saved profile", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(jsonResponse(preview));

    render(<Harness config={{ tags: ["kubernetes"] }} />);

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/template/preview",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ engine: "nuclei", config: { tags: ["kubernetes"] } }),
        }),
      ),
    );
    expect(await screen.findByLabelText("Templates selected")).toHaveTextContent("152");
  });

  it("asks for nothing until there is a configuration", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");

    render(<Harness config={null} />);

    await waitFor(() => expect(screen.getByText("No preview available.")).toBeInTheDocument());
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("surfaces a rejected configuration instead of showing a stale count", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({ error: "nuclei option \"rate-limitt\" has no mapping" }, 422),
    );

    render(<Harness config={{ "rate-limitt": 5 }} />);

    expect(await screen.findByRole("alert")).toHaveTextContent("has no mapping");
  });
});
