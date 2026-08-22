import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { buildScanReport } from "./scan-report-model";
import {
  BreakdownGrid,
  CoverageSection,
  DisclosureNotes,
  ReportHeader,
  RunTable,
} from "./scan-report-summary";
import type { ScanReportData } from "./scan-report-types";

const GENERATED_AT = "2026-03-14T09:30:00.000Z";

function payload(overrides: Partial<ScanReportData> = {}): ScanReportData {
  return {
    scan: {
      id: "scan-1",
      name: "nuclei-safe-214",
      engine: "nuclei",
      engineVersion: "3.4.10",
      profile: "scan:nuclei:safe",
      selectorLabel: "class prod",
      endpointCount: 86,
      phase: "done",
      startedAt: "2026-03-14T09:12:47.000Z",
      finishedAt: "2026-03-14T09:30:00.000Z",
      durationMs: 1_033_000,
      findings: 11,
      severities: { critical: 1, high: 2, medium: 4, low: 3, info: 1, unknown: 0 },
      hosts: ["api.example.test"],
    },
    findings: [],
    generatedAt: GENERATED_AT,
    ...overrides,
  };
}

const SCOPE = "Unauthenticated web scan of every internet-facing host in the production class.";

/**
 * The printed page is compiled against a different Tailwind build than the
 * playground preview, and its type scale only exists inside `@media print`.
 * These two guards are what keep a class copied off a screen surface from
 * silently rendering at the wrong size, or in the wrong colour, on paper.
 */
function expectPrintSafe(html: string) {
  expect(html).not.toMatch(/(?:text|leading)-\[\d+(?:\.\d+)?px\]/);
  expect(html).not.toMatch(
    /text-muted-foreground|border-border|bg-muted|bg-background|text-foreground|iconify-icon|ring-\d/,
  );
}

describe("ReportHeader", () => {
  it("leads with the worst severity the run found", () => {
    const model = buildScanReport(payload());
    const html = renderToStaticMarkup(<ReportHeader model={model} scope={SCOPE} />);

    expect(html).toContain("recon · Internal · nuclei-safe-214");
    expect(html).toContain("<h1");
    expect(html).toContain("Scan Findings Report");
    expect(html).toContain(SCOPE);
    expect(html).toContain("11 findings");
    expect(html).toContain("generated 2026-03-14 09:30:00Z");
    // critical > 0, so the eyebrow tile is the critical ramp, not the neutral one.
    expect(html).toContain("text-rose-700");
    expectPrintSafe(html);
  });

  it("falls back to the report glyph when the run found nothing", () => {
    const model = buildScanReport(
      payload({
        scan: {
          ...payload().scan,
          findings: 0,
          severities: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
        },
      }),
    );
    const html = renderToStaticMarkup(<ReportHeader model={model} />);

    expect(html).toContain("text-blue-700");
    expect(html).not.toContain("text-rose-700");
  });

  it("prints no lede when the run was given no scope", () => {
    const html = renderToStaticMarkup(<ReportHeader model={buildScanReport(payload())} />);

    expect(html).not.toContain("max-w-[76ch]");
  });
});

describe("RunTable", () => {
  it("prints every fact once, under the group it belongs to", () => {
    const model = buildScanReport(
      payload({
        options: { audience: "Platform Operations", preparedBy: "Security Engineering" },
        sourceURL: "http://localhost:8280/scans/scan-1",
      }),
    );
    const html = renderToStaticMarkup(<RunTable groups={model.metadata} />);

    for (const label of ["Engine", "Profile", "Selector", "Started", "Finished", "Outcome"]) {
      expect(html.split(`>${label}<`), label).toHaveLength(2);
    }
    expect(html).toContain("nuclei 3.4.10");
    expect(html).toContain("scan:nuclei:safe");
    expect(html).toContain("Platform Operations");
    expect(html).toContain("http://localhost:8280/scans/scan-1");
    expectPrintSafe(html);
  });

  it("tiles a clean verdict and an unfinished run differently", () => {
    const done = renderToStaticMarkup(<RunTable groups={buildScanReport(payload()).metadata} />);
    const failed = renderToStaticMarkup(
      <RunTable
        groups={buildScanReport(payload({ scan: { ...payload().scan, phase: "failed" } })).metadata}
      />,
    );

    expect(done).toContain("text-emerald-700");
    expect(failed).toContain("text-amber-800");
  });

  it("sets identifiers in monospace and prose in the body face", () => {
    const model = buildScanReport(payload({ options: { audience: "Platform Operations" } }));
    const html = renderToStaticMarkup(<RunTable groups={model.metadata} />);

    expect(html).toMatch(/font-mono[^>]*>scan:nuclei:safe/);
    expect(html).not.toMatch(/font-mono[^>]*>Platform Operations/);
  });
});

describe("BreakdownGrid", () => {
  it("gives every row the glyph its own vocabulary names", () => {
    const html = renderToStaticMarkup(
      <BreakdownGrid
        breakdowns={[
          { key: "severity", title: "By severity", rows: [{ name: "critical", count: 1 }] },
          {
            key: "check",
            title: "By check",
            rows: [{ name: "http/exposures/files/directory-listing", count: 2 }],
          },
          { key: "resource", title: "By resource", rows: [{ name: "api.example.test", count: 3 }] },
        ]}
      />,
    );

    expect(html).toContain("<svg");
    expect(html).toContain("text-rose-700"); // severity: critical
    expect(html).toContain("text-indigo-700"); // check: exposure
    expect(html).toContain("text-teal-700"); // resource: infrastructure
    expectPrintSafe(html);
  });

  it("renders nothing when the run produced no breakdowns", () => {
    expect(renderToStaticMarkup(<BreakdownGrid breakdowns={[]} />)).toBe("");
  });
});

describe("CoverageSection", () => {
  it("prints each metric with the basis it was counted from", () => {
    const model = buildScanReport(payload());
    const html = renderToStaticMarkup(<CoverageSection metrics={model.coverage} />);

    expect(html).toContain("Targets selected");
    expect(html).toContain("class prod");
    expect(html).toContain("at least one finding");
    expect(html).not.toContain("Passing checks");
    expectPrintSafe(html);
  });

  it("prints a pass rate only when the engine recorded verdicts", () => {
    const html = renderToStaticMarkup(
      <CoverageSection metrics={[]} rate={{ passed: 90, failed: 10, percent: 90 }} />,
    );

    expect(html).toContain("Passing checks — 90 of 100");
    expect(html).toContain("90.0%");
  });
});

describe("DisclosureNotes", () => {
  it("says nothing when the report has nothing to disclose", () => {
    expect(renderToStaticMarkup(<DisclosureNotes notes={[]} />)).toBe("");
  });

  it("tiles the disclosures as an auditable note", () => {
    const html = renderToStaticMarkup(<DisclosureNotes notes={["The run reported an error: x"]} />);

    expect(html).toContain("Scope of this report");
    expect(html).toContain("The run reported an error: x");
    expect(html).toContain("text-sky-700");
    expectPrintSafe(html);
  });
});
