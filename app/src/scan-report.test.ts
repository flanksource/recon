import { describe, expect, it } from "vitest";

import {
  playgroundUrl,
  reportDataUrl,
  reportOptionsFromQuery,
  reportQuery,
  reportUrl,
} from "./scan-report";
import type { ReportOptions } from "../reports/scan-report-types";

// The query string is the contract between the playground, the export menu and
// internal/httpapi/scanreport.go: a design tuned on screen has to survive being
// pasted into a runbook and come back as the same document. These specs pin the
// two halves of that — what a set of options serialises to, and that reading it
// back returns what went in.

describe("reportQuery", () => {
  it("writes nothing for options left at the template's defaults", () => {
    expect(reportQuery({}).toString()).toBe("");
  });

  it("ignores a field the user cleared back to whitespace", () => {
    expect(reportQuery({ title: "   ", classification: "Secret" }).toString()).toBe(
      "classification=Secret",
    );
  });

  it("writes only the sections that were turned off", () => {
    const query = reportQuery({ sections: { traffic: false, appendix: true } });

    expect(query.get("traffic")).toBe("false");
    expect(query.has("appendix")).toBe(false);
  });

  it("writes a zero cap, which is not the same as no cap", () => {
    expect(reportQuery({ maxDetailedFindings: 0 }).get("maxDetailedFindings")).toBe("0");
    expect(reportQuery({}).has("maxDetailedFindings")).toBe(false);
  });
});

describe("reportOptionsFromQuery", () => {
  it("round-trips every option a report can carry", () => {
    const options: ReportOptions = {
      title: "Quarterly Review",
      subtitle: "Q1 production",
      classification: "Confidential",
      preparedBy: "Security Engineering",
      audience: "Platform Operations",
      scope: "every internet-facing host in the production class",
      watermark: "DRAFT",
      minSeverity: "medium",
      maxDetailedFindings: 25,
      sections: { traffic: false, appendix: false },
    };

    expect(reportOptionsFromQuery(reportQuery(options))).toEqual(options);
  });

  it("reads no sections at all when none were toggled, leaving the template's defaults", () => {
    expect(reportOptionsFromQuery(new URLSearchParams("title=Report")).sections).toBeUndefined();
  });
});

describe("report URLs", () => {
  it("addresses the rendered document, the payload and the playground for one run", () => {
    const options: ReportOptions = { title: "Q1", sections: { traffic: false } };

    expect(reportUrl("scan-1", "pdf", options)).toBe(
      "/api/scan/scan-1/report.pdf?title=Q1&traffic=false",
    );
    expect(reportUrl("scan-1", "html", options)).toBe(
      "/api/scan/scan-1/report.html?title=Q1&traffic=false",
    );
    expect(reportDataUrl("scan-1", options)).toBe("/api/scan/scan-1/report?title=Q1&traffic=false");
    expect(playgroundUrl("scan-1", options)).toBe("/reports/scan-1?title=Q1&traffic=false");
  });

  it("leaves a default report as a bare URL", () => {
    expect(reportUrl("scan-1", "pdf")).toBe("/api/scan/scan-1/report.pdf");
  });

  it("escapes a run id that is not URL-safe", () => {
    expect(reportUrl("scan/1 2", "pdf")).toBe("/api/scan/scan%2F1%202/report.pdf");
  });
});
