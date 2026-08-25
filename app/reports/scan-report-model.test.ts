import { describe, expect, it } from "vitest";

import {
  breakdowns,
  buildScanReport,
  coverageMetrics,
  groupFindings,
  passRate,
  severityCards,
  sortFindings,
  trafficModel,
  type MetadataRow,
  type ScanReportModel,
} from "./scan-report-model";
import { formatBytes, formatDuration } from "./scan-report-format";
import type {
  ReportFinding,
  ReportScan,
  ReportStats,
  ScanReportData,
} from "./scan-report-types";

const GENERATED_AT = "2026-03-14T09:30:00.000Z";

function stats(overrides: Partial<ReportStats> = {}): ReportStats {
  return {
    requests: 0,
    total: 0,
    percent: 100,
    rps: 0,
    matched: 0,
    errors: 0,
    hosts: 0,
    templates: 0,
    ...overrides,
  };
}

function scan(overrides: Partial<ReportScan> = {}): ReportScan {
  return {
    id: "scan-1",
    name: "prowler-cis-1",
    engine: "prowler",
    engineVersion: "5.14.0",
    profile: "scan:prowler:cis",
    selectorLabel: "class prod",
    endpointCount: 12,
    phase: "done",
    startedAt: "2026-03-14T09:00:00.000Z",
    finishedAt: "2026-03-14T09:12:00.000Z",
    durationMs: 720_000,
    findings: 3,
    severities: { critical: 1, high: 1, medium: 1, low: 0, info: 0, unknown: 0 },
    hosts: ["acct-a", "acct-b"],
    ...overrides,
  };
}

// The server always sends at least one resource, synthesising it from the
// finding's own identity for engines that name none of their own — so a fixture
// without one would be a payload the API cannot produce.
function finding(overrides: Partial<ReportFinding> = {}): ReportFinding {
  const built: ReportFinding = {
    scanId: "scan-1",
    lineNo: 1,
    templateId: "aws/iam_root_mfa",
    name: "Root account has no MFA",
    severity: "critical",
    host: "acct-a",
    matchedAt: "arn:aws:iam::1:root",
    tags: ["iam"],
    ...overrides,
  };
  if (!built.resources) {
    built.resources = [
      { uid: built.host, name: built.matchedAt || built.host, type: built.type },
    ];
  }
  return built;
}

function metadataRow(model: ScanReportModel, label: string): MetadataRow | undefined {
  return model.metadata.flatMap((group) => group.rows).find((row) => row.label === label);
}

function payload(overrides: Partial<ScanReportData> = {}): ScanReportData {
  return {
    scan: scan(),
    findings: [finding()],
    generatedAt: GENERATED_AT,
    ...overrides,
  };
}

describe("formatDuration", () => {
  it.each([
    [0, "—"],
    [450, "450ms"],
    [1_500, "1.5s"],
    [90_000, "1m 30s"],
    [3_930_000, "1h 5m"],
  ])("renders %ims as %s", (milliseconds, expected) => {
    expect(formatDuration(milliseconds)).toBe(expected);
  });
});

describe("formatBytes", () => {
  it.each([
    [0, "0 B"],
    [512, "512 B"],
    [1024, "1 KiB"],
    [1_572_864, "1.5 MiB"],
  ])("renders %i bytes as %s", (bytes, expected) => {
    expect(formatBytes(bytes)).toBe(expected);
  });
});

describe("coverageMetrics", () => {
  it("reports selected, scanned, clean and affected resources as separate counts", () => {
    const metrics = coverageMetrics(
      scan({ endpointCount: 12, hosts: ["acct-a", "acct-b"], stats: stats({ hosts: 10 }) }),
    );
    expect(metrics.map((metric) => [metric.key, metric.value])).toEqual(
      expect.arrayContaining([
        ["targets", "12"],
        ["scanned", "10"],
        ["clean", "8"],
        ["affected", "2"],
      ]),
    );
  });

  it("omits resources scanned when the engine never reported host coverage", () => {
    const keys = coverageMetrics(scan({ stats: undefined })).map((metric) => metric.key);
    expect(keys).toContain("targets");
    expect(keys).not.toContain("scanned");
    expect(keys).not.toContain("clean");
  });

  it("omits clean resources when more hosts have findings than the engine counted", () => {
    const keys = coverageMetrics(
      scan({ hosts: ["a", "b", "c"], stats: stats({ hosts: 2 }) }),
    ).map((metric) => metric.key);
    expect(keys).not.toContain("clean");
  });

  it("reports passing checks only for an engine that records verdicts", () => {
    const recorded = coverageMetrics(
      scan({ stats: stats({ passed: 147, passRecorded: true }) }),
    ).find((metric) => metric.key === "passed");
    expect(recorded?.value).toBe("147");

    const silent = coverageMetrics(scan({ stats: stats({ requests: 4_000 }) }));
    expect(silent.find((metric) => metric.key === "passed")).toBeUndefined();
  });
});

describe("passRate", () => {
  it("is the verdict split for an engine that counts passes", () => {
    expect(passRate(stats({ passed: 147, matched: 3, passRecorded: true }))).toEqual({
      passed: 147,
      failed: 3,
      percent: (147 / 150) * 100,
    });
  });

  it("is absent when the engine records no verdict, even with requests and matches", () => {
    expect(passRate(stats({ requests: 4_000, matched: 3 }))).toBeUndefined();
  });

  it("is absent when a recording engine produced no checks at all", () => {
    expect(passRate(stats({ passed: 0, matched: 0, passRecorded: true }))).toBeUndefined();
  });
});

describe("trafficModel", () => {
  it("summarises wire traffic and orders each breakdown by count", () => {
    const model = trafficModel(
      stats({
        http: {
          requests: 4_000,
          responses: 3_900,
          failed: 100,
          bytes: 1_572_864,
          statusCodes: { "200": 3_000, "404": 900 },
          protocols: { http: 3_800, dns: 200 },
          errors: { timeout: 60, refused: 40 },
          waf: { cloudflare: 12 },
        },
      }),
    );
    expect(model?.totals.map((total) => total.value)).toEqual(["4,000", "3,900", "100", "1.5 MiB"]);
    expect(model?.statusCodes).toEqual([
      { name: "200", count: 3_000 },
      { name: "404", count: 900 },
    ]);
    expect(model?.errors[0]).toEqual({ name: "timeout", count: 60 });
  });

  it("is absent when nothing was counted", () => {
    expect(trafficModel(stats())).toBeUndefined();
    expect(
      trafficModel(
        stats({
          http: {
            requests: 0,
            responses: 0,
            failed: 0,
            bytes: 0,
            statusCodes: {},
            protocols: {},
            errors: {},
            waf: {},
          },
        }),
      ),
    ).toBeUndefined();
  });
});

describe("severityCards", () => {
  it("always shows critical and high, and adds the other levels only when present", () => {
    const cards = severityCards(
      scan({ severities: { critical: 0, high: 0, medium: 4, low: 0, info: 0, unknown: 0 } }),
    );
    expect(cards.map((card) => card.severity)).toEqual(["critical", "high", "medium"]);
    expect(cards.map((card) => card.value)).toEqual([0, 0, 4]);
  });
});

describe("sortFindings", () => {
  it("orders worst severity first, then by check and resource", () => {
    const sorted = sortFindings([
      finding({ severity: "low", templateId: "b", host: "h2" }),
      finding({ severity: "critical", templateId: "z", host: "h1" }),
      finding({ severity: "low", templateId: "a", host: "h3" }),
    ]);
    expect(sorted.map((row) => [row.severity, row.templateId])).toEqual([
      ["critical", "z"],
      ["low", "a"],
      ["low", "b"],
    ]);
  });
});

describe("groupFindings", () => {
  it("groups occurrences by template and projects unique canonical resource instances", () => {
    const serviceAccount = {
      name: "projects/example-prod/serviceAccounts/scanner-sa@example-prod.iam.gserviceaccount.com",
      region: "global",
      type: "iam.googleapis.com/ServiceAccount",
      uid: "scanner-sa@example-prod.iam.gserviceaccount.com",
    };
    const groups = groupFindings([
      finding({
        lineNo: 2,
        templateId: "gcp/iam_service_account_keys",
        name: "Service account key is exposed",
        severity: "high",
        matcherName: "FAIL",
        type: "prowler",
        tags: ["identity", "compliance:CIS-1.2"],
        remediation: "Rotate the **affected key**.",
        resources: [serviceAccount],
        raw: {
          info: { description: "The **service account** has an exposed key." },
        },
      }),
      finding({
        lineNo: 3,
        templateId: "gcp/iam_service_account_keys",
        name: "Service account key is exposed",
        severity: "critical",
        matcherName: "FAIL",
        type: "prowler",
        tags: ["identity", "leaked-secret", "compliance:PCI-DSS"],
        resources: [serviceAccount],
      }),
      finding({ lineNo: 4, templateId: "http/header-check", severity: "low" }),
    ]);

    expect(groups.map((group) => [group.templateId, group.findings.length])).toEqual([
      ["gcp/iam_service_account_keys", 2],
      ["http/header-check", 1],
    ]);
    expect(groups[0]).toMatchObject({
      names: ["Service account key is exposed"],
      severity: "critical",
      matcherNames: ["FAIL"],
      types: ["prowler"],
      tags: ["identity", "leaked-secret"],
      descriptions: ["The **service account** has an exposed key."],
      remediations: ["Rotate the **affected key**."],
      instances: [serviceAccount],
    });
  });

  // The synthesised reference an engine with no resources of its own gets. It is
  // built server-side now, so what this asserts is that the projection carries it
  // through unchanged rather than re-deriving anything from matchedAt and host.
  it("projects the reference the server synthesised for an engine that names none", () => {
    expect(groupFindings([finding({ type: "ssl" })])[0].instances).toEqual([
      {
        name: "arn:aws:iam::1:root",
        region: "",
        type: "ssl",
        uid: "acct-a",
      },
    ]);
  });
});

describe("breakdowns", () => {
  it("counts severity from the run and everything else from the printed findings", () => {
    const result = breakdowns(
      scan({ severities: { critical: 1, high: 0, medium: 2, low: 0, info: 0, unknown: 0 } }),
      [
        finding({ templateId: "a", host: "h1", tags: ["iam", "cis", "compliance:CIS-1.2"] }),
        finding({ templateId: "a", host: "h2", tags: ["iam"] }),
      ],
    );
    expect(result.find((entry) => entry.key === "severity")?.rows).toEqual([
      { name: "critical", count: 1 },
      { name: "medium", count: 2 },
    ]);
    expect(result.find((entry) => entry.key === "check")?.rows).toEqual([{ name: "a", count: 2 }]);
    expect(result.find((entry) => entry.key === "tag")?.rows).toEqual([
      { name: "iam", count: 2 },
      { name: "cis", count: 1 },
    ]);
  });

  it("drops a breakdown with no rows rather than printing an empty table", () => {
    expect(breakdowns(scan({ severities: {} }), []).map((entry) => entry.key)).toEqual([]);
  });
});

describe("buildScanReport", () => {
  it("formats effective scan parameters in stable key order", () => {
    const model = buildScanReport(
      payload({
        parameters: {
          severity: ["high", "critical"],
          "rate-limit": 50,
          headless: true,
        },
      }),
    );

    expect(model.parameters).toEqual([
      { name: "headless", value: "true" },
      { name: "rate-limit", value: "50" },
      { name: "severity", value: '["high","critical"]' },
    ]);
  });

  it("keeps the run's own severity totals when a severity floor hides findings", () => {
    const model = buildScanReport(
      payload({
        findings: [finding({ severity: "critical" }), finding({ lineNo: 2, severity: "low" })],
        options: { minSeverity: "high" },
      }),
    );
    expect(model.findings).toHaveLength(1);
    expect(model.totalFindings).toBe(3);
    expect(model.notes).toContainEqual(expect.stringContaining("below high severity are excluded"));
  });

  it("discloses an API-capped findings query", () => {
    const model = buildScanReport(
      payload({
        scan: scan({ findings: 900 }),
        findings: Array.from({ length: 500 }, (_, index) => finding({ lineNo: index })),
        findingLimit: 500,
      }),
    );
    expect(model.notes).toContainEqual(
      "This report covers the first 500 of 900 findings — the API caps a query at 500.",
    );
  });

  it("caps detailed evidence without shortening the summary table", () => {
    const model = buildScanReport(
      payload({
        findings: Array.from({ length: 5 }, (_, index) => finding({ lineNo: index })),
        options: { maxDetailedFindings: 2 },
      }),
    );
    expect(model.findings).toHaveLength(5);
    expect(model.detailed).toHaveLength(2);
    expect(model.notes).toContainEqual(expect.stringContaining("Detailed evidence is printed for the 2"));
  });

  it("discloses a run that did not finish cleanly", () => {
    const model = buildScanReport(
      payload({ scan: scan({ phase: "failed", error: "prowler exited 4" }) }),
    );
    expect(model.notes).toEqual(
      expect.arrayContaining([
        "The run reported an error: prowler exited 4",
        'The run finished in phase "failed", so its coverage may be partial.',
      ]),
    );
  });

  it("prints no disclosures for a complete, uncapped, unfiltered run", () => {
    expect(buildScanReport(payload()).notes).toEqual([]);
  });

  it("defaults every section on and lets options turn one off", () => {
    expect(buildScanReport(payload()).sections.traffic).toBe(true);
    expect(buildScanReport(payload({ options: { sections: { traffic: false } } })).sections).toEqual({
      coverage: true,
      traffic: false,
      breakdowns: true,
      summaryTable: true,
      detailedFindings: true,
      evidence: true,
      appendix: true,
    });
  });

  it("stamps the supplied generation time rather than reading the clock", () => {
    const model = buildScanReport(payload());
    expect(model.generatedAt).toBe(GENERATED_AT);
    expect(metadataRow(model, "Generated")).toEqual({
      label: "Generated",
      value: "2026-03-14 09:30:00Z",
      kind: "time",
    });
  });
});

describe("metadata groups", () => {
  it("splits run detail from report provenance and kinds every row", () => {
    const model = buildScanReport(payload());

    expect(model.metadata.map((group) => group.title)).toEqual(["Run", "Report"]);
    expect(model.metadata[0].rows).toEqual([
      { label: "Engine", value: "prowler 5.14.0", kind: "engine" },
      { label: "Profile", value: "scan:prowler:cis", kind: "profile" },
      { label: "Selector", value: "class prod", kind: "selector" },
      { label: "Started", value: "2026-03-14 09:00:00Z", kind: "time" },
      { label: "Finished", value: "2026-03-14 09:12:00Z", kind: "time" },
      { label: "Outcome", value: "done", kind: "outcome" },
    ]);
  });

  it("omits an unset option rather than printing it blank", () => {
    const rows = buildScanReport(payload()).metadata[1].rows;

    expect(rows.map((row) => row.label)).toEqual(["Generated", "Classification"]);
  });

  it("carries the audience, author and source once they are supplied", () => {
    const model = buildScanReport(
      payload({
        options: { audience: "Platform Operations", preparedBy: "Security Engineering" },
        sourceURL: "http://localhost:8280/scans/scan-1",
      }),
    );

    expect(model.metadata[1].rows).toEqual([
      { label: "Generated", value: "2026-03-14 09:30:00Z", kind: "time" },
      { label: "Classification", value: "Internal", kind: "classification" },
      { label: "Audience", value: "Platform Operations", kind: "audience" },
      { label: "Prepared by", value: "Security Engineering", kind: "author" },
      { label: "Source", value: "http://localhost:8280/scans/scan-1", kind: "source" },
    ]);
  });

  it("marks a run that did not finish so its outcome is not tiled as a clean verdict", () => {
    expect(metadataRow(buildScanReport(payload()), "Outcome")).toEqual({
      label: "Outcome",
      value: "done",
      kind: "outcome",
    });
    expect(
      metadataRow(buildScanReport(payload({ scan: scan({ phase: "failed" }) })), "Outcome"),
    ).toEqual({ label: "Outcome", value: "failed", kind: "incomplete" });
  });

  it("prints the classification the footer prints", () => {
    const model = buildScanReport(payload({ options: { classification: "Restricted" } }));

    expect(metadataRow(model, "Classification")?.value).toBe(model.classification);
    expect(model.classification).toBe("Restricted");
  });
});
