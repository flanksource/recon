import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { groupFindings } from "./scan-report-model";
import { DetailedFindings, FindingsSummaryTable } from "./scan-report-sections";
import type { ReportFinding } from "./scan-report-types";

const SERVICE_ACCOUNT = {
  name: "projects/example-prod/serviceAccounts/scanner-sa@example-prod.iam.gserviceaccount.com",
  region: "global",
  type: "iam.googleapis.com/ServiceAccount",
  uid: "scanner-sa@example-prod.iam.gserviceaccount.com",
};

function finding(lineNo: number): ReportFinding {
  return {
    scanId: "scan-1",
    lineNo,
    templateId: "gcp/iam_service_account_keys",
    name: "Service account key is exposed",
    severity: "high",
    host: "example-prod",
    matchedAt: SERVICE_ACCOUNT.name,
    matcherName: "FAIL",
    type: "prowler",
    tags: ["identity", "leaked-secret", "compliance:CIS-1.2"],
    raw: { resources: [SERVICE_ACCOUNT] },
  };
}

describe("grouped finding report sections", () => {
  it("renders one finding block with a canonical instances table and semantic badges", () => {
    const html = renderToStaticMarkup(
      <DetailedFindings groups={groupFindings([finding(1), finding(2)])} showEvidence={false} />,
    );

    expect(html.match(/<h3[^>]*>Service account key is exposed<\/h3>/g)).toHaveLength(1);
    expect(html).toContain("Instances (1)");
    expect(html).toContain(SERVICE_ACCOUNT.name);
    expect(html).toContain(SERVICE_ACCOUNT.region);
    expect(html).toContain(SERVICE_ACCOUNT.type);
    expect(html).toContain(SERVICE_ACCOUNT.uid);
    expect(html).toContain("text-violet-700");
    expect(html).toContain("<svg");
    expect(html).not.toContain("compliance:CIS-1.2");
  });

  it("summarises each template once with its instance count", () => {
    const html = renderToStaticMarkup(
      <FindingsSummaryTable groups={groupFindings([finding(1), finding(2)])} />,
    );

    expect(html).toContain("Findings by check");
    expect(html).toContain("1 instance");
    expect(html.match(/gcp\/iam_service_account_keys/g)).toHaveLength(1);
  });

  it("renders descriptions and recommended actions as markdown", () => {
    const richFinding = {
      ...finding(1),
      remediation:
        "1. Rotate the **affected key**.\n2. Follow the [response runbook](https://example.test/runbook).",
      raw: {
        info: { description: "The **service account** can access `production` resources." },
        resources: [SERVICE_ACCOUNT],
      },
    };

    const html = renderToStaticMarkup(
      <DetailedFindings groups={groupFindings([richFinding])} showEvidence={false} />,
    );

    expect(html).toContain("Description");
    expect(html).toContain("Recommended action");
    expect(html).toContain("<strong>service account</strong>");
    expect(html).toContain(">production</code>");
    expect(html).toContain("<strong>affected key</strong>");
    expect(html).toContain("<ol");
    expect(html).toContain('href="https://example.test/runbook"');
    expect(html).not.toContain("**service account**");
  });
});
