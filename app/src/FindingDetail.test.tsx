// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FindingDetail } from "./FindingDetail";
import type { Finding } from "./types";

// A CVE finding as nuclei reports it: the normalised columns carry almost none
// of what triage needs — description, impact, classification and the template
// path only exist under `raw.info`.
const HTTP_FINDING: Finding = {
  id: "01JFINDING",
  scanId: "scan-1",
  lineNo: 5,
  templateId: "CVE-2018-15811",
  name: "DotNetNuke 9.2 - 9.2.1 - Weak Encryption",
  severity: "high",
  host: "https://api.example.test",
  matchedAt: "https://api.example.test/dnn",
  resources: [{
    provider: "nuclei",
    scope: "api.example.test",
    uid: "https://api.example.test/dnn",
    name: "https://api.example.test/dnn",
  }],
  type: "http",
  tags: ["cve", "rce"],
  timestamp: "2026-08-11T07:35:45+03:00",
  remediation: "Update to DotNetNuke 9.2.2 or later.",
  reference: ["https://wpscan.com/vulnerability/9117"],
  curl: "curl -X GET https://api.example.test/dnn",
  request: "GET /dnn HTTP/1.1\nHost: api.example.test",
  response: "HTTP/1.1 200 OK",
  raw: {
    "template-path": "/templates/http/cves/2018/CVE-2018-15811.yaml",
    "matcher-status": true,
    ip: "203.0.113.7",
    port: "443",
    info: {
      author: ["pdteam"],
      description: "DNN uses a weak encryption algorithm to protect input parameters.",
      impact: "Attackers can decrypt or tamper with input parameters.",
      classification: {
        "cve-id": ["cve-2018-15811"],
        "cwe-id": ["cwe-326"],
        "cvss-score": 7.5,
        "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "epss-score": 0.74048,
        "epss-percentile": 0.99431,
      },
      metadata: { product: "dotnetnuke", "max-request": 1 },
    },
  },
};

describe("FindingDetail", () => {
  beforeEach(() => {
    // CodeBlock resolves the syntax theme from the media query.
    Object.defineProperty(window, "matchMedia", {
      configurable: true,
      value: vi.fn().mockReturnValue({
        matches: false,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
      }),
    });
  });
  afterEach(cleanup);

  it("surfaces the engine's description, impact and classification alongside the normalised fields", () => {
    render(<FindingDetail finding={HTTP_FINDING} />);

    expect(
      screen.getByText("DNN uses a weak encryption algorithm to protect input parameters."),
    ).toBeInTheDocument();
    expect(screen.getByText("Attackers can decrypt or tamper with input parameters.")).toBeInTheDocument();
    expect(screen.getByText("Update to DotNetNuke 9.2.2 or later.")).toBeInTheDocument();

    expect(screen.getByRole("link", { name: /CVE-2018-15811/ })).toHaveAttribute(
      "href",
      "https://nvd.nist.gov/vuln/detail/CVE-2018-15811",
    );
    expect(screen.getByText("CWE-326")).toBeInTheDocument();
    expect(screen.getByText("7.5")).toBeInTheDocument();
    expect(screen.getByText("0.74048 (p0.99431)")).toBeInTheDocument();

    // Template path, address and template metadata exist only in the raw record.
    expect(screen.getByText("/templates/http/cves/2018/CVE-2018-15811.yaml")).toBeInTheDocument();
    expect(screen.getByText("203.0.113.7:443")).toBeInTheDocument();
    expect(screen.getByText("product")).toBeInTheDocument();
    expect(screen.getByText("dotnetnuke")).toBeInTheDocument();
  });

  it("renders finding descriptions and recommended actions as markdown", async () => {
    render(
      <FindingDetail
        finding={{
          ...HTTP_FINDING,
          remediation:
            "1. Rotate the **affected key**.\n2. Follow the [response runbook](https://example.test/runbook).",
          raw: {
            ...HTTP_FINDING.raw,
            info: {
              ...(HTTP_FINDING.raw?.info as Record<string, unknown>),
              description: "The **service account** can access `production` resources.",
            },
          },
        }}
      />,
    );

    await waitFor(() => {
      expect(screen.getByText("service account")).toHaveAttribute("data-streamdown", "strong");
      expect(screen.getByText("affected key")).toHaveAttribute("data-streamdown", "strong");
    });
    expect(screen.getByText("production").tagName).toBe("CODE");
    expect(screen.getByRole("button", { name: "response runbook" })).toHaveAttribute(
      "data-streamdown",
      "link",
    );
    expect(screen.getByText("affected key").closest("ol")).not.toBeNull();
  });

  it("keeps curl, request and response on an Evidence tab counted by what the finding carries", () => {
    render(<FindingDetail finding={HTTP_FINDING} />);

    const evidence = screen.getByRole("tab", { name: /Evidence/ });
    expect(evidence).toHaveTextContent("3");
    fireEvent.click(evidence);

    expect(screen.getByText("Reproduce (curl)")).toBeInTheDocument();
    expect(screen.getByText(/curl -X GET/)).toBeInTheDocument();
    expect(screen.getByText(/GET \/dnn HTTP\/1\.1/)).toBeInTheDocument();
    expect(screen.getByText(/HTTP\/1\.1 200 OK/)).toBeInTheDocument();
  });

  it("drops the Evidence tab when the engine captured no request or response", () => {
    const bare = { ...HTTP_FINDING };
    delete bare.curl;
    delete bare.request;
    delete bare.response;

    render(<FindingDetail finding={bare} />);

    expect(screen.queryByRole("tab", { name: /Evidence/ })).toBeNull();
  });

  it("renders the whole finding — engine record included — on the Raw JSON tab", () => {
    render(<FindingDetail finding={HTTP_FINDING} />);

    fireEvent.click(screen.getByRole("tab", { name: "Raw JSON" }));

    expect(screen.getByText(/01JFINDING/)).toBeInTheDocument();
    expect(screen.getByText("raw")).toBeInTheDocument();
  });
});

// A failed CIS control as InSpec reports it. Nothing was sent to the account,
// so there is no request, response or curl — the evidence is the assertion and
// the reason it did not hold.
const COMPLIANCE_FINDING: Finding = {
  _id: "scan-2#1",
  scanId: "scan-2",
  lineNo: 1,
  templateId: "cis-gcp-1.4-iam",
  name: "[IAM] Ensure that there are only GCP-managed service account keys for each service account",
  severity: "medium",
  host: "acme-platform-prod",
  matchedAt:
    "[acme-platform-prod] Service Account: builder@acme-platform-prod.iam.gserviceaccount.com should not have user-managed keys",
  type: "inspec",
  tags: ["profile:inspec-gcp-cis-benchmark", "cis_gcp:1.4", "cis_level:1"],
  timestamp: "2026-08-20T09:41:02+02:00",
  remediation: "Anyone who has access to the keys will be able to access resources.",
  reference: ["https://www.cisecurity.org/benchmark/google_cloud_computing_platform/"],
  raw: {
    profile: "inspec-gcp-cis-benchmark",
    control: {
      id: "cis-gcp-1.4-iam",
      impact: 0.5,
      code: "control 'cis-gcp-1.4-iam' do\n  impact 'medium'\nend",
    },
    result: {
      status: "failed",
      code_desc:
        "[acme-platform-prod] Service Account: builder@acme-platform-prod.iam.gserviceaccount.com should not have user-managed keys",
      message: 'expected ["USER_MANAGED", "SYSTEM_MANAGED"] not to include "USER_MANAGED"',
    },
  },
};

describe("a compliance finding", () => {
  afterEach(cleanup);

  it("still offers evidence even though nothing was sent", () => {
    // Without this the Evidence tab disappears and the only way to see why a
    // control failed is to read the raw JSON.
    render(<FindingDetail finding={COMPLIANCE_FINDING} />);

    expect(screen.getByRole("tab", { name: /Evidence/ })).toBeInTheDocument();
  });

  it("shows the assertion and the reason it did not hold", () => {
    render(<FindingDetail finding={COMPLIANCE_FINDING} />);

    fireEvent.click(screen.getByRole("tab", { name: /Evidence/ }));

    expect(screen.getByText("Assertion")).toBeInTheDocument();
    expect(screen.getByText("Why it failed")).toBeInTheDocument();
    expect(screen.getByText(/not to include/)).toBeInTheDocument();
  });

  it("shows the control's own source", () => {
    // The Ruby says what the control actually asserts, which is the difference
    // between "this failed" and knowing whether the finding is right.
    render(<FindingDetail finding={COMPLIANCE_FINDING} />);

    fireEvent.click(screen.getByRole("tab", { name: /Evidence/ }));

    expect(screen.getByText("Control source")).toBeInTheDocument();
  });

  it("offers no HTTP evidence panels", () => {
    // A compliance finding carries no request or response, and labelling its
    // assertion as one would misrepresent what the engine did.
    render(<FindingDetail finding={COMPLIANCE_FINDING} />);

    fireEvent.click(screen.getByRole("tab", { name: /Evidence/ }));

    expect(screen.queryByText("Request")).toBeNull();
    expect(screen.queryByText("Response")).toBeNull();
    expect(screen.queryByText("Reproduce (curl)")).toBeNull();
  });
});

// A secret as trivy reports it. The value is already masked in the engine's own
// record — recon never sees the token — so the evidence worth showing is where
// in the file it is.
const SECRET_FINDING: Finding = {
  _id: "scan-3#1",
  scanId: "scan-3",
  lineNo: 1,
  templateId: "github-pat",
  name: "GitHub Personal Access Token",
  severity: "critical",
  host: "ghcr.io/acme/api:1.4",
  matchedAt: "app/config/credentials:4",
  type: "trivy",
  tags: ["class:secret", "category:GitHub"],
  remediation: "Rotate the credential and remove it from app/config/credentials",
  raw: {
    RuleID: "github-pat",
    Title: "GitHub Personal Access Token",
    StartLine: 4,
    Match: "github_token = ****************",
    Code: {
      Lines: [
        { Number: 3, Content: "[github]", IsCause: false },
        { Number: 4, Content: "github_token = ****************", IsCause: true },
      ],
    },
  },
};

// A vulnerability has no code block: the package inventory is the evidence, and
// the description is the only prose trivy gives.
const VULNERABILITY_FINDING: Finding = {
  _id: "scan-3#2",
  scanId: "scan-3",
  lineNo: 2,
  templateId: "CVE-2019-19844",
  name: "Django: crafted email address allows account takeover",
  severity: "critical",
  host: "ghcr.io/acme/api:1.4",
  matchedAt: "requirements.txt: Django@2.0.1",
  type: "trivy",
  tags: ["class:lang-pkgs", "package:Django"],
  raw: {
    VulnerabilityID: "CVE-2019-19844",
    PkgName: "Django",
    Description: "Django before 1.11.27 allows account takeover.",
  },
};

describe("an artifact finding", () => {
  afterEach(cleanup);

  it("renders top-level engine descriptions as markdown", async () => {
    render(
      <FindingDetail
        finding={{
          ...VULNERABILITY_FINDING,
          raw: {
            ...VULNERABILITY_FINDING.raw,
            Description: "The **affected package** is vulnerable.",
          },
        }}
      />,
    );

    await waitFor(() => {
      expect(screen.getByText("affected package")).toHaveAttribute("data-streamdown", "strong");
    });
  });

  it("shows the lines of the file the secret is in", () => {
    render(<FindingDetail finding={SECRET_FINDING} />);

    fireEvent.click(screen.getByRole("tab", { name: /Evidence/ }));

    expect(screen.getByText("Code")).toBeInTheDocument();
    expect(screen.getByText(/github_token/)).toBeInTheDocument();
  });

  it("keeps the value masked, exactly as the engine wrote it", () => {
    render(<FindingDetail finding={SECRET_FINDING} />);

    fireEvent.click(screen.getByRole("tab", { name: /Evidence/ }));

    expect(screen.getByText(/\*{4}/)).toBeInTheDocument();
  });

  it("falls back to the description when there is no code to show", () => {
    render(<FindingDetail finding={VULNERABILITY_FINDING} />);

    fireEvent.click(screen.getByRole("tab", { name: /Evidence/ }));

    expect(screen.getByText("Description")).toBeInTheDocument();
    expect(screen.getByText(/account takeover/)).toBeInTheDocument();
  });

  it("offers no HTTP evidence panels", () => {
    // Nothing was sent: the image was pulled and read. Labelling the file's
    // lines as a request would misrepresent what the engine did.
    render(<FindingDetail finding={SECRET_FINDING} />);

    fireEvent.click(screen.getByRole("tab", { name: /Evidence/ }));

    expect(screen.queryByText("Request")).toBeNull();
    expect(screen.queryByText("Reproduce (curl)")).toBeNull();
  });

  it("asks how far a mute should reach rather than deciding for the operator", () => {
    // This URL being expected and this check being noise everywhere are
    // different facts, and only one of them is about this finding.
    render(<FindingDetail finding={HTTP_FINDING} engine="nuclei" onMute={vi.fn()} />);

    fireEvent.click(screen.getByRole("button", { name: "Mute this finding" }));

    expect(
      screen.getAllByRole("menuitem").map((item) => item.textContent),
    ).toEqual([
      "This check on this resource",
      "This check on this host",
      "This check everywhere",
      "Anything on this resource",
    ]);
  });

  it("opens a draft scoped to the choice rather than muting on the spot", () => {
    // The editor previews before it commits: a rule drops what it matches, so
    // the click has to open a draft, not create a rule.
    const onMute = vi.fn();
    render(<FindingDetail finding={HTTP_FINDING} engine="nuclei" onMute={onMute} />);

    fireEvent.click(screen.getByRole("button", { name: "Mute this finding" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "This check everywhere" }));

    expect(onMute).toHaveBeenCalledTimes(1);
    expect(onMute).toHaveBeenCalledWith("/mutes/new?templates=CVE-2018-15811&engines=nuclei");
  });

  it("scopes to the canonical endpoint, not the host, when the choice says this resource", () => {
    const onMute = vi.fn();
    render(<FindingDetail finding={HTTP_FINDING} engine="nuclei" onMute={onMute} />);

    fireEvent.click(screen.getByRole("button", { name: "Mute this finding" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "This check on this resource" }));

    expect(onMute).toHaveBeenCalledWith(
      "/mutes/new?templates=CVE-2018-15811" +
        "&resourceKeys=nuclei%2Fapi.example.test%2Fhttps%3A%2F%2Fapi.example.test%2Fdnn&engines=nuclei",
    );
  });

  it("offers no mute action where there is nowhere to navigate to", () => {
    render(<FindingDetail finding={HTTP_FINDING} />);

    expect(screen.queryByRole("button", { name: "Mute this finding" })).toBeNull();
  });
});
