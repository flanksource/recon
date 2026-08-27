// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FindingDetail } from "./FindingDetail";
import type { Finding } from "./types";

// A CVE finding as nuclei reports it, stored as an OCSF Detection Finding.
//
// Everything triage needs has a published name now: the description and impact
// are finding_info.desc and impact, the classification is vulnerabilities[],
// the template path is finding_info.uid_alt, and the HTTP exchange is one
// evidences[] entry. All of it used to be reachable only by digging through
// `raw.info`, differently per engine.
const HTTP_FINDING: Finding = {
  id: "01JFINDING",
  scanId: "scan-1",
  lineNo: 5,
  checkId: "CVE-2018-15811",
  engine: "nuclei",
  host: "https://api.example.test",
  matchedAt: "https://api.example.test/dnn",
  resources: [{
    provider: "nuclei",
    scope: "api.example.test",
    uid: "https://api.example.test/dnn",
    name: "https://api.example.test/dnn",
  }],
  tags: ["cve", "rce"],

  class_uid: 2004,
  category_uid: 2,
  type_uid: 200401,
  activity_id: 1,
  severity_id: 4,
  status_id: 1,
  time: Date.parse("2026-08-11T07:35:45+03:00"),

  finding_info: {
    uid: "CVE-2018-15811",
    title: "DotNetNuke 9.2 - 9.2.1 - Weak Encryption",
    desc: "DNN uses a weak encryption algorithm to protect input parameters.",
    types: ["cve", "rce"],
    uid_alt: "/templates/http/cves/2018/CVE-2018-15811.yaml",
  },
  impact: "Attackers can decrypt or tamper with input parameters.",
  metadata: {
    version: "1.5.0",
    event_code: "CVE-2018-15811",
    product: { name: "nuclei", vendor_name: "flanksource-recon" },
  },
  remediation: {
    desc: "Update to DotNetNuke 9.2.2 or later.",
    references: ["https://wpscan.com/vulnerability/9117"],
  },
  vulnerabilities: [{
    title: "DotNetNuke 9.2 - 9.2.1 - Weak Encryption",
    cve: {
      uid: "cve-2018-15811",
      cwe_uid: "cwe-326",
      cvss: [{
        base_score: 7.5,
        vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
      }],
      epss: { score: "0.74048", percentile: 0.99431 },
    },
  }],
  evidences: [{
    name: "status",
    url: { url_string: "https://api.example.test/dnn" },
    dst_endpoint: { ip: "203.0.113.7", port: 443, hostname: "api.example.test" },
    http_request: { args: "GET /dnn HTTP/1.1\nHost: api.example.test" },
    http_response: { message: "HTTP/1.1 200 OK" },
    data: { curl: "curl -X GET https://api.example.test/dnn" },
  }],
  unmapped: {
    protocol: "http",
    matcher_name: "status",
    authors: ["pdteam"],
    product: "dotnetnuke",
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

    // The template path is finding_info.uid_alt, the resolved address is the
    // evidence's destination endpoint, and what neither names is unmapped.
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
          remediation: {
            desc: "1. Rotate the **affected key**.\n2. Follow the [response runbook](https://example.test/runbook).",
          },
          finding_info: {
            ...HTTP_FINDING.finding_info,
            desc: "The **service account** can access `production` resources.",
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

  it("renders the exchange on an Evidence tab counted by the blocks it produced", () => {
    render(<FindingDetail finding={HTTP_FINDING} />);

    // Request, response and the engine's own payload. The evidence's URL is not
    // a fourth: it is the location the overview already states.
    const evidence = screen.getByRole("tab", { name: /Evidence/ });
    expect(evidence).toHaveTextContent("3");
    fireEvent.click(evidence);

    expect(screen.getByText("status · Request")).toBeInTheDocument();
    expect(screen.getByText("status · Response")).toBeInTheDocument();
    expect(screen.getByText("status · Details")).toBeInTheDocument();
    expect(screen.queryByText("status · URL")).toBeNull();
  });

  it("drops the Evidence tab when the engine captured nothing", () => {
    const bare: Finding = { ...HTTP_FINDING, evidences: [] };

    render(<FindingDetail finding={bare} />);

    expect(screen.queryByRole("tab", { name: /Evidence/ })).toBeNull();
  });

  it("renders the whole OCSF record on the Raw JSON tab", () => {
    render(<FindingDetail finding={HTTP_FINDING} />);

    fireEvent.click(screen.getByRole("tab", { name: "Raw JSON" }));

    expect(screen.getByText(/01JFINDING/)).toBeInTheDocument();
    // The engine's own payload is inside the record now rather than beside it,
    // so what a copy of this tab carries is the finding and its evidence both.
    expect(screen.getByText("evidences")).toBeInTheDocument();
    expect(screen.queryByText("raw")).toBeNull();
  });
});

// A failed CIS control as InSpec reports it. Nothing was sent to the account,
// so there is no request, response or curl — the evidence is the assertion and
// the reason it did not hold.
const COMPLIANCE_FINDING: Finding = {
  _id: "scan-2#1",
  scanId: "scan-2",
  lineNo: 1,
  checkId: "cis-gcp-1.4-iam",
  engine: "inspec",
  host: "acme-platform-prod",
  matchedAt:
    "[acme-platform-prod] Service Account: builder@acme-platform-prod.iam.gserviceaccount.com should not have user-managed keys",
  tags: ["profile:inspec-gcp-cis-benchmark", "cis_gcp:1.4", "cis_level:1"],
  severity_id: 3,
  status_id: 1,
  time: Date.parse("2026-08-20T09:41:02+02:00"),
  finding_info: {
    uid: "cis-gcp-1.4-iam",
    title:
      "[IAM] Ensure that there are only GCP-managed service account keys for each service account",
  },
  remediation: {
    desc: "Anyone who has access to the keys will be able to access resources.",
    references: ["https://www.cisecurity.org/benchmark/google_cloud_computing_platform/"],
  },
  // One entry per assertion the control failed, which is the collapse: the
  // control is the check, and its N results are its evidence. Then the control's
  // own source, whose payload is the Ruby itself rather than an object.
  evidences: [
    {
      name:
        "[acme-platform-prod] Service Account: builder@acme-platform-prod.iam.gserviceaccount.com should not have user-managed keys",
      data: {
        status: "failed",
        profile: "inspec-gcp-cis-benchmark",
        code_desc:
          "[acme-platform-prod] Service Account: builder@acme-platform-prod.iam.gserviceaccount.com should not have user-managed keys",
        message: 'expected ["USER_MANAGED", "SYSTEM_MANAGED"] not to include "USER_MANAGED"',
      },
    },
    {
      name: "Control source",
      data:
        "control 'cis-gcp-1.4-iam' do\n  impact 'medium'\n  describe google_service_account_keys do\n    its('key_types') { should_not include 'USER_MANAGED' }\n  end\nend",
    },
  ],
};

describe("a compliance finding", () => {
  afterEach(cleanup);

  it("still offers evidence even though nothing was sent", () => {
    // Without this the Evidence tab disappears and the only way to see why a
    // control failed is to read the raw JSON.
    render(<FindingDetail finding={COMPLIANCE_FINDING} />);

    expect(screen.getByRole("tab", { name: /Evidence/ })).toBeInTheDocument();
  });

  it("titles the assertion's evidence with the assertion itself", () => {
    render(<FindingDetail finding={COMPLIANCE_FINDING} />);

    fireEvent.click(screen.getByRole("tab", { name: /Evidence/ }));

    expect(
      screen.getByText(/should not have user-managed keys · Details$/),
    ).toBeInTheDocument();
  });

  it("shows the control's own source under its own name", () => {
    // The Ruby says what the control actually asserts, which is the difference
    // between "this failed" and knowing whether the finding is right. Its
    // payload is the source itself, so it is not titled as a wrapper.
    render(<FindingDetail finding={COMPLIANCE_FINDING} />);

    fireEvent.click(screen.getByRole("tab", { name: /Evidence/ }));

    expect(screen.getByText("Control source")).toBeInTheDocument();
    expect(screen.queryByText("Control source · Details")).toBeNull();
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
  checkId: "github-pat",
  engine: "trivy",
  host: "ghcr.io/acme/api:1.4",
  matchedAt: "app/config/credentials:4",
  tags: ["class:secret", "category:GitHub"],
  severity_id: 5,
  status_id: 1,
  finding_info: {
    uid: "github-pat",
    title: "GitHub Personal Access Token",
    types: ["secret", "class:secret", "category:GitHub"],
  },
  remediation: { desc: "Rotate the credential and remove it from app/config/credentials" },
  // The line number and nothing else. The matched text is masked in trivy's own
  // report and is not carried at all, so there is nowhere for it to leak from.
  evidences: [{ name: "secret", data: { start_line: 4 } }],
};

// A vulnerability has no code block: the package inventory is the evidence, and
// the description is the only prose trivy gives.
const VULNERABILITY_FINDING: Finding = {
  _id: "scan-3#2",
  scanId: "scan-3",
  lineNo: 2,
  checkId: "CVE-2019-19844",
  engine: "trivy",
  host: "ghcr.io/acme/api:1.4",
  matchedAt: "requirements.txt: Django@2.0.1",
  tags: ["class:lang-pkgs", "package:Django"],
  severity_id: 5,
  status_id: 1,
  finding_info: {
    uid: "CVE-2019-19844",
    title: "Django: crafted email address allows account takeover",
    desc: "Django before 1.11.27 allows account takeover.",
  },
  vulnerabilities: [{
    title: "Django: crafted email address allows account takeover",
    desc: "Django before 1.11.27 allows account takeover.",
    is_fix_available: true,
    cve: { uid: "CVE-2019-19844" },
    affected_packages: [{ name: "Django", version: "2.0.1", fixed_in_version: "1.11.27" }],
  }],
};

describe("an artifact finding", () => {
  afterEach(cleanup);

  it("renders the engine's description as markdown", async () => {
    render(
      <FindingDetail
        finding={{
          ...VULNERABILITY_FINDING,
          finding_info: {
            ...VULNERABILITY_FINDING.finding_info,
            desc: "The **affected package** is vulnerable.",
          },
        }}
      />,
    );

    await waitFor(() => {
      expect(screen.getByText("affected package")).toHaveAttribute("data-streamdown", "strong");
    });
  });

  it("says where in the file the secret is and nothing of its value", () => {
    // Trivy masks the matched text before it writes the report, and recon does
    // not carry even the masked form: the line number is the whole of the
    // evidence, so there is nowhere for the token to leak from.
    render(<FindingDetail finding={SECRET_FINDING} />);

    fireEvent.click(screen.getByRole("tab", { name: /Evidence/ }));

    expect(screen.getByText("secret · Details")).toBeInTheDocument();
    // The JSON renders as a collapsible tree, so the rendered text is read off
    // the whole tree rather than matched as one node.
    expect(document.body.textContent).toMatch(/start_line:\s*4/);
    expect(document.body.textContent).not.toMatch(/\*{4}/);
  });

  it("shows a vulnerability's package and description without an Evidence tab", () => {
    // Nothing was captured: trivy read a package inventory. The affected
    // package and the description are the finding, and both are the overview.
    render(<FindingDetail finding={VULNERABILITY_FINDING} />);

    expect(screen.queryByRole("tab", { name: /Evidence/ })).toBeNull();
    expect(screen.getByText("Description")).toBeInTheDocument();
    expect(screen.getByText(/account takeover/)).toBeInTheDocument();
    expect(screen.getByText("Django@2.0.1")).toBeInTheDocument();
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
