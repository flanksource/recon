// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FindingDetail } from "./FindingDetail";
import type { Finding } from "./types";

// A CVE finding as nuclei reports it: the normalised columns carry almost none
// of what triage needs — description, impact, classification and the template
// path only exist under `raw.info`.
const HTTP_FINDING: Finding = {
  _id: "scan-1#5",
  scanId: "scan-1",
  lineNo: 5,
  templateId: "CVE-2018-15811",
  name: "DotNetNuke 9.2 - 9.2.1 - Weak Encryption",
  severity: "high",
  host: "https://api.example.test",
  matchedAt: "https://api.example.test/dnn",
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

    expect(screen.getByText(/scan-1#5/)).toBeInTheDocument();
    expect(screen.getByText("raw")).toBeInTheDocument();
  });
});
