// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ScanTraffic } from "./ScanTraffic";
import type { HTTPStats } from "./types";

const HTTP: HTTPStats = {
  requests: 1200,
  responses: 900,
  failed: 300,
  bytes: 5_242_880,
  statusCodes: { "200": 700, "301": 150, "404": 40, "503": 10 },
  protocols: { http: 1100, dns: 100 },
  errors: { "network-permanent-error": 250, "deadline-error": 50 },
  waf: { cloudflare: 12 },
};

describe("ScanTraffic", () => {
  afterEach(cleanup);

  it("reports what was sent, what came back, and how much of it failed", () => {
    render(<ScanTraffic http={HTTP} />);

    expect(screen.getByText("requests").parentElement).toHaveTextContent("1,200");
    expect(screen.getByText("responses").parentElement).toHaveTextContent("900");
    expect(screen.getByText("failed").parentElement).toHaveTextContent("300");
    // 300 of 1200, computed here rather than read off the payload: the server
    // reports counts and the rate is this component's arithmetic.
    expect(screen.getByText("failure rate").parentElement).toHaveTextContent("25.0%");
    expect(screen.getByText("received").parentElement).toHaveTextContent("5.0 MiB");
  });

  it("breaks the traffic down by status code, protocol, error kind and firewall", () => {
    render(<ScanTraffic http={HTTP} />);

    const codes = screen.getByText("Status codes").parentElement!;
    expect(within(codes).getByText("200").parentElement).toHaveTextContent("700");
    expect(within(codes).getByText("503").parentElement).toHaveTextContent("10");
    expect(within(screen.getByText("Protocols").parentElement!).getByText("dns")).toBeInTheDocument();
    expect(
      within(screen.getByText("Errors").parentElement!).getByText("deadline-error"),
    ).toBeInTheDocument();
    expect(
      within(screen.getByText("WAF detected").parentElement!).getByText("cloudflare"),
    ).toBeInTheDocument();
  });

  // Bars scale to the largest count, not to the total: a run where nearly every
  // response is a 200 would otherwise render the handful of 5xx — the ones
  // worth seeing — as an invisible sliver.
  it("scales each bar against the largest count in its breakdown", () => {
    const { container } = render(
      <ScanTraffic http={{ ...HTTP, statusCodes: { "200": 100, "500": 50 } }} />,
    );

    const widths = [...container.querySelectorAll<HTMLElement>("span[style*='width']")].map(
      (bar) => bar.style.width,
    );
    expect(widths).toContain("100%");
    expect(widths).toContain("50%");
  });

  it("hides the tail of a long breakdown rather than growing without bound", () => {
    const many = Object.fromEntries(
      Array.from({ length: 12 }, (_, index) => [`${400 + index}`, 12 - index]),
    );
    render(<ScanTraffic http={{ ...HTTP, statusCodes: many }} />);

    expect(screen.getByText("+4 more not shown")).toBeInTheDocument();
  });

  it("says nothing was counted rather than rendering a breakdown of nothing", () => {
    render(<ScanTraffic />);

    expect(
      screen.getByText("No traffic statistics were collected for this scan."),
    ).toBeInTheDocument();
  });
});
