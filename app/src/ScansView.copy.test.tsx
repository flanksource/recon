// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ScanDetailView } from "./ScansView";
import type { Finding, Scan } from "./types";

const SCAN: Scan = {
  id: "scan-1",
  name: "Acme perimeter scan",
  engine: "nuclei",
  profile: "safe",
  selector: { hosts: ["app.acme.test"] },
  selectorLabel: "host app.acme.test",
  endpointCount: 101,
  phase: "done",
  startedAt: "2026-08-21T08:00:00Z",
  durationMs: 60_000,
  findings: 101,
  severities: {
    critical: 0,
    high: 101,
    medium: 0,
    low: 0,
    info: 0,
    unknown: 0,
  },
  hosts: ["app.acme.test"],
  resultPath: "/var/lib/recon/results/scan-1",
};

function finding(lineNo: number, values: Partial<Finding> = {}): Finding {
  return {
    scanId: "scan-1",
    lineNo,
    templateId: `shared-template-${lineNo}`,
    name: `Shared finding ${lineNo}`,
    severity: "high",
    host: "app.acme.test",
    matchedAt: `https://app.acme.test/${lineNo}`,
    type: "http",
    tags: ["internet-facing"],
    ...values,
  };
}

function mockRequests(findings: Finding[]) {
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const path = String(input);
    if (path === "/api/v1/finding?__lookup=filters") {
      return new Response(JSON.stringify({ filters: {} }), { status: 200 });
    }
    if (path === "/api/v1/finding?scan=scan-1&limit=500") {
      return new Response(JSON.stringify(findings), { status: 200 });
    }
    if (path === "/api/v1/scan/scan-1") {
      return new Response(JSON.stringify(SCAN), { status: 200 });
    }
    if (path === "/api/scan/scan-1/files/config.json") {
      return new Response(JSON.stringify({ "rate-limit": 50, headless: true }), {
        status: 200,
      });
    }
    throw new Error(`unexpected request: ${path}`);
  });
}

describe("ScanDetailView finding copy action", () => {
  beforeEach(() => {
    window.history.replaceState(null, "", "/scans/scan-1");
    Object.defineProperty(window, "matchMedia", {
      configurable: true,
      value: vi.fn().mockReturnValue({
        matches: false,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
      }),
    });
    vi.stubGlobal(
      "IntersectionObserver",
      class {
        observe() {}
        unobserve() {}
        disconnect() {}
      },
    );
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    Reflect.deleteProperty(navigator, "clipboard");
    window.history.replaceState(null, "", "/");
  });

  it("copies unrevealed findings and then narrows the payload with table search", async () => {
    const findings = Array.from({ length: 101 }, (_, index) =>
      finding(index + 1),
    );
    findings[100] = finding(101, {
      templateId: "tail-only-template",
      name: "Tail-only finding",
    });
    mockRequests(findings);
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });

    render(
      <ScanDetailView id="scan-1" onBack={vi.fn()} onOpenPlayground={vi.fn()} />,
    );

    const copy = await screen.findByRole("button", {
      name: "Copy visible findings for an LLM",
    });
    await waitFor(() => expect(copy).toBeEnabled());
    fireEvent.click(copy);

    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    expect(writeText.mock.calls[0][0]).toContain("Tail-only finding");
    expect(writeText.mock.calls[0][0]).toContain('"rate-limit": 50');

    fireEvent.change(
      screen.getByPlaceholderText("Search findings, hosts, templates…"),
      { target: { value: "tail-only-template" } },
    );
    expect(await screen.findByText("Tail-only finding")).toBeInTheDocument();
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Copy visible findings for an LLM",
      }),
    );

    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(2));
    expect(writeText.mock.calls[1][0]).toContain("Visible findings: 1");
    expect(writeText.mock.calls[1][0]).toContain("Tail-only finding");
    expect(writeText.mock.calls[1][0]).not.toContain("Shared finding 1\n");
  });

  it("surfaces a rejected clipboard write", async () => {
    mockRequests([finding(1)]);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: vi.fn().mockRejectedValue(new Error("clipboard denied")),
      },
    });

    render(
      <ScanDetailView id="scan-1" onBack={vi.fn()} onOpenPlayground={vi.fn()} />,
    );

    const copy = await screen.findByRole("button", {
      name: "Copy visible findings for an LLM",
    });
    await waitFor(() => expect(copy).toBeEnabled());
    fireEvent.click(copy);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "clipboard denied",
    );
    expect(screen.getByRole("button", { name: "Copy failed" })).toBeEnabled();
  });
});
