// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { createRef } from "react";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchFindings } from "./api";
import { ScanRunStatus } from "./ScanRunStatus";
import { emptySeverities, type Finding, type ScanStatus } from "./types";

vi.mock("./api", () => ({
  fetchFindings: vi.fn(),
}));

const fetchFindingsMock = vi.mocked(fetchFindings);

describe("ScanRunStatus", () => {
  afterEach(() => {
    cleanup();
    fetchFindingsMock.mockReset();
  });

  it("summarises a running Nuclei scan and labels streamed stdout and stderr", () => {
    render(
      <ScanRunStatus
        status={
          {
            phase: "running",
            profile: "full",
            selectorLabel: "class prod",
            hosts: ["api.example.com", "www.example.com"],
            id: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            name: "full-prod-20260809-080000",
            startedAt: "2026-08-09T08:00:00.000Z",
            finishedAt: undefined,
            stats: {
              requests: 25,
              total: 100,
              percent: 25,
              rps: 12,
              matched: 1,
              errors: 2,
              hosts: 2,
              templates: 18,
              duration: "5s",
            },
            findings: 0,
            severities: emptySeverities(),
            log: "",
            error: undefined,
            command: ["nuclei", "-config", ".gen/scan-profile.yaml"],
            exitCode: undefined,
            output: [
              {
                sequence: 1,
                timestamp: "2026-08-09T08:00:01.000Z",
                stream: "stdout",
                text: "loaded 18 templates\n",
              },
              {
                sequence: 2,
                timestamp: "2026-08-09T08:00:02.000Z",
                stream: "stderr",
                text: "retrying one request\n",
              },
            ],
          } as ScanStatus
        }
        logRef={createRef<HTMLDivElement>()}
      />,
    );

    expect(screen.getByText("Nuclei full scan")).toBeInTheDocument();
    expect(screen.getByText("class prod")).toBeInTheDocument();
    expect(screen.getByText("25 / 100")).toBeInTheDocument();
    expect(screen.getByText("18")).toBeInTheDocument();
    expect(screen.getByText("nuclei -config .gen/scan-profile.yaml")).toBeInTheDocument();
    const output = screen.getByRole("log", { name: "Live scan output" });
    expect(within(output).getByText("stdout")).toBeInTheDocument();
    expect(within(output).getByText("stderr")).toBeInTheDocument();
    expect(output).toHaveTextContent("loaded 18 templates");
    expect(output).toHaveTextContent("retrying one request");
    expect(fetchFindingsMock).not.toHaveBeenCalled();
  });

  it("renders Nuclei's zero-total percentage overflow as unknown progress", () => {
    fetchFindingsMock.mockResolvedValue([]);
    const status: ScanStatus = {
      phase: "failed",
      profile: "safe",
      hosts: [],
      id: "overflow-scan",
      name: "nuclei-safe-overflow",
      engine: "nuclei",
      selector: {},
      selectorLabel: "host app.example.test",
      endpointCount: 1,
      startedAt: "2026-08-10T12:45:19.000Z",
      stats: {
        requests: 0,
        total: 0,
        percent: 9223372036854776000,
        rps: 0,
        matched: 0,
        errors: 0,
        hosts: 1,
        templates: 0,
        duration: "0:00:01",
      },
      findings: 0,
      severities: emptySeverities(),
      running: false,
      log: "",
      output: [],
    };
    render(
      <ScanRunStatus
        status={status}
        logRef={createRef<HTMLDivElement>()}
      />,
    );

    expect(screen.getByText("0%")).toBeInTheDocument();
    expect(screen.queryByText(/922337203685477/)).not.toBeInTheDocument();
  });

  it("fetches and renders findings once the scan reaches a terminal phase", async () => {
    const findings: Finding[] = [
      {
        scanId: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        lineNo: 1,
        templateId: "tls-version",
        name: "Deprecated TLS version",
        severity: "high",
        host: "api.example.com",
        matchedAt: "https://api.example.com",
        tags: ["tls"],
      },
    ];
    fetchFindingsMock.mockResolvedValue(findings);

    render(
      <ScanRunStatus
        status={
          {
            phase: "done",
            profile: "full",
            selectorLabel: "class public",
            hosts: ["api.example.com"],
            id: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            name: "full-public-20260809-080000",
            startedAt: "2026-08-09T08:00:00.000Z",
            finishedAt: "2026-08-09T08:00:03.000Z",
            stats: undefined,
            findings: 1,
            severities: { ...emptySeverities(), high: 1 },
            log: "",
            error: undefined,
            command: ["nuclei", "-config", ".gen/scan-profile.yaml"],
            exitCode: 0,
            output: [
              {
                sequence: 1,
                timestamp: "2026-08-09T08:00:03.000Z",
                stream: "system",
                text: "scan finished\n",
              },
            ],
          } as ScanStatus
        }
        logRef={createRef<HTMLDivElement>()}
      />,
    );

    expect(fetchFindingsMock).toHaveBeenCalledWith({ scan: "01ARZ3NDEKTSV4RRFFQ69G5FAV" });
    expect(screen.getByText("exit 0")).toBeInTheDocument();
    expect(screen.getByText("1 finding")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("Deprecated TLS version")).toBeInTheDocument());
    expect(screen.getByText("tls-version")).toBeInTheDocument();
  });
});
