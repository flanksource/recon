// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ScanExecutionDetails } from "./ScanExecutionDetails";
import { emptySeverities, type Scan } from "./types";

const SCAN: Scan = {
  id: "scan-1",
  name: "nuclei-safe-20260810-120000",
  engine: "nuclei",
  engineVersion: "3.4.10",
  profile: "safe",
  selector: { hosts: ["api.example.test"] },
  selectorLabel: "host api.example.test",
  endpointCount: 3,
  phase: "done",
  startedAt: "2026-08-10T12:00:00",
  finishedAt: "2026-08-10T12:00:02",
  durationMs: 2500,
  command: [
    "/opt/recon/bin/nuclei",
    "-target",
    "api value",
    "-output",
    "/workspace/.gen/scan-019feb2d-a8ba-61dd-da9b-747d63b66200/findings.jsonl",
    "-stats",
  ],
  exitCode: 0,
  findings: 4,
  severities: { ...emptySeverities(), high: 1, medium: 3 },
  stats: {
    requests: 40,
    total: 60,
    percent: 66.7,
    rps: 12,
    matched: 4,
    errors: 2,
    hosts: 3,
    templates: 18,
    duration: "2s",
  },
  hosts: ["api.example.test", "admin.example.test"],
  outputCaptured: true,
  stdout: "loaded 18 templates\n",
  stderr: "retried one request\n",
  stdoutTruncated: true,
  stderrTruncated: false,
};

describe("ScanExecutionDetails", () => {
  afterEach(cleanup);

  it("renders exact argv, runtime, target/request stats, and captured streams", () => {
    render(<ScanExecutionDetails scan={SCAN} />);

    const command = screen.getByLabelText("Command and arguments");
    expect(within(command).getByText("/opt/recon/bin/nuclei")).toHaveAttribute("data-command-part", "executable");
    expect(within(command).getByText("-target")).toHaveAttribute("data-command-part", "flag");
    expect(within(command).getByText("api value")).toHaveAttribute("data-command-part", "value");
    expect(within(command).getByText(/findings\.jsonl$/)).toHaveClass("break-all");
    expect(command).not.toHaveTextContent('["/opt/recon/bin/nuclei"');
    expect(screen.getByText("2.5s")).toBeInTheDocument();
    expect(screen.getByText("targets").parentElement).toHaveTextContent("3");
    expect(screen.getByText("requests").parentElement).toHaveTextContent("40 / 60");
    expect(screen.getByText("templates").parentElement).toHaveTextContent("18");
    expect(screen.getByText("matched").parentElement).toHaveTextContent("4");
    expect(screen.getByText("errors").parentElement).toHaveTextContent("2");
    expect(screen.getByText("profile").parentElement).toHaveTextContent("safe");
    expect(screen.getByText("selector").parentElement).toHaveTextContent("host api.example.test");
    expect(screen.getByText("loaded 18 templates")).toBeInTheDocument();
    expect(screen.getByText("retried one request")).toBeInTheDocument();
    expect(screen.getByText("showing latest 1 MiB")).toBeInTheDocument();
  });

  it("distinguishes legacy scans whose process output was never captured", () => {
    render(<ScanExecutionDetails scan={{ ...SCAN, outputCaptured: false, stdout: undefined, stderr: undefined }} />);

    expect(screen.getByText("Process output was not captured for this scan.")).toBeInTheDocument();
  });
});
