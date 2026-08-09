// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { createRef } from "react";
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ScanRunStatus } from "./ScanRunStatus";
import type { ScanStatus } from "./types";

describe("ScanRunStatus", () => {
  afterEach(cleanup);

  it("summarises a running Nuclei scan and labels streamed stdout and stderr", () => {
    render(
      <ScanRunStatus
        status={
          {
            phase: "running",
            profile: "full",
            group: "prod",
            hosts: ["api.example.com", "www.example.com"],
            file: "full-prod-20260809.jsonl",
            startedAt: "2026-08-09T08:00:00.000Z",
            finishedAt: null,
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
            findings: [],
            log: "",
            error: null,
            command: ["nuclei", "-config", ".gen/scan-profile.yaml"],
            exitCode: null,
            observations: null,
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
    expect(screen.getByText("25 / 100")).toBeInTheDocument();
    expect(screen.getByText("18")).toBeInTheDocument();
    expect(screen.getByText("nuclei -config .gen/scan-profile.yaml")).toBeInTheDocument();
    const output = screen.getByRole("log", { name: "Live scan output" });
    expect(within(output).getByText("stdout")).toBeInTheDocument();
    expect(within(output).getByText("stderr")).toBeInTheDocument();
    expect(output).toHaveTextContent("loaded 18 templates");
    expect(output).toHaveTextContent("retrying one request");
  });

  it("reports refreshed observations and output for a completed discovery rescan", () => {
    render(
      <ScanRunStatus
        status={
          {
            phase: "done",
            profile: "discovery",
            group: "public",
            hosts: ["www.example.com"],
            file: null,
            startedAt: "2026-08-09T08:00:00.000Z",
            finishedAt: "2026-08-09T08:00:03.000Z",
            stats: null,
            findings: [],
            log: "",
            error: null,
            command: ["httpx", "-config", "config/discovery.httpx.yaml"],
            exitCode: 0,
            observations: 1,
            output: [
              {
                sequence: 1,
                timestamp: "2026-08-09T08:00:03.000Z",
                stream: "system",
                text: "refreshed 1 target observation\n",
              },
            ],
          } as ScanStatus
        }
        logRef={createRef<HTMLDivElement>()}
      />,
    );

    expect(screen.getByText("Discovery rescan")).toBeInTheDocument();
    expect(screen.getByText("1 observation refreshed")).toBeInTheDocument();
    expect(screen.getByText("exit 0")).toBeInTheDocument();
    expect(screen.getByRole("log", { name: "Live scan output" })).toHaveTextContent(
      "refreshed 1 target observation",
    );
  });
});
