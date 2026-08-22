// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { UploadInsightsButton } from "./UploadInsightsButton";
import { uploadScan } from "./api";
import { emptySeverities, type Scan, type Upload } from "./types";

vi.mock("./api", () => ({
  uploadScan: vi.fn(),
}));

const uploadScanMock = vi.mocked(uploadScan);

function scan(overrides: Partial<Scan> = {}): Scan {
  return {
    id: "01JSCAN",
    name: "nuclei-safe-1",
    engine: "nuclei",
    profile: "safe",
    selector: {},
    selectorLabel: "class non-prod",
    endpointCount: 3,
    phase: "done",
    startedAt: "2026-08-10T12:00:00",
    finishedAt: "2026-08-10T12:00:20",
    durationMs: 20000,
    findings: 2,
    severities: { ...emptySeverities(), high: 2 },
    hosts: ["api.example.test"],
    ...overrides,
  };
}

function result(overrides: Partial<Upload> = {}): Upload {
  return {
    scanId: "01JSCAN",
    engine: "nuclei",
    agent: "recon",
    server: "https://mc.example.test",
    findings: 2,
    total: 2,
    pushed: 0,
    resolved: 2,
    rolledUp: 0,
    configs: [
      { id: "cfg-1", name: "api.example.test", type: "Kubernetes::Ingress", insights: 2 },
    ],
    unresolved: [],
    ...overrides,
  };
}

describe("UploadInsightsButton", () => {
  afterEach(() => {
    cleanup();
    uploadScanMock.mockReset();
  });

  // The preview is the whole point: nothing reaches Mission Control until
  // someone has seen how much of the run resolves and confirms it.
  it("previews with a dry run and pushes nothing until confirmed", async () => {
    uploadScanMock.mockResolvedValue(result({ dryRun: true }));

    render(<UploadInsightsButton scan={scan()} />);
    fireEvent.click(screen.getByRole("button", { name: "Upload insights" }));

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Push 2 insights" })).toBeInTheDocument(),
    );
    expect(uploadScanMock).toHaveBeenCalledExactlyOnceWith("01JSCAN", { dryRun: true });
    expect(screen.getByText("Kubernetes::Ingress", { exact: false })).toBeInTheDocument();
  });

  it("pushes for real once confirmed and reports what landed", async () => {
    uploadScanMock.mockResolvedValueOnce(result({ dryRun: true }));
    uploadScanMock.mockResolvedValueOnce(result({ pushed: 2 }));

    render(<UploadInsightsButton scan={scan()} />);
    fireEvent.click(screen.getByRole("button", { name: "Upload insights" }));
    fireEvent.click(await screen.findByRole("button", { name: "Push 2 insights" }));

    await waitFor(() => expect(screen.getByText("Pushed")).toBeInTheDocument());
    expect(uploadScanMock).toHaveBeenLastCalledWith("01JSCAN", { dryRun: false });
  });

  // Everything rolling up means the catalog does not hold what recon scanned,
  // which the reader has to be able to see before pushing.
  it("separates what landed on the resource from what rolled up", async () => {
    uploadScanMock.mockResolvedValue(
      result({
        dryRun: true,
        resolved: 1,
        rolledUp: 1,
        configs: [
          { id: "cfg-1", name: "api.example.test", type: "Kubernetes::Ingress", insights: 1 },
          { id: "cfg-2", name: "prod-euw1", type: "Kubernetes::Cluster", insights: 1, rolledUp: true },
        ],
      }),
    );

    render(<UploadInsightsButton scan={scan()} />);
    fireEvent.click(screen.getByRole("button", { name: "Upload insights" }));

    await waitFor(() => expect(screen.getByText("Rolled up")).toBeInTheDocument());
    expect(screen.getByText("prod-euw1", { exact: false }).textContent).toContain("rolled up");
    expect(screen.getByText("api.example.test", { exact: false }).textContent).not.toContain(
      "rolled up",
    );
  });

  it("lists findings nothing in the catalog claims", async () => {
    uploadScanMock.mockResolvedValue(
      result({
        dryRun: true,
        resolved: 1,
        unresolved: [
          {
            finding: "01JSCAN#2",
            host: "unknown.example.test",
            severity: "low",
            tried: ["https://unknown.example.test/x", "unknown.example.test"],
            reason: "no catalog config item matches",
          },
        ],
      }),
    );

    render(<UploadInsightsButton scan={scan()} />);
    fireEvent.click(screen.getByRole("button", { name: "Upload insights" }));

    await waitFor(() =>
      expect(screen.getByText("unknown.example.test")).toBeInTheDocument(),
    );
    expect(screen.getByText("tried", { exact: false })).toBeInTheDocument();
  });

  // The credential lives on the server, so an unconfigured faro context is the
  // most likely failure and has to name the command that fixes it.
  it("surfaces a rejected upload rather than looking like it worked", async () => {
    uploadScanMock.mockRejectedValue(
      new Error("no Mission Control server context configured; run `faro auth login --server <url>`"),
    );

    render(<UploadInsightsButton scan={scan()} />);
    fireEvent.click(screen.getByRole("button", { name: "Upload insights" }));

    await waitFor(() =>
      expect(
        screen.getByText("no Mission Control server context configured", { exact: false }),
      ).toBeInTheDocument(),
    );
    expect(screen.queryByRole("button", { name: /^Push/ })).not.toBeInTheDocument();
  });

  it("offers nothing to upload for a run that has no findings or has not finished", () => {
    const { rerender } = render(<UploadInsightsButton scan={scan({ findings: 0 })} />);
    expect(screen.getByRole("button", { name: "Upload insights" })).toBeDisabled();

    rerender(<UploadInsightsButton scan={scan({ phase: "running" })} />);
    expect(screen.getByRole("button", { name: "Upload insights" })).toBeDisabled();

    rerender(<UploadInsightsButton scan={scan()} />);
    expect(screen.getByRole("button", { name: "Upload insights" })).toBeEnabled();
  });
});
