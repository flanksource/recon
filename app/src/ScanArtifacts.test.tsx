// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ScanArtifacts } from "./ScanArtifacts";

const DIR = "/srv/recon/results/nuclei/2026-08-12/nuclei-safe-20260812-093000";

// The real API client is exercised rather than mocked out, so the route these
// links point at is the route the panel actually calls.
function mockFetch(status: number, body: unknown) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = typeof input === "string" ? input : (input as Request).url;
    expect(url).toBe("/api/scan/scan-1/files");
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  });
}

describe("ScanArtifacts", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("links every retained file and shows where the directory is on disk", async () => {
    mockFetch(200, {
      scanId: "scan-1",
      path: DIR,
      files: [
        { name: "findings.jsonl", size: 4096, modified: "2026-08-12T09:31:00Z" },
        { name: "targets.txt", size: 120, modified: "2026-08-12T09:30:00Z" },
      ],
    });

    render(<ScanArtifacts scanId="scan-1" path={DIR} />);

    const findings = await screen.findByRole("link", { name: "findings.jsonl" });
    expect(findings).toHaveAttribute("href", "/api/scan/scan-1/files/findings.jsonl");
    expect(screen.getByRole("link", { name: "targets.txt" })).toBeInTheDocument();
    expect(screen.getByText(DIR)).toBeInTheDocument();
    expect(screen.getByText("4.0 KiB")).toBeInTheDocument();
    // The listing says what each file is for, so the answer to "which of these
    // do I open" does not require knowing the engine's conventions.
    expect(screen.getByText("The engine's own output, one result per line")).toBeInTheDocument();
  });

  it("does not ask the server about a run that kept nothing", () => {
    const fetchMock = mockFetch(200, {});

    render(<ScanArtifacts scanId="scan-1" />);

    expect(fetchMock).not.toHaveBeenCalled();
    expect(screen.getByText(/ran before results were retained on disk/)).toBeInTheDocument();
  });

  // A directory that has been pruned or moved is not a run that produced
  // nothing, and the panel has to say which it is looking at.
  it("surfaces a directory the server can no longer read", async () => {
    mockFetch(410, { error: "read scan artifacts: no such file or directory" });

    render(<ScanArtifacts scanId="scan-1" path={DIR} />);

    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent("read scan artifacts"),
    );
    expect(screen.queryAllByRole("link")).toHaveLength(0);
  });

  it("says so when a run's directory is there but empty", async () => {
    mockFetch(200, { scanId: "scan-1", path: DIR, files: [] });

    render(<ScanArtifacts scanId="scan-1" path={DIR} />);

    expect(await screen.findByText("The directory is empty.")).toBeInTheDocument();
  });

  // A compliance run writes one report per account, named after the account.
  // The names are not knowable in advance, so they are described by shape.
  it("describes a per-account report and names the account", async () => {
    mockFetch(200, {
      scanId: "scan-1",
      path: DIR,
      files: [
        { name: "inspec-acme-platform-prod.json", size: 412_000, modified: "2026-08-20T09:41:12Z" },
      ],
    });

    render(<ScanArtifacts scanId="scan-1" path={DIR} />);

    expect(
      await screen.findByText(/Full InSpec report for acme-platform-prod/),
    ).toBeInTheDocument();
  });

  it("still lists a file it has no description for", async () => {
    // An engine may write more than recon knows about, and hiding a file
    // because it is unfamiliar is the opposite of retaining evidence.
    mockFetch(200, {
      scanId: "scan-1",
      path: DIR,
      files: [{ name: "vendor.lock", size: 120, modified: "2026-08-20T09:41:12Z" }],
    });

    render(<ScanArtifacts scanId="scan-1" path={DIR} />);

    expect(await screen.findByRole("link", { name: "vendor.lock" })).toBeInTheDocument();
  });
});
