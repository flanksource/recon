// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ScanDialog } from "./ScanDialog";
import type { ScanStatus, TargetRow } from "./types";

const rows: TargetRow[] = [
  {
    $schema: "../target.schema.json",
    version: 1,
    host: "api.example.com",
    class: "prod",
    profiles: ["safe"],
    tags: ["api"],
  },
  {
    $schema: "../target.schema.json",
    version: 1,
    host: "docs.example.com",
    class: "public",
    profiles: ["safe"],
    tags: ["docs"],
  },
];

const running: ScanStatus = {
  phase: "running",
  profile: "discovery",
  group: "prod",
  hosts: ["api.example.com"],
  file: null,
  startedAt: "2026-08-09T08:00:00.000Z",
  finishedAt: null,
  stats: null,
  findings: [],
  log: ">>> httpx discovery rescan of 1 host\n",
  error: null,
  command: ["httpx", "-config", "config/discovery.httpx.yaml"],
  exitCode: null,
  observations: null,
  output: [
    {
      sequence: 1,
      timestamp: "2026-08-09T08:00:00.000Z",
      stream: "system",
      text: ">>> httpx discovery rescan of 1 host\n",
    },
  ],
};

describe("ScanDialog", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("rescans the selected targets with the discovery profile", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify(running), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    const onStatus = vi.fn();

    render(
      <ScanDialog
        open
        onClose={vi.fn()}
        rows={rows}
        savedHosts={rows.map((row) => row.host)}
        selectedHosts={["api.example.com"]}
        status={null}
        onStatus={onStatus}
        onOpenScan={vi.fn()}
      />,
    );

    fireEvent.change(screen.getByLabelText("Profile"), {
      target: { value: "discovery" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Rescan 1 host" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/scan",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            hosts: ["api.example.com"],
            profile: "discovery",
            confirm: false,
          }),
        }),
      ),
    );
    expect(onStatus).toHaveBeenCalledWith(running);
  });

  it("requires new targets to be saved before discovery observations can be rescanned", () => {
    render(
      <ScanDialog
        open
        onClose={vi.fn()}
        rows={rows}
        savedHosts={[]}
        selectedHosts={["api.example.com"]}
        status={null}
        onStatus={vi.fn()}
      />,
    );

    fireEvent.change(screen.getByLabelText("Profile"), {
      target: { value: "discovery" },
    });

    expect(
      screen.getByRole("button", { name: "Rescan 1 host" }),
    ).toBeDisabled();
    expect(
      screen.getByText(
        "Save 1 new target before rescanning discovery observations.",
      ),
    ).toBeInTheDocument();
  });
});
