// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useScanStatus } from "./useScanStatus";
import type { ScanStatus } from "./types";

const idle = {
  phase: "idle",
  profile: null,
  group: null,
  hosts: [],
  file: null,
  startedAt: null,
  finishedAt: null,
  stats: null,
  findings: [],
  log: "",
  error: null,
  command: null,
  exitCode: null,
  observations: null,
  output: [],
} as ScanStatus;

class FakeEventSource {
  static instance: FakeEventSource | null = null;
  onmessage: ((event: MessageEvent<string>) => void) | null = null;
  onerror: (() => void) | null = null;
  readonly url: string;
  closed = false;

  constructor(url: string | URL) {
    this.url = String(url);
    FakeEventSource.instance = this;
  }

  emit(status: ScanStatus) {
    this.onmessage?.(new MessageEvent("message", { data: JSON.stringify(status) }));
  }

  close() {
    this.closed = true;
  }
}

function Probe({ onFinish }: { onFinish: (status: ScanStatus) => void }) {
  const { status } = useScanStatus(onFinish);
  return <output>{`${status?.phase ?? "loading"}:${status?.output.length ?? 0}`}</output>;
}

describe("useScanStatus", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    FakeEventSource.instance = null;
  });

  it("receives scan status events without polling and reports the finished transition", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify(idle), { status: 200 }),
    );
    vi.stubGlobal("EventSource", FakeEventSource);
    const onFinish = vi.fn();

    const view = render(<Probe onFinish={onFinish} />);
    await screen.findByText("idle:0");
    expect(FakeEventSource.instance?.url).toBe("/api/scan/events");

    act(() => {
      FakeEventSource.instance?.emit({
        ...idle,
        phase: "running",
        profile: "safe",
        output: [
          {
            sequence: 1,
            timestamp: "2026-08-09T08:00:01.000Z",
            stream: "stdout",
            text: "template loaded\n",
          },
        ],
      });
    });
    expect(screen.getByText("running:1")).toBeInTheDocument();

    act(() => {
      FakeEventSource.instance?.emit({ ...idle, phase: "done" });
    });
    await waitFor(() => expect(onFinish).toHaveBeenCalledOnce());
    expect(globalThis.fetch).toHaveBeenCalledOnce();

    view.unmount();
    expect(FakeEventSource.instance?.closed).toBe(true);
  });
});
