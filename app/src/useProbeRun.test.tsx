// @vitest-environment jsdom
import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as api from "./api";
import { useProbeRun } from "./useProbeRun";
import type { ProbeResult, ProbeRun } from "./types";

vi.mock("./api", () => ({ fetchProbe: vi.fn() }));

function result(host: string, up = true): ProbeResult {
  return { host, up, responseTimeMs: 10, updated: true };
}

function makeRun(overrides: Partial<ProbeRun> = {}): ProbeRun {
  return {
    id: "01JPROBE",
    selector: {},
    selectorLabel: "class non-prod",
    phase: "running",
    ranAt: "2026-08-11T09:00:00",
    durationMs: 0,
    total: 3,
    live: 0,
    updated: 0,
    results: [],
    ...overrides,
  };
}

describe("useProbeRun", () => {
  // The poll interval is a real second. Waiting it out would make every spec
  // here take longer than the behaviour it checks, so time is driven instead.
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  // Lets the in-flight fetch settle without advancing the clock, which is what
  // the first poll needs — it runs immediately rather than on a timer.
  const settle = async () => {
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
  };

  // One poll interval, with the promises that tick queues allowed to settle.
  // Asserted directly rather than through waitFor, which drives its own timers
  // and deadlocks against these.
  const tick = async () => {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
  };

  it("does not ask about a run that has not started", () => {
    renderHook(() => useProbeRun(null));

    expect(api.fetchProbe).not.toHaveBeenCalled();
  });

  it("follows a run until it reaches a terminal phase, then stops", async () => {
    vi.mocked(api.fetchProbe)
      .mockResolvedValueOnce(makeRun({ results: [result("one.example.test")] }))
      .mockResolvedValue(
        makeRun({ phase: "done", live: 2, results: [result("one.example.test"), result("two.example.test")] }),
      );

    const view = renderHook(() => useProbeRun("01JPROBE"));

    await settle();
    await tick();
    expect(view.result.current.run?.phase).toBe("done");

    // A terminal run is not polled again; without the phase check the dialog
    // would keep requesting until it was closed.
    const calls = vi.mocked(api.fetchProbe).mock.calls.length;
    await tick();
    await tick();
    expect(vi.mocked(api.fetchProbe).mock.calls.length).toBe(calls);
  });

  it("reports each host once, as its result appears", async () => {
    vi.mocked(api.fetchProbe)
      .mockResolvedValueOnce(makeRun({ results: [result("one.example.test")] }))
      .mockResolvedValue(
        makeRun({
          phase: "done",
          // The first host is still in the payload — every poll returns the whole
          // run — so a caller that did not track what it had seen would refresh
          // the same inventory row on every tick.
          results: [result("one.example.test"), result("two.example.test")],
        }),
      );
    const onHosts = vi.fn();

    renderHook(() => useProbeRun("01JPROBE", onHosts));

    await settle();
    await tick();
    expect(onHosts).toHaveBeenCalledTimes(2);
    expect(onHosts.mock.calls).toEqual([
      [["one.example.test"]],
      [["two.example.test"]],
    ]);
  });

  it("surfaces a failed poll without discarding what it already showed", async () => {
    vi.mocked(api.fetchProbe)
      .mockResolvedValueOnce(makeRun({ results: [result("one.example.test")] }))
      .mockRejectedValue(new Error("probe 01JPROBE not found"));

    const view = renderHook(() => useProbeRun("01JPROBE"));

    await settle();
    await tick();
    expect(view.result.current.error).toBe("probe 01JPROBE not found");
    expect(view.result.current.run?.results).toHaveLength(1);
  });
});
