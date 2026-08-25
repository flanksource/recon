// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SyncInsightsButton } from "./SyncInsightsButton";
import type { InsightSync } from "./types";

function result(overrides: Partial<InsightSync> = {}): InsightSync {
  return {
    agent: "recon",
    server: "https://mc.example.test",
    matchedResources: 3,
    matchedStates: 4,
    eligible: 3,
    skipped: 1,
    open: 1,
    resolved: 1,
    silenced: 1,
    direct: 2,
    rolledUp: 1,
    pushed: 0,
    configs: [{ id: "cfg-1", name: "api.example.test", type: "Kubernetes::Ingress", insights: 3 }],
    unresolved: [],
    ...overrides,
  };
}

describe("SyncInsightsButton", () => {
  afterEach(cleanup);

  it("previews the exact selection before syncing it", async () => {
    const sync = vi.fn()
      .mockResolvedValueOnce(result({ dryRun: true }))
      .mockResolvedValueOnce(result({ pushed: 3 }));

    render(<SyncInsightsButton sync={sync} />);
    fireEvent.click(screen.getByRole("button", { name: "Sync insights" }));

    expect(await screen.findByRole("button", { name: "Sync 3 insights" })).toBeInTheDocument();
    expect(sync).toHaveBeenCalledExactlyOnceWith(true);
    expect(screen.getByText("Open").previousSibling).toHaveTextContent("1");
    expect(screen.getByText("Resolved").previousSibling).toHaveTextContent("1");
    expect(screen.getByText("Silenced").previousSibling).toHaveTextContent("1");

    fireEvent.click(screen.getByRole("button", { name: "Sync 3 insights" }));
    await waitFor(() => expect(sync).toHaveBeenLastCalledWith(false));
    expect(await screen.findByText("Pushed")).toBeInTheDocument();
  });

  it("does not offer to sync when no eligible state resolves to a catalog item", async () => {
    const sync = vi.fn().mockResolvedValue(result({
      eligible: 1,
      direct: 0,
      rolledUp: 0,
      unresolved: [{ finding: "prowler/check", tried: ["gcp/project/resource"], reason: "not found" }],
    }));

    render(<SyncInsightsButton sync={sync} />);
    fireEvent.click(screen.getByRole("button", { name: "Sync insights" }));

    await screen.findByText("No resolvable insights match this selection.");
    expect(screen.queryByRole("button", { name: /^Sync \d/ })).not.toBeInTheDocument();
  });
});
