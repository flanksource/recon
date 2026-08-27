// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
    pinned: 0,
    pushed: 0,
    configs: [{ id: "cfg-1", name: "api.example.test", type: "Kubernetes::Ingress", insights: 3 }],
    unresolved: [],
    ambiguous: [],
    ...overrides,
  };
}

const ambiguity = {
  identity: "workload-prod-eu-02",
  scope: true,
  states: 12,
  resources: ["web-1", "web-2"],
  options: [
    { id: "eb6a8af6", name: "workload-prod-eu-02", type: "GCP::Project" },
    { id: "03525cee", name: "workload-prod-eu-02", type: "Kubernetes::Cluster" },
    { id: "9f0c1d22", name: "acme-root", type: "GCP::Organization", root: true, ancestor: true },
  ],
};

// The task list the modal shows while a sync runs is the server's, polled over
// the same API the tasks page uses; nothing here is running, so it answers empty.
function withQueryClient(element: ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={client}>{element}</QueryClientProvider>;
}

describe("SyncInsightsButton", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(
      new Response("[]", { headers: { "content-type": "application/json" } }),
    ));
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("previews the exact selection before syncing it", async () => {
    const sync = vi.fn()
      .mockResolvedValueOnce(result({ dryRun: true }))
      .mockResolvedValueOnce(result({ pushed: 3 }));

    render(withQueryClient(<SyncInsightsButton sync={sync} />));
    fireEvent.click(screen.getByRole("button", { name: "Sync insights" }));

    expect(await screen.findByRole("button", { name: "Sync 3 insights" })).toBeInTheDocument();
    expect(sync).toHaveBeenCalledExactlyOnceWith({ dryRun: true });
    expect(screen.getByText("Open").previousSibling).toHaveTextContent("1");
    expect(screen.getByText("Resolved").previousSibling).toHaveTextContent("1");
    expect(screen.getByText("Silenced").previousSibling).toHaveTextContent("1");

    fireEvent.click(screen.getByRole("button", { name: "Sync 3 insights" }));
    await waitFor(() => expect(sync).toHaveBeenLastCalledWith({ dryRun: false, choices: {} }));
    expect(await screen.findByText("Pushed")).toBeInTheDocument();
  });

  it("does not offer to sync when no eligible state resolves to a catalog item", async () => {
    const sync = vi.fn().mockResolvedValue(result({
      eligible: 1,
      direct: 0,
      rolledUp: 0,
      unresolved: [{ finding: "prowler/check", tried: ["gcp/project/resource"], reason: "not found" }],
    }));

    render(withQueryClient(<SyncInsightsButton sync={sync} />));
    fireEvent.click(screen.getByRole("button", { name: "Sync insights" }));

    await screen.findByText("No resolvable insights match this selection.");
    expect(screen.queryByRole("button", { name: /^Sync \d/ })).not.toBeInTheDocument();
  });

  it("groups unresolved states by why nothing claimed them", async () => {
    const sync = vi.fn().mockResolvedValue(result({
      unresolved: [
        { finding: "prowler/a", host: "bucket-1", tried: [], reason: "no catalog config item matches" },
        { finding: "prowler/b", host: "bucket-2", tried: [], reason: "no catalog config item matches" },
      ],
    }));

    render(withQueryClient(<SyncInsightsButton sync={sync} />));
    fireEvent.click(screen.getByRole("button", { name: "Sync insights" }));

    expect(await screen.findByText(/no catalog config item matches/)).toBeInTheDocument();
    expect(screen.getByText("2×")).toBeInTheDocument();
    expect(screen.getByText("bucket-1, bucket-2")).toBeInTheDocument();
  });

  it("sends the config item chosen for an identity several config items carry", async () => {
    const sync = vi.fn()
      .mockResolvedValueOnce(result({ dryRun: true, ambiguous: [ambiguity] }))
      .mockResolvedValueOnce(result({ pushed: 15, ambiguous: [{ ...ambiguity, chosen: "03525cee" }] }));

    render(withQueryClient(<SyncInsightsButton sync={sync} />));
    fireEvent.click(screen.getByRole("button", { name: "Sync insights" }));

    // Nothing is chosen for it yet, so only what already resolved is offered.
    expect(await screen.findByRole("button", { name: "Sync 3 insights" })).toBeInTheDocument();
    expect(screen.getByText("workload-prod-eu-02")).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: "acme-root · GCP::Organization · contains the matches · root" }))
      .toBeInTheDocument();

    fireEvent.click(screen.getByRole("radio", {
      name: "workload-prod-eu-02 · Kubernetes::Cluster",
    }));

    // The twelve states riding on that identity join the count without a
    // second round trip to the catalog.
    fireEvent.click(await screen.findByRole("button", { name: "Sync 15 insights" }));
    await waitFor(() => expect(sync).toHaveBeenLastCalledWith({
      dryRun: false,
      choices: { "workload-prod-eu-02": "03525cee" },
    }));
    expect(await screen.findByText("Pushed")).toBeInTheDocument();
  });

  it("can re-preview with the choices before committing to them", async () => {
    const sync = vi.fn().mockResolvedValue(result({ dryRun: true, ambiguous: [ambiguity] }));

    render(withQueryClient(<SyncInsightsButton sync={sync} />));
    fireEvent.click(screen.getByRole("button", { name: "Sync insights" }));

    await screen.findByRole("button", { name: "Sync 3 insights" });
    expect(screen.queryByRole("button", { name: "Preview with choices" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("radio", { name: "workload-prod-eu-02 · GCP::Project" }));
    fireEvent.click(await screen.findByRole("button", { name: "Preview with choices" }));

    await waitFor(() => expect(sync).toHaveBeenLastCalledWith({
      dryRun: true,
      choices: { "workload-prod-eu-02": "eb6a8af6" },
    }));
  });
});
