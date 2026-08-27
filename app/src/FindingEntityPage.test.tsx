// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FindingEntityPage } from "./FindingEntityPage";
import { fetchFinding } from "./api-scans";
import type { Finding } from "./types";

vi.mock("./api-scans", () => ({ fetchFinding: vi.fn() }));

const fetchFindingMock = vi.mocked(fetchFinding);

const FINDING_ID = "01a039ab-c7d5-c07e-567f-14e80ba75d06";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: FINDING_ID,
    scanId: "01JSCAN",
    lineNo: 2,
    targetId: "gcp-prod",
    checkId: "gcp/bigquery_dataset_cmk_encryption",
    engine: "prowler",
    host: "workload-prod-eu-02",
    matchedAt: "workload-prod-eu-02:default",
    severity_id: 4,
    tags: [],
    remediation: { desc: "Recreate the dataset with a customer-managed key." },
    finding_info: { title: "BigQuery dataset is encrypted with Customer-Managed Keys" },
    resources: [{
      id: "01JRESOURCE",
      provider: "gcp",
      scope: "workload-prod-eu-02",
      uid: "workload-prod-eu-02:default",
      name: "default",
    }],
    ...overrides,
  } as Finding;
}

function stubMatchMedia() {
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    value: vi.fn().mockReturnValue({
      matches: false,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    }),
  });
}

describe("FindingEntityPage", () => {
  beforeEach(() => {
    stubMatchMedia();
    fetchFindingMock.mockResolvedValue(finding());
  });
  afterEach(cleanup);

  it("titles the page with what the finding says rather than its id", async () => {
    render(<FindingEntityPage id={FINDING_ID} onBack={vi.fn()} />);

    expect(await screen.findByRole("heading", {
      name: "BigQuery dataset is encrypted with Customer-Managed Keys",
    })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: new RegExp(FINDING_ID) })).not.toBeInTheDocument();
    expect(fetchFindingMock).toHaveBeenCalledWith(FINDING_ID);
  });

  it("renders the remediation the engine reported", async () => {
    render(<FindingEntityPage id={FINDING_ID} onBack={vi.fn()} />);

    // Asserted against the body rather than a node handle: the markdown
    // renderer swaps its subtree, so a node captured before that lands is
    // detached by the time it is read.
    expect(await screen.findByText("Recommended action")).toBeInTheDocument();
    await waitFor(() => expect(document.body)
      .toHaveTextContent("Recreate the dataset with a customer-managed key."));
  });

  it("offers a retry rather than a dead end when the fetch fails", async () => {
    fetchFindingMock.mockRejectedValueOnce(new Error("finding 01a039ab not found"));
    const onBack = vi.fn();
    render(<FindingEntityPage id={FINDING_ID} onBack={onBack} />);

    expect(await screen.findByRole("alert")).toHaveTextContent("finding 01a039ab not found");
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());

    expect(await screen.findByRole("heading", {
      name: "BigQuery dataset is encrypted with Customer-Managed Keys",
    })).toBeInTheDocument();
  });
});
