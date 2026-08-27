// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { useState } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MutesView } from "./MutesView";
import { createMute, deleteMute, fetchMutes, previewMute, updateMute } from "./api-mutes";
import { fetchEngines, fetchFilterOptions, fetchFilters } from "./api";
import type { MuteRule } from "./mute-types";

vi.mock("./api-mutes", () => ({
  fetchMutes: vi.fn(),
  createMute: vi.fn(),
  updateMute: vi.fn(),
  deleteMute: vi.fn(),
  previewMute: vi.fn(),
}));

// The targets editor builds its bar from the inventory's own filter vocabulary,
// so the form reaches for these even though no test here drives the bar.
vi.mock("./api", () => ({
  fetchEngines: vi.fn(),
  fetchFilters: vi.fn(() => Promise.resolve([])),
  fetchFilterOptions: vi.fn(() => Promise.resolve([])),
}));

const fetchMutesMock = vi.mocked(fetchMutes);
const createMuteMock = vi.mocked(createMute);
const updateMuteMock = vi.mocked(updateMute);
const deleteMuteMock = vi.mocked(deleteMute);
const previewMuteMock = vi.mocked(previewMute);
const fetchEnginesMock = vi.mocked(fetchEngines);

function rule(overrides: Partial<MuteRule> = {}): MuteRule {
  return {
    name: "accepted-open-redirect",
    comment: "httpbin is a deliberate fixture",
    engines: ["nuclei"],
    templates: ["open-redirect"],
    ...overrides,
  };
}

function engines() {
  return [
    { name: "nuclei", title: "Nuclei" },
    { name: "trivy", title: "Trivy" },
    { name: "prowler", title: "Prowler" },
  ] as unknown as Awaited<ReturnType<typeof fetchEngines>>;
}

/**
 * Stands in for the router. Which rule is open is a route, not component state,
 * so the tests drive it the way App does — and `route` lets one assert where a
 * save navigated to.
 */
const route: { selected?: string } = {};

function Harness({ initial, search }: { initial?: string; search?: string }) {
  const [selected, setSelected] = useState<string | undefined>(initial);
  route.selected = selected;
  return (
    <MutesView
      selected={selected}
      search={search}
      onSelect={(name) => {
        route.selected = name;
        setSelected(name);
      }}
    />
  );
}

// resetAllMocks clears implementations as well as calls, so the filter
// vocabulary the targets editor loads has to be re-established each time.
beforeEach(() => {
  vi.mocked(fetchFilters).mockResolvedValue([]);
  vi.mocked(fetchFilterOptions).mockResolvedValue([]);
});

afterEach(() => {
  cleanup();
  vi.resetAllMocks();
  delete route.selected;
});

describe("the mutes view", () => {
  it("lists the stored rules with what each one covers", async () => {
    fetchMutesMock.mockResolvedValue([rule()]);
    fetchEnginesMock.mockResolvedValue(engines());

    render(<Harness />);

    expect(await screen.findByText("accepted-open-redirect")).toBeInTheDocument();
    expect(screen.getByText("open-redirect")).toBeInTheDocument();
  });

  it("says so when nothing is muted, rather than showing an empty table", async () => {
    fetchMutesMock.mockResolvedValue([]);
    fetchEnginesMock.mockResolvedValue(engines());

    render(<Harness />);

    expect(
      await screen.findByText(/Everything an engine reports is recorded/),
    ).toBeInTheDocument();
  });

  it("marks a rule that is switched off", async () => {
    fetchMutesMock.mockResolvedValue([rule({ disabled: true })]);
    fetchEnginesMock.mockResolvedValue(engines());

    render(<Harness />);

    expect(await screen.findByText("off")).toBeInTheDocument();
    expect(screen.getByText(/1 disabled/)).toBeInTheDocument();
  });

  // The one mistake this surface must not allow: a rule with no scope matches
  // every finding, and a muted finding is not recorded anywhere.
  it("refuses to save a rule that selects nothing", async () => {
    fetchMutesMock.mockResolvedValue([]);
    fetchEnginesMock.mockResolvedValue(engines());

    render(<Harness />);
    fireEvent.click(await screen.findByRole("button", { name: "New rule" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "everything" } });

    expect(screen.getByText(/This rule selects nothing/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create rule" })).toBeDisabled();
    expect(createMuteMock).not.toHaveBeenCalled();
  });

  it("refuses a name that could not be a filename fragment", async () => {
    fetchMutesMock.mockResolvedValue([]);
    fetchEnginesMock.mockResolvedValue(engines());

    render(<Harness />);
    fireEvent.click(await screen.findByRole("button", { name: "New rule" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Accepted Risk" } });
    fireEvent.change(screen.getByLabelText("Checks"), { target: { value: "open-redirect" } });

    expect(screen.getByText(/lowercase letters, digits and dashes/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create rule" })).toBeDisabled();
  });

  it("creates a rule from what was typed", async () => {
    fetchMutesMock.mockResolvedValue([]);
    fetchEnginesMock.mockResolvedValue(engines());
    createMuteMock.mockResolvedValue(rule({ name: "accepted" }));

    render(<Harness />);
    fireEvent.click(await screen.findByRole("button", { name: "New rule" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "accepted" } });
    fireEvent.change(screen.getByLabelText("Checks"), {
      target: { value: "open-redirect, gcp/bucket_*" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create rule" }));

    await waitFor(() => expect(createMuteMock).toHaveBeenCalledTimes(1));
    expect(createMuteMock.mock.calls[0][0]).toMatchObject({
      name: "accepted",
      templates: ["open-redirect", "gcp/bucket_*"],
    });
  });

  // Otherwise a reload after creating reopens an empty draft rather than the
  // rule that was just written.
  it("addresses a created rule by its name once it exists", async () => {
    fetchMutesMock.mockResolvedValue([]);
    fetchEnginesMock.mockResolvedValue(engines());
    createMuteMock.mockResolvedValue(rule({ name: "accepted" }));

    render(<Harness />);
    fireEvent.click(await screen.findByRole("button", { name: "New rule" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "accepted" } });
    fireEvent.change(screen.getByLabelText("Checks"), { target: { value: "open-redirect" } });
    fireEvent.click(screen.getByRole("button", { name: "Create rule" }));

    await waitFor(() => expect(route.selected).toBe("accepted"));
  });

  it("edits an existing rule without renaming it", async () => {
    fetchMutesMock.mockResolvedValue([rule()]);
    fetchEnginesMock.mockResolvedValue(engines());
    updateMuteMock.mockResolvedValue(rule());

    render(<Harness />);
    fireEvent.click(await screen.findByText("accepted-open-redirect"));

    expect(screen.getByLabelText("Name")).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Comment"), { target: { value: "still accepted" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(updateMuteMock).toHaveBeenCalledTimes(1));
    expect(updateMuteMock.mock.calls[0][0]).toBe("accepted-open-redirect");
    expect(updateMuteMock.mock.calls[0][1]).toMatchObject({ comment: "still accepted" });
  });

  // Preview is the only way to see a rule's reach, because a rule in force
  // drops what it matches rather than marking it.
  it("reports what a saved rule would hide", async () => {
    fetchMutesMock.mockResolvedValue([rule()]);
    fetchEnginesMock.mockResolvedValue(engines());
    previewMuteMock.mockResolvedValue({
      rule: "accepted-open-redirect",
      matched: 2,
      examined: 40,
      findings: [
        {
          scanId: "s1", lineNo: 1, checkId: "open-redirect", name: "Open redirect",
          severity: "low", host: "httpbin.example.test", matchedAt: "", tags: [],
        },
        {
          scanId: "s1", lineNo: 4, checkId: "open-redirect", name: "Open redirect",
          severity: "low", host: "other.example.test", matchedAt: "", tags: [],
        },
      ],
    });

    render(<Harness />);
    fireEvent.click(await screen.findByText("accepted-open-redirect"));
    fireEvent.click(screen.getByRole("button", { name: "What would this hide?" }));

    expect(await screen.findByText(/of 40 recorded findings/)).toBeInTheDocument();
    expect(screen.getByText("httpbin.example.test")).toBeInTheDocument();
  });

  // A rule that errors mutes nothing, which is a different answer from a rule
  // that matched nothing.
  it("distinguishes an expression that could not be evaluated from one that matched nothing", async () => {
    fetchMutesMock.mockResolvedValue([rule({ expr: "finding.host" })]);
    fetchEnginesMock.mockResolvedValue(engines());
    previewMuteMock.mockResolvedValue({
      rule: "accepted-open-redirect",
      matched: 0,
      examined: 40,
      findings: [],
      errors: ["failed to parse template output (httpbin) as bool"],
    });

    render(<Harness />);
    fireEvent.click(await screen.findByText("accepted-open-redirect"));
    fireEvent.click(screen.getByRole("button", { name: "What would this hide?" }));

    expect(
      await screen.findByText(/could not be evaluated, so this rule would mute nothing/),
    ).toBeInTheDocument();
  });

  it("cannot check a rule that has not been saved yet", async () => {
    fetchMutesMock.mockResolvedValue([]);
    fetchEnginesMock.mockResolvedValue(engines());

    render(<Harness />);
    fireEvent.click(await screen.findByRole("button", { name: "New rule" }));

    expect(screen.getByRole("button", { name: "What would this hide?" })).toBeDisabled();
    expect(screen.getByText(/Save the rule before checking it/)).toBeInTheDocument();
  });

  it("reports a save the server refused", async () => {
    fetchMutesMock.mockResolvedValue([rule()]);
    fetchEnginesMock.mockResolvedValue(engines());
    updateMuteMock.mockRejectedValue(new Error("mute rule x: invalid expression: undeclared reference"));

    render(<Harness />);
    fireEvent.click(await screen.findByText("accepted-open-redirect"));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("invalid expression");
  });
});

describe("deleting a rule", () => {
  it("asks first, because the runs that already dropped findings do not get them back", async () => {
    fetchMutesMock.mockResolvedValue([rule()]);
    fetchEnginesMock.mockResolvedValue(engines());

    render(<Harness />);
    fireEvent.click(await screen.findByText("accepted-open-redirect"));
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    expect(screen.getByText(/Runs that already dropped them are unchanged/)).toBeInTheDocument();
    expect(deleteMuteMock).not.toHaveBeenCalled();
  });

  it("deletes once confirmed", async () => {
    fetchMutesMock.mockResolvedValue([rule()]);
    fetchEnginesMock.mockResolvedValue(engines());
    deleteMuteMock.mockResolvedValue(undefined);

    render(<Harness />);
    fireEvent.click(await screen.findByText("accepted-open-redirect"));
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    await waitFor(() => expect(deleteMuteMock).toHaveBeenCalledWith("accepted-open-redirect"));
    await waitFor(() => expect(route.selected).toBeUndefined());
  });

  it("keeps the rule when the confirmation is declined", async () => {
    fetchMutesMock.mockResolvedValue([rule()]);
    fetchEnginesMock.mockResolvedValue(engines());

    render(<Harness />);
    fireEvent.click(await screen.findByText("accepted-open-redirect"));
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    expect(screen.queryByText(/Runs that already dropped them/)).not.toBeInTheDocument();
    expect(deleteMuteMock).not.toHaveBeenCalled();
  });
});

// A rule is addressable so a finding can link to one, which is where the
// decision to mute is actually taken.
describe("the rule in the route", () => {
  it("opens the rule the route names without needing a click", async () => {
    fetchMutesMock.mockResolvedValue([rule()]);
    fetchEnginesMock.mockResolvedValue(engines());

    render(<Harness initial="accepted-open-redirect" />);

    await waitFor(() =>
      expect(screen.getByLabelText("Comment")).toHaveValue("httpbin is a deliberate fixture"),
    );
  });

  it("says a linked rule no longer exists rather than showing an empty form", async () => {
    fetchMutesMock.mockResolvedValue([rule()]);
    fetchEnginesMock.mockResolvedValue(engines());

    render(<Harness initial="deleted-last-week" />);

    expect(await screen.findByRole("alert")).toHaveTextContent("No mute rule named");
  });

  it("opens a draft describing the finding the link came from", async () => {
    fetchMutesMock.mockResolvedValue([]);
    fetchEnginesMock.mockResolvedValue(engines());

    render(
      <Harness
        initial="new"
        search="?templates=gcp%2Fbucket-public-access&resources=%2F%2Fstorage.googleapis.com%2Facme-logs&severity=high&engines=prowler"
      />,
    );

    await waitFor(() =>
      expect(screen.getByLabelText("Checks")).toHaveValue("gcp/bucket-public-access"),
    );
    expect(screen.getByLabelText("Resources")).toHaveValue("//storage.googleapis.com/acme-logs");
    expect(screen.getByRole("button", { name: "high" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "prowler" })).toHaveAttribute("aria-pressed", "true");
    // Named after what it covers, so the rule is recognisable in a run's
    // mutes.json without anyone having to invent a name first. Named only once
    // the stored rules have arrived, so the suggestion cannot collide.
    await waitFor(() =>
      expect(screen.getByLabelText("Name")).toHaveValue("gcp-bucket-public-access-acme-logs"),
    );
  });

  it("does not name a new rule after one that already exists", async () => {
    // The server upserts on the name, so reusing one would rewrite that rule
    // rather than add a second.
    fetchMutesMock.mockResolvedValue([rule({ name: "open-redirect" })]);
    fetchEnginesMock.mockResolvedValue(engines());

    render(<Harness initial="new" search="?templates=open-redirect" />);

    await waitFor(() =>
      expect(screen.getByLabelText("Name")).toHaveValue("open-redirect-2"),
    );
  });

  it("keeps a name that was typed instead of regenerating over it", async () => {
    fetchMutesMock.mockResolvedValue([]);
    fetchEnginesMock.mockResolvedValue(engines());

    render(<Harness initial="new" search="?templates=open-redirect" />);

    await waitFor(() => expect(screen.getByLabelText("Name")).toHaveValue("open-redirect"));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "httpbin-is-a-fixture" } });

    expect(screen.getByLabelText("Name")).toHaveValue("httpbin-is-a-fixture");
  });
});
