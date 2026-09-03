// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { FilterBarFilter, FilterBarMultiFilterMode } from "@flanksource/clicky-ui/components";
import { selectionQuery, useEntityFilters } from "./filters";

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

// The shape a listing's `?__lookup=filters` answers with. `tag` and `type` are
// the vocabularies the server reads as patterns; `severity` is a literal value.
const vocabulary = {
  filters: {
    severity: { label: "Severity", options: { critical: "critical", info: "info" } },
    type: { label: "Protocol", options: { http: "http", dns: "dns" } },
    tag: { label: "Tag", options: { k8s: "k8s", docker: "docker" }, total: 40, truncated: true },
  },
};

// A fresh Response per call: a body can only be read once, so a shared instance
// makes every request after the first look like it answered with nothing.
function mockLookup(body: unknown = vocabulary) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async () => jsonResponse(body));
}

async function loadFilters(entity = "template") {
  const view = renderHook(() => useEntityFilters(entity));
  await waitFor(() => expect(view.result.current.filters).not.toHaveLength(0));
  return view;
}

function byKey(filters: FilterBarFilter[], key: string): FilterBarFilter {
  const found = filters.find((filter) => filter.key === key);
  if (!found) throw new Error(`no filter ${key} in ${filters.map((f) => f.key).join(", ")}`);
  return found;
}

// Narrowed accessors: the union is wide and each spec knows which arm it wants.
function multi(filters: FilterBarFilter[], key: string) {
  const filter = byKey(filters, key);
  if (filter.kind !== "multi") throw new Error(`${key} is ${filter.kind}, not multi`);
  return filter;
}

function dateRange(filters: FilterBarFilter[], key: string) {
  const filter = byKey(filters, key);
  if (filter.kind !== "date-range") throw new Error(`${key} is ${filter.kind}, not date-range`);
  return filter;
}

describe("entity filter controls", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("gives tags and protocols a tri-state control and everything else a plain one", async () => {
    mockLookup();

    const { result } = await loadFilters();

    expect(multi(result.current.filters, "tag").kind).toBe("multi");
    expect(multi(result.current.filters, "type").kind).toBe("multi");
    // Severity is read as a literal value server-side, so an exclusion there
    // would be sent as a severity named "!info" and quietly match nothing.
    expect(byKey(result.current.filters, "severity").kind).toBe("lookup-multi");
  });

  it("renders date range metadata as date-only controls and sends both bounds", async () => {
    mockLookup({
      filters: {
        "first-seen": { label: "First seen", type: "day-range" },
        "last-seen": { label: "Last seen", type: "day-range" },
      },
    });
    const { result } = await loadFilters("resource");

    expect(dateRange(result.current.filters, "first-seen").timeEnabled).toBe(false);
    expect(dateRange(result.current.filters, "last-seen").timeEnabled).toBe(false);

    act(() => {
      dateRange(result.current.filters, "first-seen").onApply("2026-08-01", "2026-08-31");
    });

    expect(result.current.selection).toEqual({
      "first-seen": [">=2026-08-01,<=2026-08-31"],
    });
    expect(selectionQuery(result.current.selection)).toEqual({
      "first-seen": ">=2026-08-01,<=2026-08-31",
    });
  });

  it("reads a stored date range back into its two bounds", async () => {
    mockLookup({
      filters: { "last-seen": { label: "Last seen", type: "day-range" } },
    });
    const { result } = await loadFilters("resource");

    act(() => {
      result.current.setSelection({ "last-seen": [">=2026-08-20,<=2026-08-22"] });
    });

    await waitFor(() => {
      expect(dateRange(result.current.filters, "last-seen")).toMatchObject({
        from: "2026-08-20",
        to: "2026-08-22",
      });
    });
  });

  // The three listings name the same idea differently: templates and findings
  // filter on `tag`, targets on `tags`. Both have to get the same control, or
  // exclusion would work on one screen and not the next.
  it("recognises the target listing's plural tags key", async () => {
    mockLookup({
      filters: {
        class: { label: "Class", options: { prod: "prod" } },
        tags: { label: "Tags", options: { http: "http", edge: "edge" } },
      },
    });

    const { result } = await loadFilters("target");

    expect(multi(result.current.filters, "tags").kind).toBe("multi");
    // A class is one of six words the server validates, not a pattern.
    expect(byKey(result.current.filters, "class").kind).toBe("lookup-multi");
  });

  it("sends an excluded value as the pattern the server reads", async () => {
    mockLookup();
    const { result } = await loadFilters();

    act(() => {
      multi(result.current.filters, "tag").onChange({
        k8s: "include",
        docker: "exclude",
      } as Record<string, FilterBarMultiFilterMode>);
    });

    expect(result.current.selection).toEqual({ tag: ["k8s", "!docker"] });
    expect(selectionQuery(result.current.selection)).toEqual({ tag: "k8s,!docker" });
  });

  it("reads a stored pattern back as the mode that produced it", async () => {
    // The selection is kept as patterns, so the control has to be able to show
    // one it did not just write — from a URL, or from a reload.
    mockLookup();
    const { result } = await loadFilters();

    act(() => {
      result.current.setSelection({ tag: ["k8s", "!docker"] });
    });

    await waitFor(() =>
      expect(multi(result.current.filters, "tag").value).toEqual({
        k8s: "include",
        docker: "exclude",
      }),
    );
  });

  it("drops the filter entirely when every value is cleared", async () => {
    // An empty control must not become `?tag=`, which the server would have to
    // decide the meaning of.
    mockLookup();
    const { result } = await loadFilters();

    act(() => {
      multi(result.current.filters, "tag").onChange({ k8s: "include" });
    });
    act(() => {
      multi(result.current.filters, "tag").onChange({});
    });

    expect(result.current.selection).toEqual({});
    expect(selectionQuery(result.current.selection)).toEqual({});
  });

  it("carries the truncation hint through, so a capped vocabulary says so", async () => {
    mockLookup();
    const { result } = await loadFilters();

    const tag = multi(result.current.filters, "tag");
    expect(tag.truncated).toBe(true);
    expect(tag.total).toBe(40);
  });

  it("narrows a tri-state option set server-side as the user types", async () => {
    const fetchMock = mockLookup();
    const { result } = await loadFilters();

    act(() => {
      void multi(result.current.filters, "tag").onSearch?.("dock");
    });

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("__lookup_filter=tag&__lookup_q=dock"),
        undefined,
      ),
    );
  });

  it("resolves the search to the matches, which is how the tri-state menu gets them", async () => {
    // The tri-state control merges what onSearch resolves to; it does not
    // re-read `options`. Returning nothing showed "No results" for every value
    // past the head set even though the server had answered with them.
    mockLookup({
      filters: { tag: { label: "Tag", options: { k8s: "k8s", "k8s-cluster": "k8s-cluster" } } },
    });
    const { result } = await loadFilters();

    const found = await multi(result.current.filters, "tag").onSearch?.("k8s");

    expect(found).toEqual([
      { value: "k8s", label: "k8s" },
      { value: "k8s-cluster", label: "k8s-cluster" },
    ]);
  });

  it("resolves to an empty list rather than rejecting when the lookup fails", async () => {
    mockLookup();
    const { result } = await loadFilters();

    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("network down"));
    const found = await multi(result.current.filters, "tag").onSearch?.("k8s");

    expect(found).toEqual([]);
    await waitFor(() => expect(result.current.error).toBe("network down"));
  });

  it("hides a filter another control already owns", async () => {
    mockLookup();
    const view = renderHook(() => useEntityFilters("template", { exclude: ["tag"] }));

    await waitFor(() => expect(view.result.current.filters).not.toHaveLength(0));
    expect(view.result.current.filters.map((filter) => filter.key)).not.toContain("tag");
  });

  it("reports a failed lookup rather than offering no filters at all", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ error: "template catalogue unavailable" }), {
        status: 503,
        headers: { "content-type": "application/json" },
      }),
    );

    const { result } = renderHook(() => useEntityFilters("template"));

    await waitFor(() =>
      expect(result.current.error).toContain("template catalogue unavailable"),
    );
  });
});
