// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, renderHook, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  JsonSchemaForm,
  type FieldControl,
  type JsonSchemaObject,
} from "@flanksource/clicky-ui";
import { PAIRED_KEYS, __test, useProfileFilterPairs } from "./ProfileFilterPairs";

const { modesOf, applyPair, enumOf, PAIRS } = __test;
const tagPair = PAIRS[0];
const typePair = PAIRS[1];

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

// DataTable and the form resolve their theme from the colour-scheme media
// query, which jsdom does not implement.
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

describe("reading a pair of include/exclude options", () => {
  it("reads the two lists as one set of modes", () => {
    expect(modesOf(["k8s", "docker"], ["dos"])).toEqual({
      k8s: "include",
      docker: "include",
      dos: "exclude",
    });
  });

  it("shows a value present in both as excluded, which is what nuclei does", () => {
    // The contradiction the paired fields allowed. Showing it as included would
    // describe a scan that does not happen.
    expect(modesOf(["dos"], ["dos"])).toEqual({ dos: "exclude" });
  });

  it("treats absent and non-array values as nothing selected", () => {
    expect(modesOf(undefined, undefined)).toEqual({});
    expect(modesOf("k8s", 7)).toEqual({});
  });
});

describe("writing a pair of include/exclude options", () => {
  it("splits the modes back across the two keys", () => {
    expect(
      applyPair({}, tagPair, { k8s: "include", dos: "exclude", cve: "include" }),
    ).toEqual({ tags: ["k8s", "cve"], "exclude-tags": ["dos"] });
  });

  it("removes an emptied key instead of storing an empty list", () => {
    // A leftover `[]` reads as an unsaved change forever, because a profile is
    // compared to its saved copy by value.
    const config = { tags: ["k8s"], "exclude-tags": ["dos"], "rate-limit": 50 };

    expect(applyPair(config, tagPair, { k8s: "include" })).toEqual({
      tags: ["k8s"],
      "rate-limit": 50,
    });
    expect(applyPair(config, tagPair, {})).toEqual({ "rate-limit": 50 });
  });

  it("leaves every other option in the profile alone", () => {
    const config = { severity: ["high"], "include-tags": ["kev"], type: ["dns"] };

    expect(applyPair(config, tagPair, { k8s: "include" })).toEqual({
      ...config,
      tags: ["k8s"],
    });
  });

  it("does not mutate the profile it was given", () => {
    const config = { tags: ["k8s"] };
    applyPair(config, tagPair, { dns: "exclude" });
    expect(config).toEqual({ tags: ["k8s"] });
  });

  it("round-trips a selection through both directions", () => {
    const written = applyPair({}, typePair, { http: "include", dns: "exclude" });
    expect(modesOf(written.type, written["exclude-type"])).toEqual({
      http: "include",
      dns: "exclude",
    });
  });
});

describe("the values a pair offers", () => {
  it("takes a closed vocabulary from the schema enum", () => {
    expect(enumOf({ type: "array", items: { enum: ["dns", "http"] } })).toEqual([
      "dns",
      "http",
    ]);
  });

  it("offers nothing rather than failing when the schema enumerates nothing", () => {
    expect(enumOf({ type: "array", items: { type: "string" } })).toEqual([]);
    expect(enumOf(undefined)).toEqual([]);
  });

  it("hides the excluded half of every pair from the generated form", () => {
    expect(PAIRED_KEYS).toEqual(["exclude-tags", "exclude-type"]);
  });
});

// The section schema as the engine serves it: the pair is two separate lists.
const filtering: JsonSchemaObject = {
  type: "object",
  properties: {
    tags: { type: "array", title: "Tags", items: { type: "string" } },
    "exclude-tags": { type: "array", title: "Excluded tags", items: { type: "string" } },
    type: { type: "array", title: "Protocol types", items: { enum: ["dns", "http"] } },
    "exclude-type": {
      type: "array",
      title: "Excluded protocol types",
      items: { enum: ["dns", "http"] },
    },
    "include-tags": { type: "array", title: "Forced tags", items: { type: "string" } },
  },
} as unknown as JsonSchemaObject;

function Form({
  value,
  onChange = () => {},
}: {
  value: Record<string, unknown>;
  onChange?: (next: Record<string, unknown>) => void;
}) {
  const { pre, post, hiddenKeys } = useProfileFilterPairs();
  return (
    <JsonSchemaForm
      schema={filtering}
      value={value}
      onChange={onChange}
      pre={pre}
      post={post}
      hiddenKeys={hiddenKeys}
      // Matches how ProfilesView and ProfileConfig render it, which is what
      // surfaces a field's description.
      layout={{ mode: "stacked", help: "hover", valueMaxWidth: "100%" }}
    />
  );
}

// The field label, not the control's own trigger text, which repeats it.
function fieldLabel(title: string) {
  return document.querySelector(`span[title="${title}"]`);
}

describe("the Filtering section of a profile", () => {
  beforeEach(() => {
    stubMatchMedia();
    vi.spyOn(globalThis, "fetch").mockImplementation(async () =>
      jsonResponse({ filters: { tag: { label: "Tag", options: { k8s: "k8s", dos: "dos" } } } }),
    );
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("shows one control per pair instead of an included and an excluded field", async () => {
    render(<Form value={{}} />);

    await waitFor(() => expect(fieldLabel("tags")).toBeInTheDocument());
    expect(fieldLabel("type")).toBeInTheDocument();
    expect(fieldLabel("exclude-tags")).not.toBeInTheDocument();
    expect(fieldLabel("exclude-type")).not.toBeInTheDocument();
  });

  it("leaves the options that are not half of a pair alone", async () => {
    // Forced tags is nuclei's -include-tags: a third state the toggle cannot
    // express, so it stays its own field rather than being folded in silently.
    render(<Form value={{}} />);

    await waitFor(() => expect(screen.getByText("Forced tags")).toBeInTheDocument());
  });

  it("describes the merged control rather than only its included half", () => {
    // "Template tags to include." stops being true once one control does both.
    // Asserted on the extension rather than the DOM: where a form paints a
    // description is the form's business, and it varies with the help setting.
    const { result } = renderHook(() => useProfileFilterPairs());
    const [pre] = result.current.pre;

    const described = pre(
      { key: "tags", description: "Template tags to include." } as FieldControl,
      { key: "tags", prop: {}, value: undefined },
    );
    expect(described?.description).toContain("include or exclude");

    const untouched = pre(
      { key: "include-tags", description: "Tags that run even when excluded elsewhere." } as FieldControl,
      { key: "include-tags", prop: {}, value: undefined },
    );
    expect(untouched?.description).toBe("Tags that run even when excluded elsewhere.");
  });

  it("renders a tri-state toggle per option, with the saved modes applied", async () => {
    render(<Form value={{ type: ["http"], "exclude-type": ["dns"] }} />);

    await waitFor(() => expect(fieldLabel("type")).toBeInTheDocument());
    // Opening the protocol control shows both halves of the pair as one list.
    screen.getAllByRole("combobox").forEach((box) => box.click());

    await waitFor(() =>
      expect(document.querySelectorAll("[data-tristate-region]").length).toBeGreaterThan(0),
    );
  });
});
