// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { columns, TargetStatusBadge } from "./columns";
import type { ProbeFailure, TableRow } from "./types";

function row(overrides: Partial<TableRow> = {}): TableRow {
  return {
    $schema: "../target.schema.json",
    version: 1,
    id: "api.example.com",
    host: "api.example.com",
    class: "prod",
    profiles: ["safe"],
    tags: [],
    dirty: false,
    ...overrides,
  } as TableRow;
}

function column(key: string) {
  const found = columns.find((c) => c.key === key);
  expect(found, `no ${key} column`).toBeDefined();
  return found!;
}

describe("the Target column", () => {
  afterEach(cleanup);

  it("uses the stable id while keeping the provider as descriptive context", () => {
    render(
      <>
        {column("id").render?.(
          "gcp-production",
          row({
            id: "gcp-production",
            host: undefined,
            kind: "provider-context",
            provider: "gcp",
          }),
        )}
      </>,
    );

    expect(screen.getByText("gcp-production")).toBeInTheDocument();
    expect(screen.getByText("gcp")).toBeInTheDocument();
  });
});

describe("the Status column", () => {
  afterEach(cleanup);

  it("shows the last status when the host is answering", () => {
    render(<TargetStatusBadge value={200} />);
    expect(screen.getByText("200")).toBeInTheDocument();
  });

  // A failed probe deliberately keeps the code from the host's last good probe,
  // so before this the row of a host that no longer resolves still read as a
  // green 200 and nothing on it said otherwise.
  it("names the failure instead of the stale status a failed probe left behind", () => {
    render(<TargetStatusBadge failure="dns" value={200} />);

    expect(screen.getByText("DNS")).toBeInTheDocument();
    expect(screen.queryByText("200")).not.toBeInTheDocument();
  });

  // A served error status is a status: the code says more than any word would,
  // and the badge already colours 4xx and 5xx.
  it("keeps showing the code when the endpoint answered with an error status", () => {
    render(<TargetStatusBadge failure="http" value={503} />);
    expect(screen.getByText("503")).toBeInTheDocument();
  });

  it.each<[ProbeFailure, string]>([
    ["dns", "DNS"],
    ["refused", "refused"],
    ["unreachable", "unreachable"],
    ["timeout", "timeout"],
    ["tls", "TLS"],
    ["other", "error"],
  ])("labels a %s failure as %s", (failure, label) => {
    render(<TargetStatusBadge failure={failure} value={undefined} />);
    expect(screen.getByText(label)).toBeInTheDocument();
  });

  it("reads the failure off the row it is given", () => {
    const render_ = column("last_status").render;
    render(<>{render_?.(200, row({ failure: "refused" }))}</>);
    expect(screen.getByText("refused")).toBeInTheDocument();
  });
});

describe("the Error column", () => {
  afterEach(cleanup);

  // The message is what turns "this host is down" into something actionable,
  // but a wrapped dial error runs to several lines — so it is truncated in the
  // cell and kept whole on hover.
  it("shows the message and keeps the whole of it available", () => {
    const message = 'Get "https://gone.example.com": dial tcp: lookup gone.example.com: no such host';
    render(<>{column("last_error").render?.(message, row())}</>);

    const cell = screen.getByText(message);
    expect(cell).toHaveAttribute("title", message);
    expect(cell).toHaveClass("truncate");
  });

  it("shows nothing for a host with no error", () => {
    const { container } = render(
      <>{column("last_error").render?.(undefined, row())}</>,
    );
    expect(container).toBeEmptyDOMElement();
  });
});

describe("the Kind column", () => {
  afterEach(cleanup);

  // The server omits kind for a host so an existing target document is
  // unchanged by cloud accounts existing. Reading the cell value directly
  // would render an empty pill for every host in the inventory.
  it("reads an absent kind as a host", () => {
    render(<>{column("kind").render?.(undefined, row())}</>);
    expect(screen.getByText("Host")).toBeInTheDocument();
  });

  it("names a provider-native target independently of its provider", () => {
    render(
      <>
        {column("kind").render?.(
          "provider-context",
          row({ kind: "provider-context", provider: "gcp" }),
        )}
      </>,
    );
    expect(screen.getByText("Provider context")).toBeInTheDocument();
  });

  // The filter has to agree with what is rendered, or selecting "host" in the
  // chip would match nothing while the column shows every row as one.
  it("filters on the resolved kind rather than the raw cell", () => {
    expect(column("kind").filterValue?.(undefined, row())).toBe("host");
    expect(
      column("kind").filterValue?.(
        "provider-context",
        row({ kind: "provider-context", provider: "gcp" }),
      ),
    ).toBe("provider-context");
  });
});
