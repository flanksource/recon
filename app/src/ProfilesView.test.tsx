// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ProfilesView } from "./ProfilesView";
import type { Engine, Profile } from "./types";

const engines: Engine[] = [
  {
    _id: "scan:nuclei",
    name: "nuclei",
    kind: "scan",
    title: "Nuclei",
    binary: "nuclei",
    installed: true,
    managed: true,
    sections: [
      {
        id: "performance",
        title: "Performance",
        description: "Rate limiting and concurrency.",
        properties: {
          "rate-limit": {
            type: "integer",
            title: "Requests per second",
            minimum: 1,
            multipleOf: 1,
          },
        },
      },
    ],
  },
  {
    _id: "discovery:naabu",
    name: "naabu",
    kind: "discovery",
    title: "Naabu",
    binary: "naabu",
    installed: true,
    managed: true,
    sections: [
      {
        id: "ports",
        title: "Ports & targets",
        description: "Which ports and hosts to probe.",
        properties: {
          "top-ports": { type: "string", title: "Top ports" },
        },
      },
    ],
  },
];

const profiles: Profile[] = [
  {
    _id: "scan:nuclei:safe",
    kind: "scan",
    engine: "nuclei",
    name: "safe",
    config: { "rate-limit": 50, severity: ["critical", "high"] },
  },
  {
    _id: "discovery:naabu:discovery",
    kind: "discovery",
    engine: "naabu",
    name: "discovery",
    config: { "top-ports": "100", rate: 250 },
  },
];

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

describe("ProfilesView", () => {
  afterEach(() => vi.restoreAllMocks());

  it("edits a selected profile through its schema and saves the complete config", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(jsonResponse(profiles))
      .mockResolvedValueOnce(jsonResponse(engines));
    render(<ProfilesView />);

    fireEvent.click(
      await screen.findByRole("button", { name: /safe.*nuclei/i }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Performance" }));
    fireEvent.change(
      screen.getByRole("spinbutton", { name: "Requests per second" }),
      { target: { value: "75" } },
    );
    expect(screen.getByText("Unsaved changes")).toBeInTheDocument();

    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        ...profiles[0],
        config: { ...profiles[0].config, "rate-limit": 75 },
      }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Save profile" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenLastCalledWith(
        "/api/v1/profile",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            kind: "scan",
            engine: "nuclei",
            name: "safe",
            config: { "rate-limit": 75, severity: ["critical", "high"] },
          }),
        }),
      ),
    );
  });

  it("exposes the Naabu discovery profile through its generated schema", async () => {
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(jsonResponse(profiles))
      .mockResolvedValueOnce(jsonResponse(engines));
    render(<ProfilesView />);

    fireEvent.click(
      await screen.findByRole("button", { name: /discovery.*naabu/i }),
    );

    expect(screen.getByText("Naabu profile")).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Ports & targets" }),
    ).toBeInTheDocument();
  });
});
