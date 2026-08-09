// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ProfilesView } from "./ProfilesView";

const profiles = [
  {
    id: "httpx:discovery",
    engine: "httpx" as const,
    name: "discovery",
    filename: "discovery.httpx.yaml",
    config: { timeout: 5, title: true },
  },
  {
    id: "nuclei:safe",
    engine: "nuclei" as const,
    name: "safe",
    filename: "safe.yaml",
    config: { "rate-limit": 50, severity: ["critical", "high"] },
  },
  {
    id: "naabu:discovery",
    engine: "naabu" as const,
    name: "discovery",
    filename: "discovery.naabu.yaml",
    config: { "top-ports": "100", rate: 250 },
  },
];

describe("ProfilesView", () => {
  afterEach(() => vi.restoreAllMocks());

  it("edits a selected profile through its schema and saves the complete config", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ profiles }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    render(<ProfilesView />);

    fireEvent.click(
      await screen.findByRole("button", { name: /safe.*nuclei/i }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Performance" }));
    fireEvent.change(
      screen.getByRole("spinbutton", { name: "Requests per second" }),
      {
        target: { value: "75" },
      },
    );
    expect(screen.getByText("Unsaved changes")).toBeInTheDocument();

    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          profile: {
            ...profiles[1],
            config: { ...profiles[1].config, "rate-limit": 75 },
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );
    fireEvent.click(screen.getByRole("button", { name: "Save profile" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenLastCalledWith(
        "/api/profiles/nuclei/safe",
        expect.objectContaining({
          method: "PUT",
          body: JSON.stringify({
            config: { "rate-limit": 75, severity: ["critical", "high"] },
          }),
        }),
      ),
    );
  });

  it("exposes the Naabu discovery profile through its generated schema", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ profiles }), { status: 200 }),
    );
    render(<ProfilesView />);

    fireEvent.click(
      await screen.findByRole("button", { name: /discovery.*naabu/i }),
    );

    expect(screen.getByText("Naabu profile")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Ports & targets" })).toBeInTheDocument();
  });
});
