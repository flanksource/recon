// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DiscoverDialog } from "./DiscoverDialog";

function response(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

describe("DiscoverDialog", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("runs mixed explicit discovery on the collection endpoint", async () => {
    Object.defineProperty(window, "matchMedia", {
      configurable: true,
      value: vi.fn().mockReturnValue({
        matches: false,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
      }),
    });
    const onDiscovered = vi.fn();
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (input) => {
        const path =
          typeof input === "string"
            ? input
            : input instanceof Request
              ? input.url
              : input.toString();
        if (path.startsWith("/api/v1/discover?")) return response([]);
        if (path === "/api/v1/discover") {
          return response({
            id: "discover-1",
            chain: "explicit",
            profile: "ABX",
            input: {},
            ranAt: "2026-08-10T09:00:00",
            durationMs: 20,
            failed: false,
            hosts: [],
            log: "",
          });
        }
        throw new Error(`unexpected fetch: ${path}`);
      });

    render(
      <DiscoverDialog open onClose={vi.fn()} onDiscovered={onDiscovered} />,
    );
    await screen.findByText(/No previous discovery/);

    fireEvent.change(screen.getByLabelText("Domains"), {
      target: { value: "example.test" },
    });
    fireEvent.change(screen.getByLabelText("Hosts"), {
      target: { value: "api.example.test,192.0.2.10" },
    });
    fireEvent.change(screen.getByLabelText("CIDRs"), {
      target: { value: "192.0.2.0/24" },
    });
    fireEvent.change(screen.getByLabelText("Profile"), {
      target: { value: "ABX" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Run discovery" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/v1/discover",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            domain: ["example.test"],
            host: ["api.example.test", "192.0.2.10"],
            cidr: ["192.0.2.0/24"],
            profile: "ABX",
          }),
        }),
      ),
    );
    await waitFor(() => expect(onDiscovered).toHaveBeenCalledOnce());
  });
});
