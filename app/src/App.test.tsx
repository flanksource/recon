// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";

describe("App routes", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    window.history.replaceState(null, "", "/");
  });

  it("renders a deep-linked inventory target with Inventory navigation active", async () => {
    window.history.replaceState(null, "", "/inventory/api.example.com");
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const path = String(input);
      if (path === "/api/inventory/schema/target") {
        return new Response(JSON.stringify({ type: "object", properties: {} }), { status: 200 });
      }
      if (path === "/api/inventory/api.example.com") {
        return new Response(
          JSON.stringify({
            $schema: "../target.schema.json",
            version: 1,
            host: "api.example.com",
            class: "prod",
            profiles: ["safe"],
            tags: [],
          }),
          { status: 200 },
        );
      }
      throw new Error(`unexpected request: ${path}`);
    });

    render(<App />);

    expect(await screen.findByRole("heading", { name: "api.example.com" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Inventory" })).toHaveAttribute("href", "/inventory");
  });
});
