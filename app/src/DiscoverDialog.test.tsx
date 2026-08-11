// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DiscoverDialog } from "./DiscoverDialog";
import type { Engine, Profile } from "./types";

function response(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function engine(name: string, title: string, byDefault = true): Engine {
  return {
    _id: name,
    id: name,
    name,
    kind: "discovery",
    title,
    description: `${title} description`,
    binary: name,
    installed: true,
    managed: true,
    // What the server reports for the engines a sweep runs on its own, which
    // is what the picker opens on.
    default: byDefault,
    sections: [
      {
        id: "general",
        title: "General",
        description: `${title} options`,
        properties: { rate: { type: "integer", title: "Rate" } },
      },
    ],
  } as unknown as Engine;
}

function profile(engineName: string, name: string): Profile {
  return {
    _id: `discovery:${engineName}:${name}`,
    id: `discovery:${engineName}:${name}`,
    kind: "discovery",
    engine: engineName,
    name,
    config: { rate: 100 },
  } as unknown as Profile;
}

const engines = [
  engine("naabu", "Naabu"),
  engine("httpx", "HTTPX"),
  // Registered and reachable, but off until someone asks for it.
  engine("katana", "Katana", false),
];
const profiles = [
  profile("naabu", "default"),
  profile("naabu", "full-ports"),
  profile("httpx", "default"),
  profile("katana", "default"),
];

function stubFetch(
  handler?: (path: string, init?: RequestInit) => Response | undefined,
) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const path =
      typeof input === "string"
        ? input
        : input instanceof Request
          ? input.url
          : input.toString();
    const handled = handler?.(path, init);
    if (handled) return handled;
    if (path.startsWith("/api/v1/engine")) return response(engines);
    if (path.startsWith("/api/v1/profile")) return response(profiles);
    if (path.startsWith("/api/v1/discover?")) return response([]);
    throw new Error(`unexpected fetch: ${path}`);
  });
}

const sweep = {
  id: "discover-1",
  chain: "explicit",
  profiles: { naabu: "full-ports", httpx: "default" },
  input: {},
  ranAt: "2026-08-10T09:00:00",
  durationMs: 20,
  failed: false,
  hosts: [],
  log: "",
};

describe("DiscoverDialog", () => {
  beforeEach(() => {
    Object.defineProperty(window, "matchMedia", {
      configurable: true,
      value: vi.fn().mockReturnValue({
        matches: false,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
      }),
    });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("runs mixed explicit discovery with the default profile for every engine", async () => {
    const onDiscovered = vi.fn();
    const fetchMock = stubFetch((path) =>
      path === "/api/v1/discover" ? response(sweep) : undefined,
    );

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
            profile: ["default"],
          }),
        }),
      ),
    );
    await waitFor(() => expect(onDiscovered).toHaveBeenCalledOnce());
  });

  it("sends an engine-qualified reference for the engine whose profile was changed", async () => {
    const fetchMock = stubFetch((path) =>
      path === "/api/v1/discover" ? response(sweep) : undefined,
    );

    render(<DiscoverDialog open onClose={vi.fn()} onDiscovered={vi.fn()} />);
    await screen.findByText(/No previous discovery/);

    const editProfiles = screen.getByRole("button", { name: "Edit profiles" });
    await waitFor(() => expect(editProfiles).toBeEnabled());
    fireEvent.click(editProfiles);
    fireEvent.change(await screen.findByLabelText("Naabu profile"), {
      target: { value: "full-ports" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Run discovery" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/v1/discover",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ profile: ["default", "naabu=full-ports"] }),
        }),
      ),
    );
  });

  // Each engine ships exactly one profile, so without this there is never a
  // second one to pick and the per-engine override is unreachable.
  it("copies the edited options into a new profile and runs the sweep with it", async () => {
    const saved: RequestInit[] = [];
    const fetchMock = stubFetch((path, init) => {
      if (path === "/api/v1/profile" && init?.method === "POST") {
        saved.push(init);
        return response({
          ...profiles[0],
          name: "deep-probe",
          config: { rate: 5 },
        });
      }
      return path === "/api/v1/discover" ? response(sweep) : undefined;
    });

    render(<DiscoverDialog open onClose={vi.fn()} onDiscovered={vi.fn()} />);
    await screen.findByText(/No previous discovery/);

    const editProfiles = screen.getByRole("button", { name: "Edit profiles" });
    await waitFor(() => expect(editProfiles).toBeEnabled());
    fireEvent.click(editProfiles);
    fireEvent.change(await screen.findByLabelText("Rate"), {
      target: { value: "5" },
    });
    fireEvent.change(screen.getByLabelText("New profile"), {
      target: { value: "deep-probe" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save as" }));

    await waitFor(() => expect(saved).toHaveLength(1));
    expect(JSON.parse(String(saved[0].body))).toEqual({
      kind: "discovery",
      engine: "naabu",
      name: "deep-probe",
      config: { rate: 5 },
    });

    // The new profile is selected for that engine, and the one it was copied
    // from is no longer dirty — so the run does not write back over it too.
    fireEvent.click(screen.getByRole("button", { name: "Run discovery" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/v1/discover",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ profile: ["default", "naabu=deep-probe"] }),
        }),
      ),
    );
    expect(saved).toHaveLength(1);
  });

  it("refuses a new profile name the database would reject", async () => {
    stubFetch();

    render(<DiscoverDialog open onClose={vi.fn()} onDiscovered={vi.fn()} />);
    await screen.findByText(/No previous discovery/);

    const editProfiles = screen.getByRole("button", { name: "Edit profiles" });
    await waitFor(() => expect(editProfiles).toBeEnabled());
    fireEvent.click(editProfiles);

    const name = await screen.findByLabelText("New profile");
    fireEvent.change(name, { target: { value: "Deep Probe" } });
    expect(screen.getByRole("button", { name: "Save as" })).toBeDisabled();
    expect(
      screen.getByText("Lowercase letters, digits and dashes only"),
    ).toBeInTheDocument();

    fireEvent.change(name, { target: { value: "default" } });
    expect(screen.getByRole("button", { name: "Save as" })).toBeDisabled();
    expect(
      screen.getByText('Naabu already has a profile called "default"'),
    ).toBeInTheDocument();
  });

  // The alternative was writing the tweak back to the profile every scheduled
  // sweep reads, which made a one-off experiment permanent.
  it("carries an edited configuration with the sweep instead of saving it", async () => {
    const saved: RequestInit[] = [];
    let sent: Record<string, unknown> = {};
    stubFetch((path, init) => {
      if (path === "/api/v1/profile" && init?.method === "POST") {
        saved.push(init);
        return response({ ...profiles[0], config: { rate: 5 } });
      }
      if (path !== "/api/v1/discover") return undefined;
      sent = JSON.parse(String(init?.body));
      return response(sweep);
    });

    render(<DiscoverDialog open onClose={vi.fn()} onDiscovered={vi.fn()} />);
    await screen.findByText(/No previous discovery/);

    const editProfiles = screen.getByRole("button", { name: "Edit profiles" });
    await waitFor(() => expect(editProfiles).toBeEnabled());
    fireEvent.click(editProfiles);
    fireEvent.change(await screen.findByLabelText("Rate"), {
      target: { value: "5" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Run discovery" }));

    await waitFor(() => expect(sent.override).toEqual({ naabu: { rate: 5 } }));
    expect(saved).toHaveLength(0);
  });

  it("names the engines only once the chosen set differs from the default", async () => {
    let sent: Record<string, unknown> = {};
    stubFetch((path, init) => {
      if (path !== "/api/v1/discover") return undefined;
      sent = JSON.parse(String(init?.body));
      return response(sweep);
    });

    render(<DiscoverDialog open onClose={vi.fn()} onDiscovered={vi.fn()} />);
    await screen.findByText(/No previous discovery/);

    const editProfiles = screen.getByRole("button", { name: "Edit profiles" });
    await waitFor(() => expect(editProfiles).toBeEnabled());
    fireEvent.click(editProfiles);

    // The picker opens on what the server would run anyway, so an untouched
    // sweep says nothing about engines and the chain keeps deciding.
    expect(screen.getByRole("checkbox", { name: /Naabu/ })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: /Katana/ })).not.toBeChecked();

    fireEvent.click(screen.getByRole("button", { name: "Run discovery" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Run discovery" })).toBeEnabled(),
    );
    expect(sent).not.toHaveProperty("engine");

    // A finished sweep closes the editor, so re-open it to change the set.
    fireEvent.click(screen.getByRole("button", { name: "Edit profiles" }));
    fireEvent.click(await screen.findByRole("checkbox", { name: /Katana/ }));
    fireEvent.click(screen.getByRole("button", { name: "Run discovery" }));

    await waitFor(() =>
      expect(sent.engine).toEqual(["naabu", "httpx", "katana"]),
    );
  });
});
