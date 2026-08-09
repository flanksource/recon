import { describe, expect, it } from "vitest";
import { discoveryExitError, parseDiscoveryRecords } from "./discover-io.ts";

describe("discovery records", () => {
  it("projects valid httpx JSONL and fails loudly on malformed records", () => {
    const record = JSON.stringify({
      input: "API.EXAMPLE.COM",
      status_code: 200,
      title: "API",
      tech: ["Go"],
    });

    expect(parseDiscoveryRecords(`${record}\n`)).toEqual([
      { host: "api.example.com", status: 200, title: "API", tech: ["Go"], live: true },
    ]);
    expect(() => parseDiscoveryRecords("{bad json}\n")).toThrow(/line 1/i);
    expect(() => parseDiscoveryRecords(`${JSON.stringify({ status_code: 200 })}\n`)).toThrow(
      /missing host/i,
    );
  });

  it("accepts discovery drift but rejects process failure and timeout", () => {
    expect(discoveryExitError({ code: 0, timedOut: false })).toBeNull();
    expect(discoveryExitError({ code: 3, timedOut: false })).toBeNull();
    expect(discoveryExitError({ code: 2, timedOut: false })).toEqual(
      new Error("discovery exited with code 2"),
    );
    expect(discoveryExitError({ code: null, timedOut: false })).toEqual(
      new Error("discovery terminated without an exit code"),
    );
    expect(discoveryExitError({ code: null, timedOut: true })).toEqual(
      new Error("discovery timed out after 220s"),
    );
  });

  it("treats a Naabu-only open port as a live discovery", () => {
    expect(
      parseDiscoveryRecords(
        `${JSON.stringify({ input: "db.example.com", open_ports: [5432] })}\n`,
      ),
    ).toEqual([
      expect.objectContaining({
        host: "db.example.com",
        openPorts: [5432],
        live: true,
      }),
    ]);
  });
});
