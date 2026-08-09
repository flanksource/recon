import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const script = resolve(import.meta.dirname, "..", "..", "hack", "discover-targets.sh");

describe("discovery script prerequisites", () => {
  it("fails with an actionable error when ripgrep is unavailable", () => {
    const result = spawnSync(
      "/bin/bash",
      [script],
      { encoding: "utf8", env: { ...process.env, PATH: "" } },
    );

    expect(result.status).toBe(1);
    expect(`${result.stdout}${result.stderr}`).toMatch(
      /MISSING \(required\): rg/,
    );
  });

  it("adds NS and MX answers to the candidate input before host normalisation", () => {
    const source = readFileSync(script, "utf8");
    const dnsRecords = source.indexOf("server/dns-discovery.ts");
    const normalisation = source.indexOf("# Normalise:");

    expect(dnsRecords).toBeGreaterThan(0);
    expect(normalisation).toBeGreaterThan(dnsRecords);
  });

  it("runs the shared Naabu and httpx discovery profile after host normalisation", () => {
    const source = readFileSync(script, "utf8");
    const normalisation = source.indexOf("# Normalise:");
    const profileRunner = source.indexOf("server/discovery-profile.ts");

    expect(profileRunner).toBeGreaterThan(normalisation);
    expect(source).toContain("--hosts .gen/discovered-hosts.txt");
  });
});
