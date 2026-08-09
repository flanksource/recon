import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse } from "yaml";
import { describe, expect, it } from "vitest";
import { profileOptionKeys, profileSections } from "./index.ts";

const configDir = resolve(import.meta.dirname, "..", "..", "config");

function configKeys(filename: string): string[] {
  return Object.keys(parse(readFileSync(resolve(configDir, filename), "utf8")));
}

describe("profile schemas", () => {
  it("covers every option already used by the tracked Nuclei profiles", () => {
    const schemaKeys = new Set(profileOptionKeys("nuclei"));

    expect(
      ["safe.yaml", "full.yaml"].flatMap((filename) =>
        configKeys(filename).filter((key) => !schemaKeys.has(key)),
      ),
    ).toEqual([]);
  });

  it("extracts the discovery controls from httpx flag groups", () => {
    const keys = profileOptionKeys("httpx");

    expect(keys).toEqual(
      expect.arrayContaining([
        "status-code",
        "content-length",
        "title",
        "tech-detect",
        "follow-host-redirects",
        "threads",
        "rate-limit",
        "timeout",
        "retries",
      ]),
    );
    expect(profileSections.httpx.map((section) => section.id)).toEqual([
      "probes",
      "filters",
      "network",
      "performance",
    ]);
    expect(
      configKeys("discovery.httpx.yaml").filter((key) => !keys.includes(key)),
    ).toEqual([]);
  });

  it("extracts bounded port-scan controls from Naabu flag groups", () => {
    const keys = profileOptionKeys("naabu");

    expect(keys).toEqual(
      expect.arrayContaining([
        "port",
        "top-ports",
        "exclude-cdn",
        "scan-type",
        "rate",
        "timeout",
        "retries",
        "verify",
      ]),
    );
    expect(profileSections.naabu.map((section) => section.id)).toEqual([
      "ports",
      "network",
      "performance",
    ]);
    expect(
      configKeys("discovery.naabu.yaml").filter((key) => !keys.includes(key)),
    ).toEqual([]);
  });

  it("keeps runner-owned and credential-bearing flags out of tracked profiles", () => {
    expect(profileOptionKeys("nuclei")).not.toEqual(
      expect.arrayContaining(["list", "output", "interactsh-token", "team-id"]),
    );
    expect(profileOptionKeys("httpx")).not.toEqual(
      expect.arrayContaining(["list", "output", "secret-file", "dashboard"]),
    );
    expect(profileOptionKeys("naabu")).not.toEqual(
      expect.arrayContaining(["list", "output", "json", "dashboard"]),
    );
  });
});
