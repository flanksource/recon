import { describe, expect, it } from "vitest";
import {
  addressableClasses,
  resolveNucleiProfile,
  scanInvocation,
} from "./scan-io.ts";

const profiles = [
  {
    id: "nuclei:full",
    engine: "nuclei" as const,
    name: "full",
    filename: "full.yaml",
    config: { dast: true, timeout: 10 },
  },
  {
    id: "nuclei:safe",
    engine: "nuclei" as const,
    name: "safe",
    filename: "safe.yaml",
    config: { timeout: 10 },
  },
];

describe("scan invocation", () => {
  it("indexes only addressable hosts and ignores provider contexts", () => {
    expect(
      addressableClasses([
        {
          host: "api.example.com",
          class: "prod",
        },
        { class: "prod" },
      ]),
    ).toEqual(new Map([["api.example.com", "prod"]]));
  });

  it("uses the combined Naabu and httpx discovery profile for a targeted rescan", () => {
    expect(
      scanInvocation({ profile: "discovery", resultFile: null }),
    ).toEqual({
      command: "pnpm",
      args: [
        "--dir",
        "app",
        "exec",
        "tsx",
        "server/discovery-profile.ts",
        "--hosts",
        ".gen/app-scan.txt",
      ],
    });
  });

  it("uses a run-specific Nuclei config and enables DAST from the effective config", () => {
    expect(
      scanInvocation({
        profile: "full",
        resultFile: "full-prod-result.jsonl",
        configFile: ".gen/app-scan-profile.yaml",
        dast: true,
      }),
    ).toEqual({
      command: "nuclei",
      args: [
        "-config",
        ".gen/app-scan-profile.yaml",
        "-etags",
        "dos,fuzz,bruteforce,intrusive,azure",
        "-dast",
        "-t",
        "dast/",
        "-l",
        ".gen/app-scan.txt",
        "-t",
        "templates/",
        "-enable-self-contained",
        "-jsonl",
        "-o",
        "results/full-prod-result.jsonl",
        "-sarif-export",
        "results/full-prod-result.sarif",
        "-stats",
        "-stats-json",
        "-stats-interval",
        "2",
      ],
    });
  });

  it("validates run-only config against the selected Nuclei profile", () => {
    expect(
      resolveNucleiProfile({
        profile: "full",
        config: { dast: true, timeout: 20 },
        profiles,
      }),
    ).toEqual({ config: { dast: true, timeout: 20 }, dast: true });
    expect(() =>
      resolveNucleiProfile({
        profile: "safe",
        config: { "unknown-option": true },
        profiles,
      }),
    ).toThrow("unsupported nuclei profile option: unknown-option");
    expect(() =>
      resolveNucleiProfile({ profile: "missing", profiles }),
    ).toThrow("Nuclei profile not found: missing");
  });
});
