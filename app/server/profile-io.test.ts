import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { listProfiles, writeProfile } from "./profile-io.ts";

const configDir = resolve(import.meta.dirname, "..", ".tmp", "profile-io-test");

describe("profile I/O", () => {
  beforeEach(() => {
    rmSync(configDir, { recursive: true, force: true });
    mkdirSync(configDir, { recursive: true });
    writeFileSync(
      resolve(configDir, "safe.yaml"),
      "# Production-safe profile.\nrate-limit: 50\nseverity: [critical, high]\n",
      "utf8",
    );
    writeFileSync(
      resolve(configDir, "discovery.httpx.yaml"),
      "# Discovery probe profile.\ntimeout: 5\ntitle: true\n",
      "utf8",
    );
    writeFileSync(
      resolve(configDir, "discovery.naabu.yaml"),
      "# Discovery port profile.\ntop-ports: \"100\"\nrate: 250\n",
      "utf8",
    );
  });

  afterAll(() => rmSync(configDir, { recursive: true, force: true }));

  it("discovers Nuclei and httpx profile files with stable IDs", () => {
    expect(listProfiles({ configDir })).toEqual([
      {
        id: "httpx:discovery",
        engine: "httpx",
        name: "discovery",
        filename: "discovery.httpx.yaml",
        config: { timeout: 5, title: true },
      },
      {
        id: "naabu:discovery",
        engine: "naabu",
        name: "discovery",
        filename: "discovery.naabu.yaml",
        config: { "top-ports": "100", rate: 250 },
      },
      {
        id: "nuclei:safe",
        engine: "nuclei",
        name: "safe",
        filename: "safe.yaml",
        config: { "rate-limit": 50, severity: ["critical", "high"] },
      },
    ]);
  });

  it("updates the selected profile while preserving its leading comment", () => {
    const saved = writeProfile(
      "nuclei",
      "safe",
      { severity: ["critical", "medium"], concurrency: 20 },
      { configDir },
    );

    expect(saved.config).toEqual({
      severity: ["critical", "medium"],
      concurrency: 20,
    });
    expect(readFileSync(resolve(configDir, "safe.yaml"), "utf8"))
      .toMatchInlineSnapshot(`
      "# Production-safe profile.
      severity:
        - critical
        - medium
      concurrency: 20
      "
    `);
  });

  it("rejects path traversal and options not present in the engine schema", () => {
    expect(() => writeProfile("nuclei", "../safe", {}, { configDir })).toThrow(
      "invalid profile name",
    );
    expect(() =>
      writeProfile(
        "httpx",
        "discovery",
        { "secret-file": "credentials.yaml" },
        { configDir },
      ),
    ).toThrow("unsupported httpx profile option: secret-file");
  });
});
