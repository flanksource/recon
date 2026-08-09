import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse } from "yaml";
import type { TargetClass, TargetDocument } from "../src/types.ts";
import { applyObservation, getObservationHost } from "./inventory-observation.ts";
import { createInventoryStore } from "./inventory-store.ts";

export type MigrationOptions = {
  targetsPath: string;
  statePath: string;
  observationPath?: string;
  inventoryDir: string;
};

type LegacyTarget = Omit<TargetDocument, "$schema" | "version" | "class" | "observed" | "http" | "tech" | "scan">;
type LegacyInventory = { zones: string[]; targets: Partial<Record<TargetClass, LegacyTarget[]>> };
type LegacyState = {
  first_observed?: string;
  last_seen?: string;
  last_status?: number;
  last_title?: string;
  last_tech?: string[];
  last_scan?: string;
  last_findings?: number;
};

function jsonLines(path: string | undefined): unknown[] {
  if (!path || !existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line, index) => {
      try {
        return JSON.parse(line) as unknown;
      } catch (error) {
        throw new Error(`${path}:${index + 1}: ${(error as Error).message}`);
      }
    });
}

function targetFromLegacy(
  targetClass: TargetClass,
  target: LegacyTarget,
  state: LegacyState | undefined,
): TargetDocument {
  return {
    $schema: "../target.schema.json",
    version: 1,
    ...target,
    class: targetClass,
    tags: target.tags ?? [],
    observed:
      state?.first_observed || state?.last_seen
        ? { first_observed: state.first_observed, last_seen: state.last_seen }
        : undefined,
    http:
      state?.last_status !== undefined || state?.last_title !== undefined
        ? { status_code: state.last_status, title: state.last_title }
        : undefined,
    tech: state?.last_tech ? { names: state.last_tech } : undefined,
    scan:
      state?.last_scan || state?.last_findings !== undefined
        ? { last_scan: state.last_scan, last_findings: state.last_findings }
        : undefined,
  };
}

function observationTimestamp(value: unknown): string {
  const timestamp = (value as { timestamp?: unknown }).timestamp;
  if (typeof timestamp !== "string") throw new Error("httpx observation must contain timestamp");
  const parsed = new Date(timestamp);
  if (Number.isNaN(parsed.getTime())) throw new Error(`invalid httpx timestamp: ${timestamp}`);
  return parsed.toISOString();
}

export function migrateLegacyInventory(options: MigrationOptions) {
  const source = parse(readFileSync(options.targetsPath, "utf8")) as LegacyInventory;
  const state = JSON.parse(readFileSync(options.statePath, "utf8")) as Record<string, LegacyState>;
  const observations = new Map(
    jsonLines(options.observationPath).map((value) => [getObservationHost(value), value]),
  );
  const targetDir = resolve(options.inventoryDir, "targets");
  mkdirSync(targetDir, { recursive: true });
  writeFileSync(
    resolve(options.inventoryDir, "inventory.json"),
    `${JSON.stringify(
      { $schema: "./inventory.schema.json", version: 1, zones: [...source.zones].sort() },
      null,
      2,
    )}\n`,
    "utf8",
  );

  const seen = new Set<string>();
  const missingState: string[] = [];
  for (const [targetClass, targets] of Object.entries(source.targets) as [
    TargetClass,
    LegacyTarget[] | undefined,
  ][]) {
    for (const legacy of targets ?? []) {
      if (seen.has(legacy.host)) throw new Error(`duplicate target: ${legacy.host}`);
      seen.add(legacy.host);
      if (!state[legacy.host]) missingState.push(legacy.host);
      let target = targetFromLegacy(targetClass, legacy, state[legacy.host]);
      const observation = observations.get(legacy.host);
      if (observation) target = applyObservation(target, observation, observationTimestamp(observation));
      writeFileSync(
        resolve(targetDir, `${legacy.host}.json`),
        `${JSON.stringify(target, null, 2)}\n`,
        "utf8",
      );
    }
  }

  const store = createInventoryStore({ inventoryDir: options.inventoryDir });
  const migrated = store.list();
  if (migrated.rows.length !== seen.size) throw new Error("migrated target count does not match source");
  const orphanedState = Object.keys(state).filter((host) => !seen.has(host));
  if (orphanedState.length > 0) throw new Error(`state contains unknown hosts: ${orphanedState.join(", ")}`);
  return {
    targets: seen.size,
    zones: source.zones.length,
    stateEntries: Object.keys(state).length,
    missingState: missingState.sort(),
  };
}
