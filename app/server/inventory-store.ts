import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import Ajv2020, { type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import type { Inventory, TargetCredentials, TargetDocument } from "../src/types.ts";
import { applyObservation, getObservationHost } from "./inventory-observation.ts";

export type InventoryStoreOptions = {
  inventoryDir?: string;
  observationPath?: string;
  now?: () => Date;
};

export type CuratedTarget = Pick<
  TargetDocument,
  "class" | "app" | "cluster" | "source" | "profiles" | "ports" | "tags" | "notes" | "reason"
> & { credentials?: TargetCredentials | null };

type Manifest = { $schema: "./inventory.schema.json"; version: 3; zones: string[] };
type UpdateOptions = { id: string; curated: CuratedTarget };
type ScanUpdate = { hosts: string[]; resultPath: string; scannedAt?: string };
type RenderOptions = { outputDir: string };

const TARGET_ID = /^(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?|[0-9a-f:]+)$/;
const CURATED_FIELDS = new Set([
  "class",
  "app",
  "cluster",
  "source",
  "profiles",
  "ports",
  "tags",
  "notes",
  "reason",
  "credentials",
]);
const DEFAULT_INVENTORY_DIR = resolve(import.meta.dirname, "..", "..", "inventory");
const SCHEMA_DIR = resolve(import.meta.dirname, "..", "..", "internal", "schema");

function parseJson(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as unknown;
  } catch (error) {
    throw new Error(`${path}: ${(error as Error).message}`);
  }
}

function validationMessage(path: string, errors: ErrorObject[] | null | undefined): string {
  const detail = errors
    ?.map((error) => `${error.instancePath || "/"} ${error.message ?? "is invalid"}`)
    .join("; ");
  return `${basename(path)}: ${detail ?? "schema validation failed"}`;
}

function assertValid(validate: ValidateFunction, value: unknown, path: string): void {
  if (!validate(value)) throw new Error(validationMessage(path, validate.errors));
}

function validators(schemaDir: string): { manifest: ValidateFunction; target: ValidateFunction } {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  addFormats(ajv);
  return {
    manifest: ajv.compile(parseJson(resolve(schemaDir, "inventory.schema.json")) as object),
    target: ajv.compile(parseJson(resolve(schemaDir, "target.schema.json")) as object),
  };
}

function assertTargetID(id: string): void {
  if (!TARGET_ID.test(id) || id.includes("..")) throw new Error(`invalid target id: ${id}`);
}

function readJsonLines(path: string): unknown[] {
  if (!existsSync(path)) return [];
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

function countFindings(resultPath: string): Map<string, number> {
  const findings = new Map<string, number>();
  for (const value of readJsonLines(resultPath)) {
    const result = value as { host?: unknown; matched_at?: unknown; "matched-at"?: unknown };
    const raw = result.host ?? result.matched_at ?? result["matched-at"];
    if (typeof raw !== "string") throw new Error(`${resultPath}: finding is missing host`);
    const host = raw.includes("://") ? new URL(raw).hostname : raw.split(":")[0];
    findings.set(host, (findings.get(host) ?? 0) + 1);
  }
  return findings;
}

export function createInventoryStore(options: InventoryStoreOptions = {}) {
  const inventoryDir = options.inventoryDir ?? DEFAULT_INVENTORY_DIR;
  const targetDir = resolve(inventoryDir, "targets");
  const validate = validators(SCHEMA_DIR);
  const now = options.now ?? (() => new Date());
  const observationPath = options.observationPath ?? resolve(inventoryDir, "..", ".gen", "discovered.json");

  function manifest(): Manifest {
    const path = resolve(inventoryDir, "inventory.json");
    const value = parseJson(path);
    assertValid(validate.manifest, value, path);
    return value as Manifest;
  }

  function get(id: string): TargetDocument {
    return redactCredentials(read(id));
  }

  function read(id: string): TargetDocument {
    assertTargetID(id);
    const path = resolve(targetDir, `${id}.json`);
    if (!existsSync(path)) throw new Error(`target not found: ${id}`);
    const value = parseJson(path);
    assertValid(validate.target, value, path);
    const target = value as TargetDocument;
    if (target.id !== id) throw new Error(`${basename(path)}: id must match filename`);
    return target;
  }

  function write(target: TargetDocument): TargetDocument {
    assertTargetID(target.id);
    assertCredentialsWritable(target);
    const path = resolve(targetDir, `${target.id}.json`);
    assertValid(validate.target, target, path);
    mkdirSync(targetDir, { recursive: true });
    const temporary = resolve(targetDir, `.${target.id}.${process.pid}.tmp`);
    writeFileSync(temporary, `${JSON.stringify(target, null, 2)}\n`, "utf8");
    renameSync(temporary, path);
    return get(target.id);
  }

  function list(): Inventory {
    const definition = manifest();
    const rows = readdirSync(targetDir)
      .filter((filename) => filename.endsWith(".json"))
      .map((filename) => get(filename.slice(0, -".json".length)))
      .sort((left, right) => left.id.localeCompare(right.id));
    return {
      version: definition.version,
      zones: definition.zones,
      rows,
      tagVocabulary: [...new Set(rows.flatMap((target) => target.tags))].sort(),
    };
  }

  function updateCurated({ id, curated }: UpdateOptions): TargetDocument {
    assertTargetID(id);
    const unexpected = Object.keys(curated).find((key) => !CURATED_FIELDS.has(key));
    if (unexpected === "id" || unexpected === "host") throw new Error(`${unexpected} is immutable`);
    if (unexpected) throw new Error(`field is not editable: ${unexpected}`);
    const targetExists = existsSync(resolve(targetDir, `${id}.json`));
    const existing = targetExists
      ? read(id)
      : ({ $schema: "../target.schema.json", version: 3, id, host: id } as TargetDocument);
    const hasCredentials = Object.prototype.hasOwnProperty.call(curated, "credentials");
    const { credentials, ...curatedFields } = curated;
    const machineOwned = Object.fromEntries(
      Object.entries(existing).filter(([key]) => !CURATED_FIELDS.has(key)),
    ) as TargetDocument;
    let target = { ...machineOwned, ...curatedFields } as TargetDocument;
    if (hasCredentials && credentials !== null && credentials !== undefined) {
      target.credentials = credentials;
    } else if (!hasCredentials && existing.credentials) {
      target.credentials = existing.credentials;
    }
    if (targetExists) return write(target);
    const cached = readJsonLines(observationPath).find((value) => getObservationHost(value) === id);
    if (cached) target = applyObservation(target, cached, now().toISOString());
    return write(target);
  }

  function addressableTargetIDs(): Map<string, string> {
    const result = new Map<string, string>();
    for (const target of list().rows) {
      if (!target.host) continue;
      const existing = result.get(target.host);
      if (existing) {
        throw new Error(`host ${target.host} belongs to both ${existing} and ${target.id}`);
      }
      result.set(target.host, target.id);
    }
    return result;
  }

  function mergeDiscovery(records: unknown[]): { updated: string[]; unknown: string[] } {
    const updated: string[] = [];
    const unknown: string[] = [];
    const timestamp = now().toISOString();
    const idByHost = addressableTargetIDs();
    for (const record of records) {
      const host = getObservationHost(record);
      const id = idByHost.get(host);
      if (!id) {
        unknown.push(host);
        continue;
      }
      write(applyObservation(read(id), record, timestamp));
      updated.push(host);
    }
    return { updated: [...new Set(updated)].sort(), unknown: [...new Set(unknown)].sort() };
  }

  function recordScan({ hosts, resultPath, scannedAt }: ScanUpdate): void {
    const findings = countFindings(resultPath);
    const timestamp = scannedAt ?? now().toISOString();
    const idByHost = addressableTargetIDs();
    for (const host of [...new Set(hosts)].sort()) {
      const id = idByHost.get(host);
      if (!id) throw new Error(`target not found for host: ${host}`);
      const target = read(id);
      write({ ...target, scan: { last_scan: timestamp, last_findings: findings.get(host) ?? 0 } });
    }
  }

  function render({ outputDir }: RenderOptions): Record<string, number> {
    const rows = list().rows;
    const counts: Record<string, number> = {};
    mkdirSync(outputDir, { recursive: true });
    const writeList = (name: string, targets: TargetDocument[]) => {
      const hosts = [...new Set(targets.flatMap((target) => (target.host ? [target.host] : [])))].sort();
      writeFileSync(resolve(outputDir, `${name}.txt`), hosts.length ? `${hosts.join("\n")}\n` : "", "utf8");
      counts[name] = hosts.length;
    };
    for (const targetClass of ["public", "prod", "non-prod", "internal", "unclassified", "deactivated"]) {
      const classRows = rows.filter((target) => target.class === targetClass);
      writeList(targetClass, classRows);
      for (const profile of ["safe", "full"]) {
        writeList(
          `${targetClass}.${profile}`,
          classRows.filter((target) => target.profiles.includes(`scan:nuclei:${profile}`)),
        );
      }
    }
    const defaults = rows.filter((target) => target.class === "public" || target.class === "non-prod");
    writeList("default", defaults);
    writeList("all", rows);
    for (const profile of ["safe", "full"]) {
      writeList(
        `default.${profile}`,
        defaults.filter((target) => target.profiles.includes(`scan:nuclei:${profile}`)),
      );
      writeList(
        `all.${profile}`,
        rows.filter((target) => target.profiles.includes(`scan:nuclei:${profile}`)),
      );
    }
    return counts;
  }

  return { get, list, mergeDiscovery, recordScan, render, updateCurated };
}

function assertCredentialsWritable(target: TargetDocument): void {
  for (const env of target.credentials?.envVars ?? []) {
    if (env.configured) {
      throw new Error(`credential ${env.name}: configured is response-only`);
    }
  }
}

function redactCredentials(target: TargetDocument): TargetDocument {
  if (!target.credentials?.envVars) return target;
  return {
    ...target,
    credentials: {
      ...target.credentials,
      envVars: target.credentials.envVars.map(({ value, ...env }) =>
        value === undefined ? env : { ...env, configured: true },
      ),
    },
  };
}
