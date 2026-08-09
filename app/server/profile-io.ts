import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseDocument } from "yaml";
import {
  validateProfileConfig,
  type ProfileDocument,
  type ProfileEngine,
} from "../profile-schema/index.ts";

const NUCLEI_DIR = resolve(import.meta.dirname, "..", "..");
const PROFILE_NAME = /^[a-z0-9][a-z0-9-]*$/;

export type ProfileStoreOptions = {
  configDir?: string;
};

function configDirectory(options: ProfileStoreOptions): string {
  return options.configDir ?? resolve(NUCLEI_DIR, "config");
}

function profileIdentity(
  filename: string,
): { engine: ProfileEngine; name: string } | null {
  if (filename.endsWith(".naabu.yaml")) {
    return { engine: "naabu", name: filename.slice(0, -".naabu.yaml".length) };
  }
  if (filename.endsWith(".httpx.yaml")) {
    return { engine: "httpx", name: filename.slice(0, -".httpx.yaml".length) };
  }
  if (filename.endsWith(".yaml")) {
    return { engine: "nuclei", name: filename.slice(0, -".yaml".length) };
  }
  return null;
}

function profileFilename(engine: ProfileEngine, name: string): string {
  if (!PROFILE_NAME.test(name))
    throw new Error(`invalid profile name: ${name}`);
  if (engine === "httpx") return `${name}.httpx.yaml`;
  if (engine === "naabu") return `${name}.naabu.yaml`;
  return `${name}.yaml`;
}

function leadingCommentBlock(source: string): string {
  return source.match(/^(?:(?:[ \t]*#[^\n]*|[ \t]*)\n)+/)?.[0] ?? "";
}

function readProfileFile(configDir: string, filename: string): ProfileDocument {
  const identity = profileIdentity(filename);
  if (!identity) throw new Error(`unsupported profile filename: ${filename}`);
  const parsed = parseDocument(
    readFileSync(resolve(configDir, filename), "utf8"),
  );
  if (parsed.errors.length)
    throw new Error(
      `invalid YAML in ${filename}: ${parsed.errors[0]?.message}`,
    );
  const config = parsed.toJS() as unknown;
  if (config === null || typeof config !== "object" || Array.isArray(config)) {
    throw new Error(`profile ${filename} must contain a YAML object`);
  }
  validateProfileConfig(identity.engine, config as Record<string, unknown>);
  return {
    id: `${identity.engine}:${identity.name}`,
    ...identity,
    filename,
    config: config as Record<string, unknown>,
  };
}

export function listProfiles(
  options: ProfileStoreOptions = {},
): ProfileDocument[] {
  const configDir = configDirectory(options);
  return readdirSync(configDir)
    .filter((filename) => profileIdentity(filename) !== null)
    .map((filename) => readProfileFile(configDir, filename))
    .sort((a, b) => a.id.localeCompare(b.id));
}

export function writeProfile(
  engine: ProfileEngine,
  name: string,
  config: Record<string, unknown>,
  options: ProfileStoreOptions = {},
): ProfileDocument {
  const configDir = configDirectory(options);
  const filename = profileFilename(engine, name);
  const path = resolve(configDir, filename);
  if (!existsSync(path))
    throw new Error(`profile not found: ${engine}:${name}`);
  if (config === null || typeof config !== "object" || Array.isArray(config)) {
    throw new Error("profile config must be an object");
  }
  validateProfileConfig(engine, config);

  const source = readFileSync(path, "utf8");
  const document = parseDocument(source);
  if (document.errors.length)
    throw new Error(
      `invalid YAML in ${filename}: ${document.errors[0]?.message}`,
    );
  const previous = document.toJS() as Record<string, unknown>;
  for (const key of Object.keys(previous)) {
    if (!(key in config)) document.delete(key);
  }
  for (const [key, value] of Object.entries(config)) document.set(key, value);
  const rendered = document
    .toString({ lineWidth: 0 })
    .replace(/^(?:(?:[ \t]*#[^\n]*|[ \t]*)\n)+/, "");
  writeFileSync(path, `${leadingCommentBlock(source)}${rendered}`, "utf8");
  return readProfileFile(configDir, filename);
}
