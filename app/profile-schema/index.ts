import { httpxProfileSections } from "./httpx.ts";
import { nucleiProfileSections } from "./nuclei.ts";
import { naabuProfileSections } from "./naabu.ts";
import type { JsonSchemaProperty } from "@flanksource/clicky-ui";
import type { ProfileEngine, ProfileSchemaSection } from "./types.ts";

export { sectionSchema } from "./types.ts";
export type {
  ProfileDocument,
  ProfileEngine,
  ProfileSchemaSection,
} from "./types.ts";

export const profileSections: Record<ProfileEngine, ProfileSchemaSection[]> = {
  nuclei: nucleiProfileSections,
  httpx: httpxProfileSections,
  naabu: naabuProfileSections,
};

export function profileOptionKeys(engine: ProfileEngine): string[] {
  return profileSections[engine].flatMap((section) =>
    Object.keys(section.properties),
  );
}

function validateOption(
  key: string,
  value: unknown,
  schema: JsonSchemaProperty,
): void {
  const type = schema.type;
  const valid =
    (type === undefined && schema.enum !== undefined) ||
    (type === "boolean" && typeof value === "boolean") ||
    (type === "string" && typeof value === "string") ||
    (type === "integer" && Number.isInteger(value)) ||
    (type === "number" &&
      typeof value === "number" &&
      Number.isFinite(value)) ||
    (type === "array" && Array.isArray(value)) ||
    (type === "object" &&
      typeof value === "object" &&
      value !== null &&
      !Array.isArray(value));
  if (!valid)
    throw new Error(
      `invalid value for profile option ${key}: expected ${String(type)}`,
    );
  if (schema.enum && !schema.enum.includes(value)) {
    throw new Error(
      `invalid value for profile option ${key}: ${String(value)}`,
    );
  }
  if (Array.isArray(value) && schema.items) {
    value.forEach((item) =>
      validateOption(`${key}[]`, item, schema.items as JsonSchemaProperty),
    );
  }
  if (
    typeof value === "number" &&
    schema.minimum != null &&
    value < schema.minimum
  ) {
    throw new Error(
      `invalid value for profile option ${key}: minimum is ${schema.minimum}`,
    );
  }
  if (
    typeof value === "number" &&
    schema.maximum != null &&
    value > schema.maximum
  ) {
    throw new Error(
      `invalid value for profile option ${key}: maximum is ${schema.maximum}`,
    );
  }
}

export function validateProfileConfig(
  engine: ProfileEngine,
  config: Record<string, unknown>,
): void {
  const schemas = new Map(
    profileSections[engine].flatMap((section) =>
      Object.entries(section.properties),
    ),
  );
  for (const [key, value] of Object.entries(config)) {
    const schema = schemas.get(key);
    if (!schema)
      throw new Error(`unsupported ${engine} profile option: ${key}`);
    validateOption(key, value, schema);
  }
}
