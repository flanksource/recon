import type {
  JsonSchemaObject,
  JsonSchemaProperty,
} from "@flanksource/clicky-ui";

export type ProfileEngine = "nuclei" | "httpx" | "naabu";

export type ProfileSchemaSection = {
  id: string;
  title: string;
  description: string;
  sourceUrl: string;
  properties: Record<string, JsonSchemaProperty>;
};

export type ProfileDocument = {
  id: string;
  engine: ProfileEngine;
  name: string;
  filename: string;
  config: Record<string, unknown>;
};

export function booleanOption(
  title: string,
  description: string,
): JsonSchemaProperty {
  return { type: "boolean", title, description };
}

export function integerOption(
  title: string,
  description: string,
  range: { minimum?: number; maximum?: number } = {},
): JsonSchemaProperty {
  return { type: "integer", title, description, multipleOf: 1, ...range };
}

export function stringOption(
  title: string,
  description: string,
): JsonSchemaProperty {
  return { type: "string", title, description };
}

export function enumOption(
  title: string,
  description: string,
  values: string[],
): JsonSchemaProperty {
  return { type: "string", title, description, enum: values };
}

export function stringList(
  title: string,
  description: string,
): JsonSchemaProperty {
  return { type: "array", title, description, items: { type: "string" } };
}

export function enumList(
  title: string,
  description: string,
  values: Array<string | number>,
): JsonSchemaProperty {
  return {
    type: "array",
    title,
    description,
    items: { enum: values },
    "x-array-display": "filter-pills",
  };
}

export function sectionSchema(section: ProfileSchemaSection): JsonSchemaObject {
  return {
    type: "object",
    title: section.title,
    description: section.description,
    additionalProperties: false,
    properties: section.properties,
    "x-columns": "auto",
    "x-column-min-width": "18rem",
    "x-classes": "gap-x-5 gap-y-4",
  };
}
