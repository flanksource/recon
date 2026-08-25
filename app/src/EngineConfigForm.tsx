import { useEffect, useMemo, useState } from "react";
import {
  Button,
  JsonSchemaForm,
  resolveLookupScope,
  type JsonSchemaFormError,
  type JsonSchemaObject,
  type JsonSchemaProperty,
  type LookupFetcher,
} from "@flanksource/clicky-ui/components";
import { fetchLookupOptions } from "./api";
import { sectionMutexGroups, useMutualExclusions, type MutexGroup } from "./MutualExclusions";
import { useProfileFilterPairs } from "./ProfileFilterPairs";
import type { CredentialMode, Engine, EngineOptionVariant } from "./types";

export type EngineConfigFormProps = {
  engine: Engine;
  identity: string;
  value: Record<string, unknown>;
  baseline?: Record<string, unknown>;
  onChange: (value: Record<string, unknown>) => void;
  onReset?: () => void;
  note?: string;
  errors?: JsonSchemaFormError[];
  lookupFetcher?: LookupFetcher;
  schemaKind?: "profile" | "context";
  variantId?: string;
  credentialMode?: CredentialMode;
  preferencesStorageKey?: string;
};

export function sameConfig(
  left: Record<string, unknown>,
  right: Record<string, unknown>,
): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

type EngineConfigSection = {
  id: string;
  title: string;
  description?: string;
  sourceUrl?: string;
  schema: JsonSchemaObject;
  keys: string[];
  mutexes: MutexGroup[];
};

export type ResolvedEngineConfigSchema = {
  variant: EngineOptionVariant;
  sections: EngineConfigSection[];
  discriminator?: string;
  credentialSelectorKeys: string[];
};

type SectionMetadata = Omit<EngineConfigSection, "schema" | "keys" | "mutexes">;

function objectSchema(
  engine: Engine,
  variant: EngineOptionVariant,
  schemaKind: "profile" | "context",
): JsonSchemaObject {
  const schema = schemaKind === "context" ? variant.contextSchema : variant.schema;
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) {
    throw new Error(
      `${engine.title} ${variant.title} has no ${schemaKind} configuration schema`,
    );
  }
  if (schema.type !== "object" || !schema.properties) {
    throw new Error(`${engine.title} ${variant.title} ${schemaKind} schema must be an object`);
  }
  return schema as JsonSchemaObject;
}

function resolveVariant(
  engine: Engine,
  value: Record<string, unknown>,
  variantId?: string,
): EngineOptionVariant {
  const { discriminator, variants } = engine.options;
  if (variants.length === 0) throw new Error(`${engine.title} defines no option variants`);
  if (!discriminator) {
    if (variants.length !== 1) {
      throw new Error(`${engine.title} requires an option discriminator`);
    }
    return variants[0];
  }

  const configured = value[discriminator];
  if (variantId && configured !== undefined && configured !== variantId) {
    throw new Error(`${engine.title} ${discriminator} cannot be changed in this editor`);
  }
  const selected = variantId ?? configured;
  if (typeof selected !== "string" || selected.length === 0) {
    throw new Error(`${engine.title} configuration requires "${discriminator}"`);
  }
  const variant = variants.find((candidate) => candidate.id === selected);
  if (!variant) {
    throw new Error(
      `${engine.title} does not define ${discriminator} variant "${selected}"`,
    );
  }
  return variant;
}

function sectionMetadata(engine: Engine, root: JsonSchemaObject): SectionMetadata[] {
  const value = root["x-sections"];
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${engine.title} configuration schema has no sections`);
  }
  const sections = value.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error(`${engine.title} configuration schema has an invalid section`);
    }
    const section = item as Record<string, unknown>;
    if (typeof section.id !== "string" || typeof section.title !== "string") {
      throw new Error(`${engine.title} configuration schema section requires id and title`);
    }
    return {
      id: section.id,
      title: section.title,
      ...(typeof section.description === "string"
        ? { description: section.description }
        : {}),
      ...(typeof section.sourceUrl === "string" ? { sourceUrl: section.sourceUrl } : {}),
    };
  });
  if (new Set(sections.map((section) => section.id)).size !== sections.length) {
    throw new Error(`${engine.title} configuration schema has duplicate section ids`);
  }
  return sections;
}

function orderedPropertyKeys(engine: Engine, root: JsonSchemaObject): string[] {
  const properties = root.properties ?? {};
  const order = root["x-order"];
  if (!Array.isArray(order) || !order.every((key) => typeof key === "string")) {
    throw new Error(`${engine.title} configuration schema requires x-order`);
  }
  if (new Set(order).size !== order.length) {
    throw new Error(`${engine.title} configuration schema x-order has duplicate properties`);
  }
  const propertyKeys = Object.keys(properties);
  if (order.length !== propertyKeys.length || order.some((key) => !(key in properties))) {
    throw new Error(`${engine.title} configuration schema x-order must include every property`);
  }
  return order;
}

function stripSchemaDefaults(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stripSchemaDefaults);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([key]) => key !== "default")
      .map(([key, child]) => [key, stripSchemaDefaults(child)]),
  );
}

function projectSections(
  engine: Engine,
  root: JsonSchemaObject,
  discriminator?: string,
): EngineConfigSection[] {
  const metadata = sectionMetadata(engine, root);
  const sectionIds = new Set(metadata.map((section) => section.id));
  const order = orderedPropertyKeys(engine, root);
  const properties = root.properties ?? {};
  for (const key of order.filter((candidate) => candidate !== discriminator)) {
    const section = properties[key]?.["x-section"];
    if (typeof section !== "string" || !sectionIds.has(section)) {
      throw new Error(`${engine.title} configuration property "${key}" has no valid section`);
    }
  }

  return metadata.flatMap((section) => {
    const keys = order.filter(
      (key) => key !== discriminator && properties[key]?.["x-section"] === section.id,
    );
    if (keys.length === 0) return [];
    const projected: JsonSchemaObject = {
      type: "object",
      additionalProperties: root.additionalProperties,
      properties: Object.fromEntries(
        keys.map((key) => [key, stripSchemaDefaults(properties[key]) as JsonSchemaProperty]),
      ),
      required: root.required?.filter((key) => keys.includes(key)),
      ...(root.$defs && typeof root.$defs === "object"
        ? { $defs: stripSchemaDefaults(root.$defs) as JsonSchemaObject["$defs"] }
        : {}),
    };
    const mutexes = sectionMutexGroups({
      root,
      sectionTitle: section.title,
      sectionKeys: keys,
      describe: (message) => `${engine.title} configuration schema ${message}`,
    });
    return [{ ...section, keys, schema: projected, mutexes }];
  });
}

export function resolveEngineConfigSchema(
  engine: Engine,
  value: Record<string, unknown>,
  schemaKind: "profile" | "context" = "profile",
  variantId?: string,
): ResolvedEngineConfigSchema {
  const variant = resolveVariant(engine, value, variantId);
  const discriminator = engine.options.discriminator;
  const root = objectSchema(engine, variant, schemaKind);
  const sections = projectSections(engine, root, discriminator);
  if (sections.length === 0) {
    throw new Error(`${engine.title} ${variant.title} ${schemaKind} schema has no editable sections`);
  }
  const credentialSelectorKeys = Object.entries(root.properties ?? {})
    .filter(([, property]) => property["x-credential-selector"] === true)
    .map(([key]) => key);
  return {
    variant,
    sections,
    credentialSelectorKeys,
    ...(discriminator ? { discriminator } : {}),
  };
}

function unescapePointerToken(token: string): string {
  return token.replaceAll("~1", "/").replaceAll("~0", "~");
}

function errorsForSection(
  errors: JsonSchemaFormError[],
  section: EngineConfigSection,
): JsonSchemaFormError[] {
  return errors.filter((error) => {
    if (!error.instancePath) return true;
    const firstToken = error.instancePath.split("/")[1];
    return firstToken !== undefined && section.keys.includes(unescapePointerToken(firstToken));
  });
}

const lookupFetcher: LookupFetcher = async ({ descriptor, query, rootValue }) =>
  fetchLookupOptions(
    descriptor.url,
    descriptor.filter,
    query,
    resolveLookupScope(descriptor, rootValue),
  );

export function EngineConfigForm({
  engine,
  identity,
  value,
  baseline,
  onChange,
  onReset,
  note,
  errors = [],
  lookupFetcher: customLookupFetcher,
  schemaKind = "profile",
  variantId,
  credentialMode,
  preferencesStorageKey = "run-profile-form-preferences",
}: EngineConfigFormProps) {
  const resolved = useMemo(
    () => resolveEngineConfigSchema(engine, value, schemaKind, variantId),
    [engine, schemaKind, value, variantId],
  );
  const { pre, post, hiddenKeys } = useProfileFilterPairs(engine.name === "nuclei");
  const [sectionId, setSectionId] = useState(resolved.sections[0].id);
  const firstSectionId = resolved.sections[0].id;
  const activeSection =
    resolved.sections.find((section) => section.id === sectionId) ?? resolved.sections[0];
  const mutexes = useMutualExclusions(
    activeSection.mutexes,
    `${identity}:${resolved.variant.id}:${schemaKind}`,
  );
  const tweaked = baseline ? !sameConfig(value, baseline) : false;

  useEffect(
    () => setSectionId(firstSectionId),
    [firstSectionId, identity, resolved.variant.id, schemaKind],
  );

  useEffect(() => {
    if (credentialMode !== "ambient") return;
    const forbidden = new Set(resolved.credentialSelectorKeys);
    if (!Object.keys(value).some((key) => forbidden.has(key))) return;
    onChange(
      Object.fromEntries(Object.entries(value).filter(([key]) => !forbidden.has(key))),
    );
  }, [credentialMode, onChange, resolved.credentialSelectorKeys, value]);

  const commit = (next: Record<string, unknown>) => {
    if (
      resolved.discriminator &&
      (variantId
        ? Object.hasOwn(next, resolved.discriminator)
        : next[resolved.discriminator] !== value[resolved.discriminator])
    ) {
      throw new Error(
        `${engine.title} ${resolved.discriminator} cannot be changed in this editor`,
      );
    }
    onChange(next);
  };
  const activeErrors = errorsForSection(errors, activeSection);
  const fetchLookup = customLookupFetcher ?? lookupFetcher;
  const scopedLookupFetcher: LookupFetcher = (request) =>
    fetchLookup({
      ...request,
      rootValue: resolved.discriminator
        ? {
            ...request.rootValue,
            [resolved.discriminator]: resolved.variant.id,
          }
        : request.rootValue,
    });

  return (
    <div className="flex min-h-0 flex-1 overflow-hidden rounded-md border border-border">
      <nav className="w-48 shrink-0 space-y-1 overflow-y-auto border-r border-border bg-muted/20 p-2">
        {resolved.discriminator ? (
          <p className="px-3 pb-2 text-xs font-medium text-muted-foreground">
            {resolved.variant.title}
          </p>
        ) : null}
        {resolved.sections.map((section) => {
          const sectionErrors = errorsForSection(errors, section).length;
          return (
            <button
              key={section.id}
              type="button"
              aria-label={section.title}
              onClick={() => setSectionId(section.id)}
              className={`flex w-full items-center rounded-md px-3 py-2 text-left text-sm transition-colors ${
                section.id === activeSection.id
                  ? "bg-accent font-medium text-accent-foreground"
                  : "text-muted-foreground hover:bg-accent/60 hover:text-foreground"
              }`}
            >
              <span>{section.title}</span>
              {sectionErrors > 0 ? (
                <span aria-hidden="true" className="ml-auto text-xs text-destructive">
                  {sectionErrors}
                </span>
              ) : null}
            </button>
          );
        })}
      </nav>
      <section className="min-w-0 flex-1 overflow-y-auto p-4">
        <div className="mb-4 flex items-start gap-3">
          <div>
            <h3 className="font-semibold">{activeSection.title}</h3>
            {activeSection.description ? (
              <p className="mt-1 text-sm text-muted-foreground">
                {activeSection.description}
              </p>
            ) : null}
            {activeSection.sourceUrl ? (
              <a
                className="mt-1 block text-xs text-primary underline"
                href={activeSection.sourceUrl}
                target="_blank"
                rel="noreferrer"
              >
                Upstream flags ↗
              </a>
            ) : null}
          </div>
          <span className="flex-1" />
          {tweaked ? (
            <span className="pt-2 text-xs text-amber-600 dark:text-amber-400">
              Unsaved changes
            </span>
          ) : null}
          {onReset ? (
            <Button variant="outline" size="sm" disabled={!tweaked} onClick={onReset}>
              Reset changes
            </Button>
          ) : null}
        </div>
        <JsonSchemaForm
          key={`${identity}:${resolved.variant.id}:${activeSection.id}`}
          idPrefix={`${identity}-${activeSection.id}`}
          schema={activeSection.schema}
          value={value}
          onChange={commit}
          errors={activeErrors}
          lookupFetcher={scopedLookupFetcher}
          pre={[...pre, ...mutexes.pre]}
          post={[...post, ...mutexes.post]}
          hiddenKeys={[
            ...hiddenKeys,
            ...(credentialMode === "ambient" ? resolved.credentialSelectorKeys : []),
          ]}
          layout={{ mode: "stacked", help: "hover", valueMaxWidth: "100%" }}
          size="sm"
          preferencesStorageKey={preferencesStorageKey}
        />
        {note ? <p className="mt-4 text-xs text-muted-foreground">{note}</p> : null}
      </section>
    </div>
  );
}
