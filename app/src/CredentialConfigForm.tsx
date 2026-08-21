import { useMemo } from "react";
import {
  Button,
  JsonSchemaForm,
  Panel,
  parseSecretRef,
  type JsonSchemaObject,
  type SecretKeyValue,
} from "@flanksource/clicky-ui/components";
import type {
  CredentialEnvVar,
  CredentialMutation,
  CredentialValueFrom,
  EngineOptionSchema,
  TargetCredentials,
} from "./types";
import { credentialFormExtensions } from "./secret-form";

type Props = {
  schema: EngineOptionSchema;
  value?: TargetCredentials;
  onChange: (next: CredentialMutation) => void;
};

type FixedEnvVar = {
  name: string;
  schema: JsonSchemaObject;
};

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function fixedEnvVar(schema: EngineOptionSchema): FixedEnvVar | null {
  const properties = object(schema.properties ?? {}, "credential schema properties");
  if (!("envVars" in properties)) return null;
  const envVars = object(properties.envVars, "credential schema envVars");
  if (envVars.type !== "array") {
    throw new Error("credential schema envVars must be an array");
  }
  const item = object(envVars.items, "credential schema envVars items");
  const itemProperties = object(item.properties, "credential EnvVar properties");
  const name = object(itemProperties.name, "credential EnvVar name").const;
  if (typeof name !== "string" || name === "") {
    throw new Error("credential EnvVar name must have a non-empty const");
  }
  return {
    name,
    schema: {
      type: "object",
      title: typeof schema.title === "string" ? schema.title : "Credentials",
      properties: {
        credential: {
          type: "string",
          title: credentialTitle(name),
          description:
            "Choose an inline value or a runtime reference. Secret values are never displayed after saving.",
          "x-clicky-component": "k8s-secret-selector",
          "x-clicky-default-source": "value",
        },
      },
    },
  };
}

function credentialTitle(name: string): string {
  return name
    .toLowerCase()
    .split("_")
    .map((word, index) =>
      index === 0 ? word[0]?.toUpperCase() + word.slice(1) : word,
    )
    .join(" ")
    .replace("api", "API");
}

function selectorReference(valueFrom: CredentialValueFrom): string {
  const entries = Object.entries(valueFrom).filter(([, value]) => value !== undefined);
  if (entries.length !== 1) {
    throw new Error("credential valueFrom must select exactly one source");
  }
  const [kind, source] = entries[0];
  if (kind === "onePassword") {
    if (typeof source !== "string") {
      throw new Error("credential onePassword reference must be a string");
    }
    return source;
  }
  const selector = object(source, `credential ${kind}`);
  if (typeof selector.name !== "string" || typeof selector.key !== "string") {
    throw new Error(`credential ${kind} must contain name and key`);
  }
  const prefix = {
    secretKeyRef: "secret",
    configMapKeyRef: "configmap",
    helmRef: "helm",
  }[kind];
  if (!prefix) throw new Error(`unsupported credential source ${kind}`);
  return `${prefix}://${selector.name}/${selector.key}`;
}

export function secretRefFromEnvVar(envVar: CredentialEnvVar): string | undefined {
  if (envVar.value !== undefined) return envVar.value;
  if (envVar.valueFrom) return selectorReference(envVar.valueFrom);
  if (envVar.configured) return undefined;
  throw new Error(`credential ${envVar.name} has no value, valueFrom, or configured marker`);
}

function valueFromSecret(value: Exclude<SecretKeyValue, { kind: "value" }>): CredentialValueFrom {
  switch (value.kind) {
    case "secret":
      return { secretKeyRef: { name: value.name, key: value.key } };
    case "configmap":
      return { configMapKeyRef: { name: value.name, key: value.key } };
    case "helm":
      return { helmRef: { name: value.name, key: value.key } };
    case "onepassword":
      return { onePassword: value.ref };
    case "serviceaccount":
      throw new Error("service-account credentials are not allowed");
  }
}

export function envVarFromSecretRef(name: string, raw: string): CredentialEnvVar {
  if (raw === "") return { name, value: "" };
  const parsed = parseSecretRef(raw);
  if (!parsed) throw new Error(`credential ${name} is not a valid secret reference`);
  return parsed.kind === "value"
    ? { name, value: parsed.value }
    : { name, valueFrom: valueFromSecret(parsed) };
}

export function CredentialConfigForm({ schema, value, onChange }: Props) {
  const field = useMemo(() => fixedEnvVar(schema), [schema]);
  if (!field) return null;

  const current = value?.envVars?.find((envVar) => envVar.name === field.name);
  const reference = current ? secretRefFromEnvVar(current) : undefined;
  const formValue = reference === undefined ? {} : { credential: reference };
  const configuredInline = current?.configured === true && !current.valueFrom;

  return (
    <Panel title={field.schema.title ?? "Credentials"}>
      <div className="space-y-3">
        {configuredInline ? (
          <p className="text-xs text-muted-foreground">
            A configured value is hidden. Saving other fields preserves it until
            you replace or explicitly clear it.
          </p>
        ) : null}
        <JsonSchemaForm
          schema={field.schema}
          value={formValue}
          onChange={(next) => {
            if (!("credential" in next) || typeof next.credential !== "string") {
              throw new Error("credential selector must produce a string reference");
            }
            onChange({
              envVars: [envVarFromSecretRef(field.name, next.credential)],
            });
          }}
          post={credentialFormExtensions.post}
          layout={{ mode: "inline", valueMaxWidth: "48rem" }}
          idPrefix="target-credentials"
        />
        <div className="flex justify-end">
          <Button variant="outline" size="sm" onClick={() => onChange(null)}>
            Clear credential
          </Button>
        </div>
      </div>
    </Panel>
  );
}
