import { useMemo, useState } from "react";
import {
  Button,
  JsonSchemaForm,
  Panel,
  Select,
  parseSecretRef,
  type JsonSchemaObject,
  type LookupFetcher,
  type SecretKeyValue,
} from "@flanksource/clicky-ui/components";
import { fetchLookupOptions } from "./api";
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
  lookupFetcher?: LookupFetcher;
};

type CredentialMethod = {
	id: string;
	title: string;
	envVars?: Array<{ name: string; title: string }>;
	connection?: { key: string; type: string };
};

type CredentialForm = {
  method: CredentialMethod;
  name: string;
  schema: JsonSchemaObject;
};

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function credentialMethods(schema: EngineOptionSchema): CredentialMethod[] {
  const raw = schema["x-credential-methods"];
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new Error("credential schema must define x-credential-methods");
  }
  return raw.map((value) => {
    const method = object(value, "credential method");
    if (typeof method.id !== "string" || typeof method.title !== "string") {
      throw new Error("credential method requires id and title");
    }
    return method as CredentialMethod;
  });
}

function formForMethod(method: CredentialMethod): CredentialForm {
  if (method.connection) {
    return {
      method,
      name: method.connection.key,
      schema: {
        type: "object",
        title: method.title,
        required: ["connection"],
        properties: {
          connection: {
            type: "string",
            title: "Connection",
            "x-clicky-lookup": {
              url: "/api/v1/connection",
              filter: "connection",
              types: [method.connection.type],
            },
          },
        },
      },
    };
  }
  if (!method.envVars?.length) {
    throw new Error(`credential method ${method.id} has no credential fields`);
  }
  return {
    method,
    name: method.id,
    schema: {
      type: "object",
      title: method.title,
      properties: Object.fromEntries(
        method.envVars.map((variable) => [
          variable.name,
          {
            type: "string",
            title: variable.title || credentialTitle(variable.name),
            description:
              "Choose an inline value or a runtime reference. Secret values are never displayed after saving.",
            "x-clicky-component": "k8s-secret-selector",
            "x-clicky-default-source": "value",
          },
        ]),
      ),
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

function methodForValue(methods: CredentialMethod[], value?: TargetCredentials): CredentialMethod {
  const connectionKeys = Object.keys(value?.connections ?? {});
  const envNames = (value?.envVars ?? []).map((item) => item.name).sort();
  return (
    methods.find((method) =>
      method.connection
        ? connectionKeys.length === 1 && connectionKeys[0] === method.connection.key
        : JSON.stringify((method.envVars ?? []).map((item) => item.name).sort()) === JSON.stringify(envNames),
    ) ?? methods[0]
  );
}

const defaultLookupFetcher: LookupFetcher = async ({ descriptor, query }) => {
  const types = (descriptor as typeof descriptor & { types?: string[] }).types;
  return fetchLookupOptions(
    descriptor.url,
    descriptor.filter,
    query,
    types?.length ? { types: types.join(",") } : {},
  );
};

export function CredentialConfigForm({ schema, value, onChange, lookupFetcher }: Props) {
  const methods = useMemo(() => credentialMethods(schema), [schema]);
  const [methodID, setMethodID] = useState(() => methodForValue(methods, value).id);
  const method = methods.find((candidate) => candidate.id === methodID) ?? methods[0];
  const form = useMemo(() => formForMethod(method), [method]);
  const currentEnv = new Map((value?.envVars ?? []).map((item) => [item.name, item]));
  const formValue = method.connection
    ? {
        connection: object(value?.connections?.[method.connection.key] ?? {}, "connection credential")
          .connection,
      }
    : Object.fromEntries(
        (method.envVars ?? []).flatMap((variable) => {
          const current = currentEnv.get(variable.name);
          const reference = current ? secretRefFromEnvVar(current) : undefined;
          return reference === undefined ? [] : [[variable.name, reference]];
        }),
      );
  const configuredInline = (method.envVars ?? []).filter(
    (variable) => currentEnv.get(variable.name)?.configured === true && !currentEnv.get(variable.name)?.valueFrom,
  );

  return (
    <Panel title={typeof schema.title === "string" ? schema.title : "Credentials"}>
      <div className="space-y-3">
        {methods.length > 1 ? (
          <label className="block space-y-1 text-sm" htmlFor="credential-method">
            <span className="font-medium">Authentication method</span>
            <Select
              id="credential-method"
              value={method.id}
              options={methods.map((candidate) => ({ value: candidate.id, label: candidate.title }))}
              onChange={(event) => setMethodID(event.target.value)}
            />
          </label>
        ) : null}
        {configuredInline.length > 0 ? (
          <p className="text-xs text-muted-foreground">
            {configuredInline.length === 1 ? "A configured value is" : "Configured values are"} hidden.
            Saving other fields preserves {configuredInline.length === 1 ? "it" : "them"} until replaced or cleared.
          </p>
        ) : null}
        <JsonSchemaForm
          schema={form.schema}
          value={formValue}
          onChange={(next) => {
            if (method.connection) {
              if (typeof next.connection !== "string" || next.connection === "") {
                throw new Error("connection picker must produce a connection reference");
              }
              onChange({ connections: { [method.connection.key]: { connection: next.connection } } });
              return;
            }
            const envVars = (method.envVars ?? []).flatMap((variable) => {
              const raw = next[variable.name];
              if (typeof raw === "string" && raw !== "") {
                return [envVarFromSecretRef(variable.name, raw)];
              }
              const current = currentEnv.get(variable.name);
              return current?.configured ? [current] : [];
            });
            onChange({ envVars });
          }}
          post={credentialFormExtensions.post}
          layout={{ mode: "inline", valueMaxWidth: "48rem" }}
          idPrefix="target-credentials"
          lookupFetcher={lookupFetcher ?? defaultLookupFetcher}
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
