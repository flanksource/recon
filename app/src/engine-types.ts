export type EngineKind = "discovery" | "scan";

export type EngineOptionSchema = Record<string, unknown>;

export type EngineOptionVariant = {
  id: string;
  title: string;
  schema: EngineOptionSchema;
  contextSchema?: EngineOptionSchema;
  credentialSchema?: EngineOptionSchema;
  schemaRef?: string;
  contextSchemaRef?: string;
  credentialSchemaRef?: string;
  cliArgumentsSchemaRef?: string;
};

export type EngineOptions = {
  discriminator?: string;
  variants: EngineOptionVariant[];
};

// What an engine's input list holds. Absent means endpoints — an address it
// connects to — which is what tells a control whether an engine's profiles can
// be assigned to a host at all.
export type EngineSubject = "accounts" | "provider-contexts";

export type Engine = {
  _id?: string;
  name: string;
  kind: EngineKind;
  title: string;
  description?: string;
  docsUrl?: string;
  binary: string;
  subject?: EngineSubject;
  accepts?: string;
  emits?: string;
  default?: boolean;
  version?: string;
  installed: boolean;
  managed: boolean;
  path?: string;
  defaults?: string;
  templates?: {
    version?: string;
    count: number;
    path?: string;
    problem?: string;
    itemLabel?: string;
    profileLabel?: string;
  };
  options: EngineOptions;
};

export type Profile = {
  _id?: string;
  kind: EngineKind;
  engine: string;
  name: string;
  config: Record<string, unknown>;
  comment?: string;
  intrusive?: boolean;
  reason?: string;
};
