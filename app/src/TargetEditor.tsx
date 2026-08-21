import type { ComponentProps } from "react";
import { JsonSchemaForm, Panel } from "@flanksource/clicky-ui/components";
import { ProviderContextConfiguration } from "./ProviderContextConfiguration";
import type {
  CredentialMutation,
  CredentialMode,
  Engine,
  TargetCredentials,
  TargetDocument,
} from "./types";

type TargetSchema = ComponentProps<typeof JsonSchemaForm>["schema"];
type TargetPreExtension = NonNullable<
  ComponentProps<typeof JsonSchemaForm>["pre"]
>[number];

export type ProviderEngineState = { engine: Engine } | { error: string } | null;

type Props = {
  id: string;
  target: TargetDocument;
  schema: TargetSchema;
  draft: Record<string, unknown>;
  setDraft: (update: (current: Record<string, unknown>) => Record<string, unknown>) => void;
  catalogLoaded: boolean;
  providerEngine: ProviderEngineState;
  credentialMutation: CredentialMutation;
  onCredentialChange: (next: CredentialMutation) => void;
};

const hideMachineFields: TargetPreExtension = (field, context) =>
  field.key === "arguments" ||
  field.key === "credentials" ||
  (field.key === "reason" && context.rootValue?.class !== "deactivated")
    ? null
    : field;

function effectiveCredentials(
  stored: TargetCredentials | undefined,
  mutation: CredentialMutation,
): TargetCredentials | undefined {
  if (mutation === undefined) return stored;
  return mutation ?? undefined;
}

function providerCredentialMode(value: unknown): CredentialMode {
  if (value === "ambient" || value === "configured") return value;
  throw new Error("provider-context target has no valid credential mode");
}

export function TargetEditor({
  id,
  target,
  schema,
  draft,
  setDraft,
  catalogLoaded,
  providerEngine,
  credentialMutation,
  onCredentialChange,
}: Props) {
  const provider = target.provider;
  return (
    <div className="space-y-4">
      <Panel title="Edit target definition">
        <JsonSchemaForm
          schema={schema}
          value={draft}
          onChange={(next) => {
            if (
              target.kind === "provider-context" &&
              draft.credentialMode === "configured" &&
              next.credentialMode === "ambient" &&
              (target.credentials || credentialMutation)
            ) {
              onCredentialChange(null);
            }
            setDraft(() => ({ ...target, ...next }));
          }}
          hideReadOnlyFields
          requiredFirst
          pre={[hideMachineFields]}
          layout={{ mode: "inline", valueMaxWidth: "48rem" }}
          idPrefix="target"
        />
      </Panel>
      {target.kind === "provider-context" && !catalogLoaded ? (
        <p className="text-sm text-muted-foreground">Loading provider options…</p>
      ) : null}
      {target.kind === "provider-context" && providerEngine && "error" in providerEngine ? (
        <p
          className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive"
          role="alert"
        >
          {providerEngine.error}
        </p>
      ) : null}
      {target.kind === "provider-context" &&
      provider &&
      providerEngine &&
      "engine" in providerEngine ? (
        <>
          <ProviderContextConfiguration
            engine={providerEngine.engine}
            identity={`${id}:context`}
            provider={provider}
            credentialMode={providerCredentialMode(draft.credentialMode)}
            arguments={(draft.arguments as Record<string, unknown> | undefined) ?? {}}
            baselineArguments={target.arguments ?? {}}
            credentials={effectiveCredentials(target.credentials, credentialMutation)}
            onArgumentsChange={(arguments_) =>
              setDraft((current) => ({ ...current, arguments: arguments_ }))
            }
            onResetArguments={() =>
              setDraft((current) => ({
                ...current,
                arguments: structuredClone(target.arguments ?? {}),
              }))
            }
            onCredentialsChange={onCredentialChange}
            note="Provider scope arguments are validated against the selected provider and saved with this target."
          />
        </>
      ) : null}
    </div>
  );
}
