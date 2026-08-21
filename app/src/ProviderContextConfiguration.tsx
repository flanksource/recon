import { CredentialConfigForm } from "./CredentialConfigForm";
import { EngineConfigForm } from "./EngineConfigForm";
import type {
  CredentialMode,
  CredentialMutation,
  Engine,
  TargetCredentials,
} from "./types";

type Props = {
  engine: Engine;
  provider: string;
  identity: string;
  credentialMode: CredentialMode;
  arguments: Record<string, unknown>;
  baselineArguments?: Record<string, unknown>;
  credentials?: TargetCredentials;
  onArgumentsChange: (next: Record<string, unknown>) => void;
  onCredentialsChange: (next: CredentialMutation) => void;
  onResetArguments?: () => void;
  note: string;
};

function credentialSchema(engine: Engine, provider: string) {
  const variant = engine.options.variants.find((candidate) => candidate.id === provider);
  if (!variant) {
    throw new Error(`${engine.title} does not define provider variant "${provider}"`);
  }
  return variant.credentialSchema;
}

export function ProviderContextConfiguration({
  engine,
  provider,
  identity,
  credentialMode,
  arguments: context,
  baselineArguments,
  credentials,
  onArgumentsChange,
  onCredentialsChange,
  onResetArguments,
  note,
}: Props) {
  const credentialsSchema = credentialSchema(engine, provider);
  return (
    <>
      <EngineConfigForm
        engine={engine}
        identity={identity}
        schemaKind="context"
        variantId={provider}
        credentialMode={credentialMode}
        value={context}
        baseline={baselineArguments}
        onChange={onArgumentsChange}
        onReset={onResetArguments}
        note={note}
      />
      {credentialMode === "configured" && credentialsSchema ? (
        <CredentialConfigForm
          schema={credentialsSchema}
          value={credentials}
          onChange={onCredentialsChange}
        />
      ) : null}
    </>
  );
}
