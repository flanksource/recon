export type CredentialKeySelector = {
  name: string;
  key: string;
};

export type CredentialValueFrom = {
  secretKeyRef?: CredentialKeySelector;
  configMapKeyRef?: CredentialKeySelector;
  helmRef?: CredentialKeySelector;
  onePassword?: string;
};

export type CredentialEnvVar = {
  name: string;
  value?: string;
  valueFrom?: CredentialValueFrom;
  // GET replaces an inline value with this marker. It is never sent for a new
  // value; leaving credentials out of an update preserves the hidden value.
  configured?: true;
};

export type TargetCredentials = {
  envVars?: CredentialEnvVar[];
  connections?: Record<string, unknown>;
};

export type CredentialMutation = TargetCredentials | null | undefined;
