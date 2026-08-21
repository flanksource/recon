import {
  createSecretFormExtensions,
  type KeyPreview,
  type OnePasswordField,
  type OnePasswordItem,
  type OnePasswordVault,
  type SecretFormLoaders,
  type SecretKind,
  type SecretResource,
  type SecretValueSource,
  type WorkloadKind,
  type WorkloadResource,
} from "@flanksource/clicky-ui/components";

export const CREDENTIAL_SOURCES = [
  "value",
  "secret",
  "configmap",
  "helm",
  "onepassword",
] as const satisfies readonly SecretValueSource[];

async function fetchJSON<T>(url: string): Promise<T> {
  const response = await fetch(url);
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`${url}: ${response.status} ${text}`);
  }
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error(`${url}: response is not valid JSON`);
  }
}

function emptyWorkloads(): Record<WorkloadKind, WorkloadResource[]> {
  return {
    service: [],
    ingress: [],
    pod: [],
    deployment: [],
    statefulset: [],
    daemonset: [],
  };
}

export const secretFormLoaders: SecretFormLoaders = {
  loadResources: (kind: SecretKind) =>
    fetchJSON<SecretResource[]>(`/api/v1/secrets?kind=${kind}`),
  loadKeyPreview: (kind: SecretKind, name: string) =>
    fetchJSON<KeyPreview[]>(
      `/api/v1/secrets/preview?kind=${kind}&name=${encodeURIComponent(name)}`,
    ),
  // The credential policy intentionally excludes service accounts and URL /
  // workload selectors, but the shared extension's complete loader contract
  // still requires these functions.
  loadServiceAccounts: async () => [],
  loadOnePasswordVaults: () =>
    fetchJSON<OnePasswordVault[]>("/api/v1/secrets/onepassword/vaults"),
  loadOnePasswordItems: (vaultID: string) =>
    fetchJSON<OnePasswordItem[]>(
      `/api/v1/secrets/onepassword/items?vault=${encodeURIComponent(vaultID)}`,
    ),
  loadOnePasswordFields: (vaultID: string, itemID: string) =>
    fetchJSON<OnePasswordField[]>(
      `/api/v1/secrets/onepassword/fields?vault=${encodeURIComponent(vaultID)}&item=${encodeURIComponent(itemID)}`,
    ),
  loadWorkloads: async () => emptyWorkloads(),
};

export const credentialFormExtensions = createSecretFormExtensions({
  loaders: secretFormLoaders,
  secretSources: [...CREDENTIAL_SOURCES],
});
