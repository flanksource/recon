package auth

import "slices"

type EnvVar struct {
	Name  string `json:"name"`
	Title string `json:"title"`
}

type Setting struct {
	Key         string `json:"key"`
	Environment string `json:"environment"`
	Title       string `json:"title"`
	Required    bool   `json:"required,omitempty"`
}

type Connection struct {
	Key  string `json:"key"`
	Type string `json:"type"`
}

type Method struct {
	ID               string         `json:"id"`
	Title            string         `json:"title"`
	EnvVars          []EnvVar       `json:"envVars,omitempty"`
	Connection       *Connection    `json:"connection,omitempty"`
	RequiredSettings []string       `json:"requiredSettings,omitempty"`
	Arguments        map[string]any `json:"arguments,omitempty"`
}

type Policy struct {
	Methods   []Method  `json:"methods,omitempty"`
	Settings  []Setting `json:"settings,omitempty"`
	Selectors []string  `json:"selectors,omitempty"`
	Ambient   []string  `json:"ambient,omitempty"`
}

var policies = map[string]Policy{
	"aws": native("AWS connection", "aws", "aws", nil,
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE",
		"AWS_DEFAULT_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE"),
	"azure": withSelectors(native("Azure service principal", "azure", "azure", map[string]any{"sp-env-auth": true},
		"AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID"),
		"az-cli-auth", "sp-env-auth", "managed-identity-auth"),
	"cloudflare": {
		Methods: []Method{
			environment("api-token", "API token", EnvVar{Name: "CLOUDFLARE_API_TOKEN", Title: "API token"}),
			withSettings(environment("global-api-key", "Global API key", EnvVar{Name: "CLOUDFLARE_API_KEY", Title: "API key"}), "api-email"),
		},
		Settings: []Setting{{Key: "api-email", Environment: "CLOUDFLARE_API_EMAIL", Title: "API email"}},
		Ambient:  []string{"CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_KEY", "CLOUDFLARE_API_EMAIL"},
	},
	"gcp": withSelectors(native("Google Cloud connection", "gcp", "google_cloud", nil, "GOOGLE_APPLICATION_CREDENTIALS"),
		"credentials-file", "impersonate-service-account"),
	"github": {
		Methods: []Method{
			environment("personal-access-token", "Personal access token", EnvVar{Name: "GITHUB_PERSONAL_ACCESS_TOKEN", Title: "Personal access token"}),
			environment("oauth-app-token", "OAuth app token", EnvVar{Name: "GITHUB_OAUTH_APP_TOKEN", Title: "OAuth app token"}),
			withSettings(environment("github-app", "GitHub App", EnvVar{Name: "GITHUB_APP_KEY", Title: "App private key"}), "github-app-id"),
		},
		Settings: []Setting{{Key: "github-app-id", Environment: "GITHUB_APP_ID", Title: "GitHub App ID"}},
		Ambient:  []string{"GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_OAUTH_APP_TOKEN", "GITHUB_APP_ID", "GITHUB_APP_KEY"},
	},
	"googleworkspace": {
		Methods: []Method{withSettings(environment("service-account", "Service account", EnvVar{
			Name: "GOOGLEWORKSPACE_CREDENTIALS_CONTENT", Title: "Service account JSON",
		}), "delegated-user")},
		Settings: []Setting{{Key: "delegated-user", Environment: "GOOGLEWORKSPACE_DELEGATED_USER", Title: "Delegated user", Required: true}},
		Ambient:  []string{"GOOGLEWORKSPACE_CREDENTIALS_CONTENT", "GOOGLEWORKSPACE_DELEGATED_USER"},
	},
	"image": {
		Methods: []Method{
			environment("registry-token", "Registry token", EnvVar{Name: "REGISTRY_TOKEN", Title: "Registry token"}),
			withSettings(environment("registry-password", "Registry username and password", EnvVar{Name: "REGISTRY_PASSWORD", Title: "Registry password"}), "registry-username"),
		},
		Settings: []Setting{{Key: "registry-username", Environment: "REGISTRY_USERNAME", Title: "Registry username"}},
		Ambient:  []string{"REGISTRY_TOKEN", "REGISTRY_USERNAME", "REGISTRY_PASSWORD"},
	},
	"llm": {
		Methods: []Method{environment("openai", "OpenAI", EnvVar{Name: "OPENAI_API_KEY", Title: "OpenAI API key"})},
		Ambient: []string{"OPENAI_API_KEY"},
	},
	"m365": {
		Methods: []Method{
			connectionMethod("azure-service-principal", "Azure service principal", "azure", "azure", map[string]any{"sp-env-auth": true}),
			withSettings(Method{
				ID: "certificate", Title: "Certificate",
				EnvVars:   []EnvVar{{Name: "AZURE_CLIENT_ID", Title: "Client ID"}, {Name: "M365_CERTIFICATE_CONTENT", Title: "Certificate content"}},
				Arguments: map[string]any{"certificate-auth": true},
			}, "tenant-id"),
		},
		Settings:  []Setting{{Key: "tenant-id", Environment: "AZURE_TENANT_ID", Title: "Tenant ID"}},
		Selectors: []string{"az-cli-auth", "sp-env-auth", "certificate-auth", "certificate-path"},
		Ambient:   []string{"AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID", "M365_CERTIFICATE_CONTENT"},
	},
	"mongodbatlas": {
		Methods:  []Method{withSettings(environment("api-key", "API key", EnvVar{Name: "ATLAS_PRIVATE_KEY", Title: "Private key"}), "atlas-public-key")},
		Settings: []Setting{{Key: "atlas-public-key", Environment: "ATLAS_PUBLIC_KEY", Title: "Public key"}},
		Ambient:  []string{"ATLAS_PUBLIC_KEY", "ATLAS_PRIVATE_KEY"},
	},
	"vercel": {
		Methods:  []Method{environment("token", "Access token", EnvVar{Name: "VERCEL_TOKEN", Title: "Access token"})},
		Settings: []Setting{{Key: "team", Environment: "VERCEL_TEAM", Title: "Team ID or slug"}},
		Ambient:  []string{"VERCEL_TOKEN", "VERCEL_TEAM"},
	},
}

func Providers() []string {
	providers := make([]string, 0, len(policies))
	for provider := range policies {
		providers = append(providers, provider)
	}
	slices.Sort(providers)
	return providers
}

func ForProvider(provider string) (Policy, bool) {
	policy, ok := policies[provider]
	return policy, ok
}

func native(title, key, connectionType string, arguments map[string]any, ambient ...string) Policy {
	return Policy{
		Methods: []Method{connectionMethod(key, title, key, connectionType, arguments)},
		Ambient: ambient,
	}
}

func connectionMethod(id, title, key, connectionType string, arguments map[string]any) Method {
	if arguments == nil {
		arguments = map[string]any{}
	}
	return Method{ID: id, Title: title, Connection: &Connection{Key: key, Type: connectionType}, Arguments: arguments}
}

func environment(id, title string, variables ...EnvVar) Method {
	return Method{ID: id, Title: title, EnvVars: variables, Arguments: map[string]any{}}
}

func withSettings(method Method, settings ...string) Method {
	method.RequiredSettings = settings
	return method
}

func withSelectors(policy Policy, selectors ...string) Policy {
	policy.Selectors = selectors
	return policy
}
