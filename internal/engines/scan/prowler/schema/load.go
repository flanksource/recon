package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/flanksource/recon/internal/engines/scan/prowler/arguments"
)

func LoadFS(fsys fs.FS) (*Registry, error) {
	manifestData, err := fs.ReadFile(fsys, "manifest.generated.json")
	if err != nil {
		return nil, fmt.Errorf("read prowler schema manifest: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("decode prowler schema manifest: %w", err)
	}
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	if manifest.SourceDigest != "" {
		if _, err := loadArgumentCatalogue(fsys, manifest); err != nil {
			return nil, err
		}
	}

	entries, err := fs.ReadDir(fsys, "providers")
	if err != nil {
		return nil, fmt.Errorf("read prowler provider schemas: %w", err)
	}
	files := make(map[string]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".generated.json") {
			return nil, fmt.Errorf("unexpected prowler schema artifact providers/%s", entry.Name())
		}
		provider := strings.TrimSuffix(entry.Name(), ".generated.json")
		files[provider] = path.Join("providers", entry.Name())
	}
	if len(files) != manifest.ProviderCount {
		return nil, fmt.Errorf("prowler schema provider count drift: manifest=%d artifacts=%d", manifest.ProviderCount, len(files))
	}

	registry := &Registry{Manifest: manifest, byID: make(map[string]ProviderSchema, len(files))}
	componentNames := map[string]string{}
	for _, provider := range manifest.Providers {
		filename, ok := files[provider]
		if !ok {
			return nil, fmt.Errorf("missing prowler schema artifact for %s", provider)
		}
		data, err := fs.ReadFile(fsys, filename)
		if err != nil {
			return nil, fmt.Errorf("read prowler schema artifact for %s: %w", provider, err)
		}
		if err := validateDigest(provider, data, manifest.Digests[provider]); err != nil {
			return nil, err
		}
		var document ProviderSchema
		if err := json.Unmarshal(data, &document); err != nil {
			return nil, fmt.Errorf("decode prowler schema artifact for %s: %w", provider, err)
		}
		if err := validateProvider(provider, document); err != nil {
			return nil, err
		}
		document.complete()
		if previous, exists := componentNames[document.ComponentName]; exists {
			return nil, fmt.Errorf("prowler providers %s and %s share OpenAPI component name %s", previous, provider, document.ComponentName)
		}
		componentNames[document.ComponentName] = provider
		registry.ordered = append(registry.ordered, document)
		registry.byID[provider] = document
		delete(files, provider)
	}
	if len(files) > 0 {
		extra := make([]string, 0, len(files))
		for provider := range files {
			extra = append(extra, provider)
		}
		sort.Strings(extra)
		return nil, fmt.Errorf("unexpected prowler schema providers: %s", strings.Join(extra, ", "))
	}
	return registry, nil
}

func loadArgumentCatalogue(fsys fs.FS, manifest Manifest) (*arguments.Catalogue, error) {
	data, err := fs.ReadFile(fsys, "arguments.generated.json")
	if err != nil {
		return nil, fmt.Errorf("read generated prowler arguments: %w", err)
	}
	catalogue, err := arguments.LoadJSON(data)
	if err != nil {
		return nil, fmt.Errorf("load generated prowler arguments: %w", err)
	}
	normalized, err := json.Marshal(catalogue)
	if err != nil {
		return nil, fmt.Errorf("normalize generated prowler arguments: %w", err)
	}
	digest := sha256.New()
	digest.Write(normalized)
	digest.Write([]byte("\n" + manifest.CatalogDigest))
	actual := hex.EncodeToString(digest.Sum(nil))
	if actual != manifest.SourceDigest {
		return nil, fmt.Errorf("prowler argument source digest drift: expected %s, got %s", manifest.SourceDigest, actual)
	}
	if len(catalogue.Common) != manifest.CommonArgumentCount {
		return nil, fmt.Errorf("prowler common argument count drift: manifest=%d artifact=%d", manifest.CommonArgumentCount, len(catalogue.Common))
	}
	for _, provider := range catalogue.Providers {
		if len(provider.Arguments) != manifest.ProviderArgumentCounts[provider.Name] {
			return nil, fmt.Errorf("prowler %s argument count drift: manifest=%d artifact=%d", provider.Name, manifest.ProviderArgumentCounts[provider.Name], len(provider.Arguments))
		}
	}
	return catalogue, nil
}

func validateManifest(manifest Manifest) error {
	switch {
	case manifest.Version != ProwlerVersion:
		return fmt.Errorf("prowler schema version drift: expected %s, got %s", ProwlerVersion, manifest.Version)
	case manifest.SourceCommit != PinnedCommit:
		return fmt.Errorf("prowler schema commit drift: expected %s, got %s", PinnedCommit, manifest.SourceCommit)
	case manifest.ProviderCount != len(manifest.Providers):
		return fmt.Errorf("prowler schema provider count drift: manifest=%d ids=%d", manifest.ProviderCount, len(manifest.Providers))
	case len(manifest.Digests) != manifest.ProviderCount:
		return fmt.Errorf("prowler schema digest count drift: manifest=%d digests=%d", manifest.ProviderCount, len(manifest.Digests))
	case manifest.SourceDigest != "" && manifest.CatalogDigest == "":
		return fmt.Errorf("prowler schema catalog digest is required")
	case manifest.SourceDigest != "" && len(manifest.ProviderArgumentCounts) != manifest.ProviderCount:
		return fmt.Errorf("prowler schema argument count drift: providers=%d argument counts=%d", manifest.ProviderCount, len(manifest.ProviderArgumentCounts))
	}
	for index, provider := range manifest.Providers {
		if provider == "" {
			return fmt.Errorf("prowler schema provider %d is empty", index)
		}
		if index > 0 && manifest.Providers[index-1] >= provider {
			return fmt.Errorf("prowler schema providers must be sorted and unique")
		}
		if manifest.Digests[provider] == "" {
			return fmt.Errorf("missing Prowler schema digest for %s", provider)
		}
	}
	return nil
}

func validateDigest(provider string, data []byte, expected string) error {
	digest := sha256.Sum256(data)
	actual := hex.EncodeToString(digest[:])
	if actual != expected {
		return fmt.Errorf("prowler schema digest drift for %s: expected %s, got %s", provider, expected, actual)
	}
	return nil
}

func validateProvider(provider string, document ProviderSchema) error {
	switch {
	case document.Provider != provider:
		return fmt.Errorf("prowler schema artifact %s identifies provider %q", provider, document.Provider)
	case document.Version != ProwlerVersion:
		return fmt.Errorf("prowler schema artifact %s has version %q", provider, document.Version)
	case document.SourceCommit != PinnedCommit:
		return fmt.Errorf("prowler schema artifact %s has commit %q", provider, document.SourceCommit)
	}
	for name, projected := range map[string]JSONSchema{
		"cli": document.CLI, "profile": document.Profile, "context": document.Context, "credential": document.Credential,
	} {
		if projected.Type != "object" || projected.AdditionalProperties == nil || *projected.AdditionalProperties {
			return fmt.Errorf("prowler %s %s schema must be a closed object", provider, name)
		}
		if err := validateLayout(provider, name, projected); err != nil {
			return err
		}
	}
	if err := validatePersistable(provider, "profile", document.Profile); err != nil {
		return err
	}
	if err := validatePersistable(provider, "context", document.Context); err != nil {
		return err
	}
	return validateCredentialPolicy(provider, document.Credential)
}

func validateCredentialPolicy(provider string, credential JSONSchema) error {
	if provider != "cloudflare" {
		if len(credential.Properties) > 0 {
			return fmt.Errorf("prowler %s credential schema must be empty", provider)
		}
		return nil
	}
	if len(credential.Properties) != 1 {
		return fmt.Errorf("prowler cloudflare credential schema must expose only envVars")
	}
	return validateCloudflareCredential(credential.Properties["envVars"])
}

func validateCloudflareCredential(envVars JSONSchema) error {
	if envVars.Type != "array" || envVars.Items == nil || envVars.MinItems == nil || *envVars.MinItems != 1 || envVars.MaxItems == nil || *envVars.MaxItems != 1 {
		return fmt.Errorf("prowler cloudflare credential schema must expose exactly one envVar")
	}
	item := envVars.Items
	if item.Type != "object" || item.AdditionalProperties == nil || *item.AdditionalProperties || len(item.Properties) != 4 {
		return fmt.Errorf("prowler cloudflare envVar must be a closed EnvVar object")
	}
	if !slices.Equal(item.Required, []string{"name"}) || !credentialAlternativesMatch(item.OneOf) {
		return fmt.Errorf("prowler cloudflare envVar must require name and exactly one credential value")
	}
	name, hasName := item.Properties["name"]
	value, hasValue := item.Properties["value"]
	valueFrom, hasValueFrom := item.Properties["valueFrom"]
	configured, hasConfigured := item.Properties["configured"]
	if !hasName || name.Type != "string" || name.Const != "CLOUDFLARE_API_TOKEN" || !name.ReadOnly ||
		!hasValue || value.Type != "string" || value.Format != "password" || !value.WriteOnly || !value.Sensitive ||
		!hasValueFrom || !hasConfigured || configured.Type != "boolean" || configured.Const != true || !configured.ReadOnly {
		return fmt.Errorf("prowler cloudflare envVar credential policy drifted")
	}
	return validateCredentialValueFrom(valueFrom)
}

func validateCredentialValueFrom(valueFrom JSONSchema) error {
	if valueFrom.Type != "object" || valueFrom.AdditionalProperties == nil || *valueFrom.AdditionalProperties ||
		valueFrom.MinProperties == nil || *valueFrom.MinProperties != 1 || valueFrom.MaxProperties == nil || *valueFrom.MaxProperties != 1 ||
		!valueFrom.SecretReference || len(valueFrom.Properties) != 4 {
		return fmt.Errorf("prowler cloudflare valueFrom must expose four approved reference types")
	}
	for _, key := range []string{"secretKeyRef", "configMapKeyRef", "helmRef"} {
		selector, ok := valueFrom.Properties[key]
		if !ok || selector.Type != "object" || selector.AdditionalProperties == nil || *selector.AdditionalProperties ||
			len(selector.Properties) != 2 || !slices.Equal(selector.Required, []string{"name", "key"}) {
			return fmt.Errorf("prowler cloudflare valueFrom is missing %s", key)
		}
		if selector.Properties["name"].Type != "string" || selector.Properties["key"].Type != "string" {
			return fmt.Errorf("prowler cloudflare valueFrom %s must contain string name and key", key)
		}
	}
	onePassword, ok := valueFrom.Properties["onePassword"]
	if !ok || onePassword.Type != "string" || onePassword.Pattern != `^op://[^/]+/[^/]+/.+` {
		return fmt.Errorf("prowler cloudflare valueFrom must expose an op reference")
	}
	return nil
}

func credentialAlternativesMatch(options []JSONSchema) bool {
	if len(options) != 3 {
		return false
	}
	for index, key := range []string{"value", "valueFrom", "configured"} {
		if !slices.Equal(options[index].Required, []string{key}) {
			return false
		}
	}
	return true
}

func validatePersistable(provider, projection string, document JSONSchema) error {
	for key, property := range document.Properties {
		if property.Sensitive || property.WriteOnly || property.Owner == "credential" {
			return fmt.Errorf("prowler %s has credential property %s in %s schema", provider, key, projection)
		}
		if key != "provider" && property.Owner != "" && property.Owner != projection {
			return fmt.Errorf("prowler %s has %s-owned property %s in %s schema", provider, property.Owner, key, projection)
		}
	}
	return nil
}

func validateLayout(provider, projection string, document JSONSchema) error {
	if len(document.Order) == 0 {
		return nil
	}
	if len(document.Order) != len(document.Properties) {
		return fmt.Errorf("prowler %s %s schema order has %d keys for %d properties", provider, projection, len(document.Order), len(document.Properties))
	}
	seen := map[string]bool{}
	for _, key := range document.Order {
		if _, ok := document.Properties[key]; !ok {
			return fmt.Errorf("prowler %s %s schema order references unknown property %s", provider, projection, key)
		}
		if seen[key] {
			return fmt.Errorf("prowler %s %s schema order repeats property %s", provider, projection, key)
		}
		seen[key] = true
	}
	sections := map[string]bool{}
	for _, section := range document.Sections {
		if section.ID == "" || sections[section.ID] {
			return fmt.Errorf("prowler %s %s schema has empty or duplicate section %q", provider, projection, section.ID)
		}
		sections[section.ID] = true
	}
	for key, property := range document.Properties {
		if property.Section == "" || !sections[property.Section] {
			return fmt.Errorf("prowler %s %s property %s references unknown section %q", provider, projection, key, property.Section)
		}
	}
	return nil
}
