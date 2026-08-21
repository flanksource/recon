package schema

import (
	"embed"
	"encoding/json"
	"fmt"

	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/scan/prowler/arguments"
)

//go:embed manifest.generated.json arguments.generated.json providers/*.generated.json
var embeddedArtifacts embed.FS

func Embedded() (*Registry, error) {
	return LoadFS(embeddedArtifacts)
}

func ArgumentCatalogue() (*arguments.Catalogue, error) {
	manifestData, err := embeddedArtifacts.ReadFile("manifest.generated.json")
	if err != nil {
		return nil, fmt.Errorf("read embedded Prowler schema manifest: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("decode embedded Prowler schema manifest: %w", err)
	}
	return loadArgumentCatalogue(embeddedArtifacts, manifest)
}

func ProviderSchemas() ([]ProviderSchema, error) {
	registry, err := Embedded()
	if err != nil {
		return nil, err
	}
	return registry.ProviderSchemas(), nil
}

func OpenAPIComponents() (map[string]engines.JSONSchema, error) {
	registry, err := Embedded()
	if err != nil {
		return nil, err
	}
	generated := registry.OpenAPIComponents()
	components := make(map[string]engines.JSONSchema, len(generated))
	for name, document := range generated {
		components[name] = document.OpenAPISchema()
	}
	return components, nil
}

func OptionCatalog() (engines.OptionCatalog, error) {
	registry, err := Embedded()
	if err != nil {
		return engines.OptionCatalog{}, err
	}
	return registry.OptionCatalog(), nil
}
