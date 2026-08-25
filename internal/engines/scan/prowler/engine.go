package prowler

import (
	"fmt"

	"github.com/flanksource/deps/pkg/types"

	"github.com/flanksource/recon/internal/engines"
	enginescan "github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/engines/scan/prowler/arguments"
	"github.com/flanksource/recon/internal/engines/scan/prowler/auth"
	"github.com/flanksource/recon/internal/engines/scan/prowler/catalog"
	"github.com/flanksource/recon/internal/engines/scan/prowler/schema"
)

const defaultProfileName = "gcp-cis-5-0-gcp"

// Engine executes Prowler once for each provider context selected by a run.
type Engine struct {
	arguments *arguments.Catalogue
	catalogue func() (*catalog.Catalog, error)
	spec      engines.Spec
}

var _ enginescan.Engine = Engine{}

func init() {
	engine, err := newEngine()
	if err != nil {
		panic(fmt.Sprintf("load Prowler engine: %v", err))
	}
	enginescan.Register(engine)
}

func newEngine() (Engine, error) {
	if catalog.ProwlerVersion != schema.ProwlerVersion || catalog.PinnedCommit != schema.PinnedCommit {
		return Engine{}, fmt.Errorf("prowler generated schema and catalogue source do not match")
	}
	registry, err := schema.Embedded()
	if err != nil {
		return Engine{}, err
	}
	argumentCatalogue, err := schema.ArgumentCatalogue()
	if err != nil {
		return Engine{}, err
	}
	options := registry.OptionCatalog()
	defaults, profiles, err := builtInProfiles(registry.BuiltInProfiles())
	if err != nil {
		return Engine{}, err
	}
	engine := Engine{
		arguments: argumentCatalogue,
		catalogue: catalog.Embedded,
	}
	engine.spec = engines.Spec{
		Name:                EngineName,
		Subject:             engines.SubjectProviderContexts,
		Binary:              EngineName,
		Title:               "Prowler",
		Description:         "Provider-native cloud security and compliance checks.",
		DocsURL:             "https://docs.prowler.com/projects/prowler-open-source/en/latest/",
		Provisioning:        engines.ProvisioningPathOnly,
		InstallInstructions: `pipx install "git+https://github.com/prowler-cloud/prowler.git@` + schema.PinnedCommit + `"`,
		Install: types.Package{
			VersionCommand: "--version",
			VersionRegex:   `(?i)prowler(?:\s+version)?\s+v?(\d+\.\d+\.\d+)`,
		},
		Version:         schema.ProwlerVersion,
		Options:         options,
		Defaults:        defaults,
		Profiles:        profiles,
		ValidateOptions: engine.validateOptions,
		ValidateProviderCredentials: func(config, context, credentials map[string]any) ([]engines.CredentialConnection, error) {
			provider, ok := config["provider"].(string)
			if !ok || provider == "" {
				return nil, fmt.Errorf("prowler provider is required")
			}
			method, err := auth.Match(provider, context, credentials)
			if err != nil {
				return nil, err
			}
			reference, err := auth.ConnectionReference(credentials, method)
			if err != nil {
				return nil, err
			}
			if reference == "" {
				return nil, nil
			}
			return []engines.CredentialConnection{{Reference: reference, Type: method.Connection.Type}}, nil
		},
	}
	if err := engine.spec.Validate(); err != nil {
		return Engine{}, err
	}
	return engine, nil
}

func builtInProfiles(generated []engines.DefaultProfile) (engines.DefaultProfile, []engines.DefaultProfile, error) {
	profiles := make([]engines.DefaultProfile, 0, len(generated)-1)
	var defaults engines.DefaultProfile
	for _, profile := range generated {
		adapted := engines.DefaultProfile{Name: profile.Name, Comment: profile.Comment, Config: profile.Config}
		if profile.Name == defaultProfileName {
			defaults = adapted
			continue
		}
		profiles = append(profiles, adapted)
	}
	if defaults.Name == "" {
		return engines.DefaultProfile{}, nil, fmt.Errorf("prowler default profile %q is absent from generated catalogue", defaultProfileName)
	}
	return defaults, profiles, nil
}

func (e Engine) validateOptions(config map[string]any) error {
	catalogue, err := e.argumentCatalogue()
	if err != nil {
		return err
	}
	provider, profile, err := profileArguments(config, catalogue)
	if err != nil {
		return err
	}
	_, err = catalogue.BuildArgv(provider, arguments.Inputs{Profile: profile, Runner: runnerArguments})
	return err
}

func (e Engine) Spec() engines.Spec { return e.spec }

func (Engine) Risk(map[string]any) engines.Risk { return engines.Safe() }

func (e Engine) argumentCatalogue() (*arguments.Catalogue, error) {
	if e.arguments == nil {
		return nil, fmt.Errorf("prowler argument catalogue is not loaded")
	}
	return e.arguments, nil
}

func (e Engine) metadataCatalogue() (*catalog.Catalog, error) {
	if e.catalogue == nil {
		return nil, fmt.Errorf("prowler metadata catalogue is not loaded")
	}
	return e.catalogue()
}
