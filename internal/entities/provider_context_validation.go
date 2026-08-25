package entities

import (
	"context"
	"fmt"
	"reflect"
	"sort"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
	enginescan "github.com/flanksource/recon/internal/engines/scan"
)

type providerContextProfileReader interface {
	GetProfile(context.Context, string) (api.Profile, error)
	ConnectionType(context.Context, string) (string, error)
}

func validateProviderContext(ctx context.Context, profiles providerContextProfileReader, target api.TargetDocument) error {
	if target.Kind != api.KindProviderContext {
		return nil
	}

	// The provider decides which engine's schema this target is validated
	// against. Assuming one engine owned every provider was correct while only
	// prowler had any, and would silently reject every target belonging to the
	// second engine that grew some.
	engine, err := enginescan.ForProvider(target.Provider)
	if err != nil {
		return err
	}
	if err := validateProviderContextSpec(engine.Spec(), target); err != nil {
		return err
	}
	connections, err := providerCredentialConnections(engine.Spec(), target)
	if err != nil {
		return err
	}
	for _, required := range connections {
		actual, err := profiles.ConnectionType(ctx, required.Reference)
		if err != nil {
			return fmt.Errorf("provider connection %s: %w", required.Reference, err)
		}
		if actual != required.Type {
			return fmt.Errorf("provider connection %s has type %s, expected %s", required.Reference, actual, required.Type)
		}
	}
	for _, profileID := range target.Profiles {
		if err := validateProviderContextProfile(ctx, profiles, profileID, target); err != nil {
			return err
		}
	}
	return nil
}

func validateProviderContextSpec(spec engines.Spec, target api.TargetDocument) error {
	config := map[string]any{"provider": target.Provider}
	variant, err := spec.Options.Resolve(config)
	if err != nil {
		return fmt.Errorf("%s provider schema: %w", spec.Name, err)
	}
	if variant.ContextSchema == nil {
		return fmt.Errorf("%s provider %s has no context schema", spec.Name, target.Provider)
	}
	// A provider that declares no credential schema is not incomplete: it is
	// saying it takes none, and ValidateCredentials below refuses any that are
	// attached anyway. Requiring one of every provider would refuse an engine
	// whose tools read their credentials from the environment.
	if err := spec.ValidateContext(config, target.Arguments); err != nil {
		return fmt.Errorf("%s provider %s context schema: %w", spec.Name, target.Provider, err)
	}
	selectors, err := credentialSelectors(target.Arguments, *variant.ContextSchema)
	if err != nil {
		return err
	}
	credentials := map[string]any{}
	if target.Credentials != nil {
		if err := target.Credentials.ValidateWrite(); err != nil {
			return err
		}
		credentials, err = target.Credentials.RawMap()
		if err != nil {
			return err
		}
	}
	if err := validateCredentialMode(target.CredentialMode, target.Credentials, selectors); err != nil {
		return err
	}
	if target.CredentialMode == api.CredentialConfigured {
		if err := spec.Options.ValidateCredentials(config, credentials); err != nil {
			return fmt.Errorf("%s provider %s credential schema: %w", spec.Name, target.Provider, err)
		}
	}
	if spec.ValidateProviderCredentials != nil && target.CredentialMode == api.CredentialConfigured {
		if _, err := spec.ValidateProviderCredentials(config, target.Arguments, credentials); err != nil {
			return fmt.Errorf("%s provider %s credential policy: %w", spec.Name, target.Provider, err)
		}
	}
	return nil
}

func providerCredentialConnections(spec engines.Spec, target api.TargetDocument) ([]engines.CredentialConnection, error) {
	if spec.ValidateProviderCredentials == nil || target.CredentialMode != api.CredentialConfigured {
		return nil, nil
	}
	credentials := map[string]any{}
	var err error
	if target.Credentials != nil {
		credentials, err = target.Credentials.RawMap()
		if err != nil {
			return nil, err
		}
	}
	connections, err := spec.ValidateProviderCredentials(
		map[string]any{"provider": target.Provider}, target.Arguments, credentials)
	if err != nil {
		return nil, fmt.Errorf("%s provider %s credential policy: %w", spec.Name, target.Provider, err)
	}
	return connections, nil
}

func validateProviderContextProfile(
	ctx context.Context,
	profiles providerContextProfileReader,
	profileID string,
	target api.TargetDocument,
) error {
	profile, err := profiles.GetProfile(ctx, profileID)
	if err != nil {
		return err
	}
	engine, err := enginescan.Get(profile.Engine)
	if err != nil {
		return fmt.Errorf("profile %s: %w", profileID, err)
	}
	variant, err := engine.Spec().Options.Resolve(profile.Config)
	if err != nil {
		return fmt.Errorf("profile %s: %w", profileID, err)
	}
	if variant.ContextSchema == nil {
		return fmt.Errorf("profile %s has no context schema", profileID)
	}
	if engine.Spec().Options.Discriminator == "provider" && variant.ID != target.Provider {
		return fmt.Errorf("profile %s uses provider %s, not %s", profileID, variant.ID, target.Provider)
	}
	if err := engine.Spec().ValidateContext(profile.Config, target.Arguments); err != nil {
		return fmt.Errorf("profile %s context schema: %w", profileID, err)
	}
	return nil
}

func credentialSelectors(arguments map[string]any, schema engines.JSONSchema) ([]string, error) {
	// Through schemaObject rather than one type assertion: a generated schema
	// decodes its properties as map[string]any and a hand-written one builds
	// them as JSONSchema, and asserting only the first refused every target of
	// the second before reading a single property.
	properties, ok := schemaObject(schema["properties"])
	if !ok && len(arguments) > 0 {
		return nil, fmt.Errorf("provider context schema properties must be an object")
	}
	selectors := []string{}
	for key, value := range arguments {
		property, ok := schemaObject(properties[key])
		if !ok {
			return nil, fmt.Errorf("provider context schema property %q must be an object", key)
		}
		if property["writeOnly"] == true || property["x-sensitive"] == true {
			return nil, fmt.Errorf("provider context argument %q is sensitive and cannot be persisted", key)
		}
		if property["x-credential-selector"] == true && contextValueIsActive(value) {
			selectors = append(selectors, key)
		}
	}
	sort.Strings(selectors)
	return selectors, nil
}

func validateCredentialMode(
	mode api.CredentialMode,
	credentials *api.ProviderCredentials,
	selectors []string,
) error {
	configured := credentials != nil && !credentials.Empty()
	if mode == api.CredentialAmbient {
		if configured {
			return fmt.Errorf("credentials are not allowed in ambient credential mode")
		}
		if len(selectors) > 0 {
			return fmt.Errorf("credential selector %q is not allowed in ambient credential mode", selectors[0])
		}
		return nil
	}
	if mode == api.CredentialConfigured && !configured && len(selectors) == 0 {
		return fmt.Errorf("configured credential mode requires credentials or an explicit credential selector")
	}
	return nil
}

func schemaObject(value any) (map[string]any, bool) {
	switch value := value.(type) {
	case engines.JSONSchema:
		return map[string]any(value), true
	case map[string]any:
		return value, true
	default:
		return nil, false
	}
}

func contextValueIsActive(value any) bool {
	if value == nil {
		return false
	}
	if boolean, ok := value.(bool); ok {
		return boolean
	}
	reflected := reflect.ValueOf(value)
	if reflected.Kind() == reflect.Slice || reflected.Kind() == reflect.Array {
		return reflected.Len() > 0
	}
	return true
}
