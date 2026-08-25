package schema

import (
	"strings"

	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/scan/prowler/auth"
)

const (
	PinnedCommit   = "ba564af4f46fd7c4908d34798687eda36b88398c"
	ProwlerVersion = "5.40.0"
)

// JSONSchema is the Draft 2020-12/OpenAPI 3.1 schema subset emitted for Prowler
// arguments. Extensions retain argparse semantics for documentation and
// deterministic command-line serialization.
type JSONSchema struct {
	Schema               string                `json:"$schema,omitempty"`
	Type                 string                `json:"type,omitempty"`
	Title                string                `json:"title,omitempty"`
	Description          string                `json:"description,omitempty"`
	Properties           map[string]JSONSchema `json:"properties,omitempty"`
	Required             []string              `json:"required,omitempty"`
	Items                *JSONSchema           `json:"items,omitempty"`
	OneOf                []JSONSchema          `json:"oneOf,omitempty"`
	AllOf                []JSONSchema          `json:"allOf,omitempty"`
	Contains             *JSONSchema           `json:"contains,omitempty"`
	Enum                 []any                 `json:"enum,omitempty"`
	Default              any                   `json:"default,omitempty"`
	Const                any                   `json:"const,omitempty"`
	Format               string                `json:"format,omitempty"`
	WriteOnly            bool                  `json:"writeOnly,omitempty"`
	ReadOnly             bool                  `json:"readOnly,omitempty"`
	AdditionalProperties *bool                 `json:"additionalProperties,omitempty"`
	MinItems             *int                  `json:"minItems,omitempty"`
	MaxItems             *int                  `json:"maxItems,omitempty"`
	MinContains          *int                  `json:"minContains,omitempty"`
	MaxContains          *int                  `json:"maxContains,omitempty"`
	UniqueItems          bool                  `json:"uniqueItems,omitempty"`
	MinProperties        *int                  `json:"minProperties,omitempty"`
	MaxProperties        *int                  `json:"maxProperties,omitempty"`
	Pattern              string                `json:"pattern,omitempty"`
	Owner                string                `json:"x-prowler-owner,omitempty"`
	Destination          string                `json:"x-prowler-destination,omitempty"`
	Flags                []string              `json:"x-prowler-flags,omitempty"`
	Action               string                `json:"x-prowler-action,omitempty"`
	NArgs                string                `json:"x-prowler-nargs,omitempty"`
	Group                string                `json:"x-prowler-group,omitempty"`
	Order                []string              `json:"x-order,omitempty"`
	ProwlerOrder         *int                  `json:"x-prowler-order,omitempty"`
	Sensitive            bool                  `json:"x-sensitive,omitempty"`
	SecretReference      bool                  `json:"x-secret-reference,omitempty"`
	CredentialSelector   bool                  `json:"x-credential-selector,omitempty"`
	Section              string                `json:"x-section,omitempty"`
	Sections             []Section             `json:"x-sections,omitempty"`
	MutualExclusions     []MutualExclusion     `json:"x-mutual-exclusions,omitempty"`
	CredentialMethods    []auth.Method         `json:"x-credential-methods,omitempty"`
	ProwlerEnvironment   string                `json:"x-prowler-env,omitempty"`
	ClickyLookup         map[string]any        `json:"x-clicky-lookup,omitempty"`
}

type Section struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	SourceURL string `json:"sourceUrl,omitempty"`
}

// MutualExclusion is one group of options of which at most one may be set.
// Named like Section because the form treats it the same way: a heading a
// reader recognises, over keys it already knows.
type MutualExclusion struct {
	ID       string   `json:"id"`
	Title    string   `json:"title,omitempty"`
	Keys     []string `json:"keys"`
	Required bool     `json:"required,omitempty"`
}

// ObjectSchema creates a closed object schema. Prowler rejects unknown
// arguments, so the generated form must do the same.
func ObjectSchema(title string, properties map[string]JSONSchema) JSONSchema {
	additional := false
	return JSONSchema{
		Schema:               "https://json-schema.org/draft/2020-12/schema",
		Type:                 "object",
		Title:                title,
		Properties:           properties,
		AdditionalProperties: &additional,
	}
}

type ProviderSchema struct {
	Provider      string     `json:"provider"`
	Title         string     `json:"title"`
	Version       string     `json:"version"`
	SourceCommit  string     `json:"sourceCommit"`
	ComponentName string     `json:"componentName,omitempty"`
	CLI           JSONSchema `json:"cli"`
	Profile       JSONSchema `json:"profile"`
	Context       JSONSchema `json:"context"`
	Credential    JSONSchema `json:"credentialSchema"`

	CLIComponentRef        string `json:"-"`
	ProfileComponentRef    string `json:"-"`
	ContextComponentRef    string `json:"-"`
	CredentialComponentRef string `json:"-"`
}

type BuiltInProfile struct {
	Name         string `json:"name"`
	Comment      string `json:"comment"`
	Provider     string `json:"provider"`
	ComplianceID string `json:"complianceId"`
}

func (p *ProviderSchema) complete() {
	if p.ComponentName == "" {
		p.ComponentName = "Prowler" + componentToken(p.Title)
	}
	p.CLIComponentRef = "#/components/schemas/" + p.ComponentName + "CLIOptions"
	p.ProfileComponentRef = "#/components/schemas/" + p.ComponentName + "ProfileOptions"
	p.ContextComponentRef = "#/components/schemas/" + p.ComponentName + "ContextOptions"
	p.CredentialComponentRef = "#/components/schemas/" + p.ComponentName + "Credential"
}

func componentToken(value string) string {
	var result strings.Builder
	upperNext := true
	for _, char := range value {
		if char >= 'a' && char <= 'z' {
			if upperNext {
				char -= 'a' - 'A'
			}
			result.WriteRune(char)
			upperNext = false
			continue
		}
		if char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' {
			result.WriteRune(char)
			upperNext = false
			continue
		}
		upperNext = true
	}
	return result.String()
}

type Manifest struct {
	Version                string            `json:"version"`
	SourceCommit           string            `json:"sourceCommit"`
	ProviderCount          int               `json:"providerCount"`
	Providers              []string          `json:"providers"`
	ProfileProjectionCount int               `json:"profileProjectionCount"`
	BuiltInProfiles        []BuiltInProfile  `json:"builtInProfiles"`
	CommonArgumentCount    int               `json:"commonArgumentCount"`
	ProviderArgumentCounts map[string]int    `json:"providerArgumentCounts,omitempty"`
	SourceDigest           string            `json:"sourceDigest"`
	CatalogDigest          string            `json:"catalogDigest"`
	Digests                map[string]string `json:"digests"`
}

type Registry struct {
	Manifest Manifest
	ordered  []ProviderSchema
	byID     map[string]ProviderSchema
}

func (r *Registry) ProviderIDs() []string {
	return append([]string(nil), r.Manifest.Providers...)
}

func (r *Registry) Provider(id string) (ProviderSchema, bool) {
	provider, ok := r.byID[id]
	return provider, ok
}

func (r *Registry) ProviderSchemas() []ProviderSchema {
	return append([]ProviderSchema(nil), r.ordered...)
}

func (r *Registry) BuiltInProfiles() []engines.DefaultProfile {
	profiles := make([]engines.DefaultProfile, 0, len(r.Manifest.BuiltInProfiles))
	for _, profile := range r.Manifest.BuiltInProfiles {
		profiles = append(profiles, engines.DefaultProfile{
			Name:    profile.Name,
			Comment: profile.Comment,
			Config: map[string]any{
				"provider":   profile.Provider,
				"compliance": []any{profile.ComplianceID},
			},
		})
	}
	return profiles
}

func (r *Registry) OpenAPIComponents() map[string]JSONSchema {
	components := make(map[string]JSONSchema, len(r.ordered)*4)
	for _, provider := range r.ordered {
		components[provider.ComponentName+"CLIOptions"] = provider.CLI
		components[provider.ComponentName+"ProfileOptions"] = provider.Profile
		components[provider.ComponentName+"ContextOptions"] = provider.Context
		components[provider.ComponentName+"Credential"] = provider.Credential
	}
	return components
}

func (r *Registry) OptionCatalog() engines.OptionCatalog {
	variants := make([]engines.OptionVariant, 0, len(r.ordered))
	for _, provider := range r.ordered {
		context := provider.Context.EngineSchema()
		credential := provider.Credential.EngineSchema()
		variants = append(variants, engines.OptionVariant{
			ID:                    provider.Provider,
			Title:                 provider.Title,
			Schema:                provider.Profile.EngineSchema(),
			ContextSchema:         &context,
			CredentialSchema:      &credential,
			SchemaRef:             provider.ProfileComponentRef,
			ContextSchemaRef:      provider.ContextComponentRef,
			CredentialSchemaRef:   provider.CredentialComponentRef,
			CLIArgumentsSchemaRef: provider.CLIComponentRef,
		})
	}
	return engines.OptionCatalog{Discriminator: "provider", Variants: variants}
}

// EngineSchema projects the typed generated representation into the generic
// engine contract without a JSON marshal/unmarshal round trip.
func (s JSONSchema) EngineSchema() engines.JSONSchema {
	result := engines.JSONSchema{}
	put := func(key string, value any, present bool) {
		if present {
			result[key] = value
		}
	}
	put("$schema", s.Schema, s.Schema != "")
	put("type", s.Type, s.Type != "")
	put("title", s.Title, s.Title != "")
	put("description", s.Description, s.Description != "")
	if len(s.Properties) > 0 {
		properties := make(map[string]any, len(s.Properties))
		for key, property := range s.Properties {
			properties[key] = property.EngineSchema()
		}
		result["properties"] = properties
	}
	put("required", append([]string(nil), s.Required...), len(s.Required) > 0)
	if s.Items != nil {
		result["items"] = s.Items.EngineSchema()
	}
	if len(s.OneOf) > 0 {
		oneOf := make([]engines.JSONSchema, len(s.OneOf))
		for index, option := range s.OneOf {
			oneOf[index] = option.EngineSchema()
		}
		result["oneOf"] = oneOf
	}
	if len(s.AllOf) > 0 {
		allOf := make([]engines.JSONSchema, len(s.AllOf))
		for index, option := range s.AllOf {
			allOf[index] = option.EngineSchema()
		}
		result["allOf"] = allOf
	}
	if s.Contains != nil {
		result["contains"] = s.Contains.EngineSchema()
	}
	put("enum", append([]any(nil), s.Enum...), len(s.Enum) > 0)
	put("default", s.Default, s.Default != nil)
	put("const", s.Const, s.Const != nil)
	put("format", s.Format, s.Format != "")
	put("writeOnly", true, s.WriteOnly)
	put("readOnly", true, s.ReadOnly)
	if s.AdditionalProperties != nil {
		result["additionalProperties"] = *s.AdditionalProperties
	}
	if s.MinItems != nil {
		result["minItems"] = *s.MinItems
	}
	if s.MaxItems != nil {
		result["maxItems"] = *s.MaxItems
	}
	if s.MinContains != nil {
		result["minContains"] = *s.MinContains
	}
	if s.MaxContains != nil {
		result["maxContains"] = *s.MaxContains
	}
	put("uniqueItems", true, s.UniqueItems)
	if s.MinProperties != nil {
		result["minProperties"] = *s.MinProperties
	}
	if s.MaxProperties != nil {
		result["maxProperties"] = *s.MaxProperties
	}
	put("pattern", s.Pattern, s.Pattern != "")
	put("x-prowler-owner", s.Owner, s.Owner != "")
	put("x-prowler-destination", s.Destination, s.Destination != "")
	put("x-prowler-flags", append([]string(nil), s.Flags...), len(s.Flags) > 0)
	put("x-prowler-action", s.Action, s.Action != "")
	put("x-prowler-nargs", s.NArgs, s.NArgs != "")
	put("x-prowler-group", s.Group, s.Group != "")
	put("x-order", append([]string(nil), s.Order...), len(s.Order) > 0)
	if s.ProwlerOrder != nil {
		result["x-prowler-order"] = *s.ProwlerOrder
	}
	put("x-sensitive", true, s.Sensitive)
	put("x-secret-reference", true, s.SecretReference)
	put("x-credential-selector", true, s.CredentialSelector)
	put("x-section", s.Section, s.Section != "")
	put("x-sections", append([]Section(nil), s.Sections...), len(s.Sections) > 0)
	put("x-mutual-exclusions", append([]MutualExclusion(nil), s.MutualExclusions...), len(s.MutualExclusions) > 0)
	put("x-credential-methods", append([]auth.Method(nil), s.CredentialMethods...), len(s.CredentialMethods) > 0)
	put("x-prowler-env", s.ProwlerEnvironment, s.ProwlerEnvironment != "")
	put("x-clicky-lookup", s.ClickyLookup, len(s.ClickyLookup) > 0)
	return result
}

// OpenAPISchema preserves the schema semantics in the JSON Schema subset used
// by OpenAPI 3.0 components: const becomes a single-value enum and $schema is
// omitted. The inline option catalogue retains the Draft 2020-12 form.
func (s JSONSchema) OpenAPISchema() engines.JSONSchema {
	return openAPIObject(s.EngineSchema())
}

func openAPIObject(input engines.JSONSchema) engines.JSONSchema {
	result := make(engines.JSONSchema, len(input))
	for key, value := range input {
		if key == "$schema" {
			continue
		}
		if key == "const" {
			result["enum"] = []any{value}
			continue
		}
		switch typed := value.(type) {
		case engines.JSONSchema:
			result[key] = openAPIObject(typed)
		case map[string]any:
			result[key] = openAPIObject(engines.JSONSchema(typed))
		case []engines.JSONSchema:
			projected := make([]engines.JSONSchema, len(typed))
			for index, option := range typed {
				projected[index] = openAPIObject(option)
			}
			result[key] = projected
		default:
			result[key] = value
		}
	}
	return result
}
