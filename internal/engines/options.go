package engines

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// JSONSchema is a Draft 2020-12 JSON Schema document served to the profile
// editor and used unchanged for server-side validation.
type JSONSchema map[string]any

// OptionCatalog contains every option schema an engine exposes. Engines whose
// configuration does not vary have one variant and no discriminator.
type OptionCatalog struct {
	Discriminator string          `json:"discriminator,omitempty"`
	Variants      []OptionVariant `json:"variants"`
}

// OptionVariant is one complete profile schema and, when needed, the context
// schema for the same provider. Component refs let the OpenAPI publisher name
// the generated schemas without making the UI resolve refs.
type OptionVariant struct {
	ID                    string      `json:"id"`
	Title                 string      `json:"title"`
	Schema                JSONSchema  `json:"schema"`
	ContextSchema         *JSONSchema `json:"contextSchema,omitempty"`
	CredentialSchema      *JSONSchema `json:"credentialSchema,omitempty"`
	SchemaRef             string      `json:"schemaRef,omitempty"`
	ContextSchemaRef      string      `json:"contextSchemaRef,omitempty"`
	CredentialSchemaRef   string      `json:"credentialSchemaRef,omitempty"`
	CLIArgumentsSchemaRef string      `json:"cliArgumentsSchemaRef,omitempty"`
}

// OptionSection is layout metadata embedded in a schema's x-sections field.
type OptionSection struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	SourceURL   string `json:"sourceUrl,omitempty"`
}

// Resolve selects the one schema that validates config.
func (c OptionCatalog) Resolve(config map[string]any) (OptionVariant, error) {
	if c.Discriminator == "" {
		if len(c.Variants) != 1 {
			return OptionVariant{}, fmt.Errorf("option catalog without a discriminator must have exactly one variant")
		}
		return c.Variants[0], nil
	}

	value, found := config[c.Discriminator]
	if !found || value == nil || value == "" {
		return OptionVariant{}, fmt.Errorf("%s is required", c.Discriminator)
	}
	selected, ok := value.(string)
	if !ok {
		return OptionVariant{}, fmt.Errorf("%s must be a string", c.Discriminator)
	}
	for _, variant := range c.Variants {
		if variant.ID == selected {
			return variant, nil
		}
	}

	available := make([]string, 0, len(c.Variants))
	for _, variant := range c.Variants {
		available = append(available, variant.ID)
	}
	sort.Strings(available)
	return OptionVariant{}, fmt.Errorf(
		"unknown %s %q: expected one of %s", c.Discriminator, selected, strings.Join(available, ", "))
}

// Validate checks that the catalog is deterministic and every inline schema
// compiles before the engine is registered.
func (c OptionCatalog) Validate() error {
	if len(c.Variants) == 0 {
		return fmt.Errorf("option catalog must have at least one variant")
	}
	if c.Discriminator == "" && len(c.Variants) != 1 {
		return fmt.Errorf("option catalog with multiple variants requires a discriminator")
	}

	seen := map[string]bool{}
	for _, variant := range c.Variants {
		if variant.ID == "" {
			return fmt.Errorf("option variant id is required")
		}
		if seen[variant.ID] {
			return fmt.Errorf("duplicate option variant %q", variant.ID)
		}
		seen[variant.ID] = true
		if variant.Title == "" {
			return fmt.Errorf("option variant %q: title is required", variant.ID)
		}
		if err := validateObjectSchema("option variant "+variant.ID+" profile schema", variant.Schema); err != nil {
			return err
		}
		if c.Discriminator != "" {
			if err := validateDiscriminator(c.Discriminator, variant); err != nil {
				return err
			}
		}
		if variant.ContextSchema != nil {
			if err := validateObjectSchema("option variant "+variant.ID+" context schema", *variant.ContextSchema); err != nil {
				return err
			}
		}
		if variant.CredentialSchema != nil {
			if err := validateObjectSchema("option variant "+variant.ID+" credential schema", *variant.CredentialSchema); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidateConfig applies the selected variant's complete JSON Schema.
func (c OptionCatalog) ValidateConfig(config map[string]any) error {
	variant, err := c.Resolve(config)
	if err != nil {
		return err
	}
	compiled, err := compileJSONSchema("option variant "+variant.ID+" profile schema", variant.Schema)
	if err != nil {
		return err
	}
	if err := compiled.Validate(config); err != nil {
		return fmt.Errorf("option variant %s: %w", variant.ID, err)
	}
	return nil
}

// ValidateContext applies the selected provider's optional context schema.
func (c OptionCatalog) ValidateContext(config, context map[string]any) error {
	variant, err := c.Resolve(config)
	if err != nil {
		return err
	}
	if variant.ContextSchema == nil {
		if len(context) > 0 {
			return fmt.Errorf("option variant %s does not accept context", variant.ID)
		}
		return nil
	}
	compiled, err := compileJSONSchema("option variant "+variant.ID+" context schema", *variant.ContextSchema)
	if err != nil {
		return err
	}
	if err := compiled.Validate(context); err != nil {
		return fmt.Errorf("option variant %s context: %w", variant.ID, err)
	}
	return nil
}

// ValidateCredentials applies the selected provider's credential schema.
func (c OptionCatalog) ValidateCredentials(config, credentials map[string]any) error {
	variant, err := c.Resolve(config)
	if err != nil {
		return err
	}
	if variant.CredentialSchema == nil {
		if len(credentials) > 0 {
			return fmt.Errorf("option variant %s does not accept credentials", variant.ID)
		}
		return nil
	}
	compiled, err := compileJSONSchema("option variant "+variant.ID+" credential schema", *variant.CredentialSchema)
	if err != nil {
		return err
	}
	if err := compiled.Validate(credentials); err != nil {
		return fmt.Errorf("option variant %s credentials: %w", variant.ID, err)
	}
	return nil
}

// ValidateOverrides prevents a run-only override from changing which variant
// validates the stored profile.
func (c OptionCatalog) ValidateOverrides(config, overrides map[string]any) error {
	if c.Discriminator == "" {
		return nil
	}
	variant, err := c.Resolve(config)
	if err != nil {
		return err
	}
	value, found := overrides[c.Discriminator]
	if !found {
		return nil
	}
	selected, ok := value.(string)
	if !ok || selected != variant.ID {
		return fmt.Errorf("cannot override %s from %q to %v", c.Discriminator, variant.ID, value)
	}
	return nil
}

func validateObjectSchema(label string, schema JSONSchema) error {
	if schema == nil {
		return fmt.Errorf("%s is required", label)
	}
	if schema["type"] != "object" {
		return fmt.Errorf("%s: root type must be object", label)
	}
	if schema["additionalProperties"] != false && schema["unevaluatedProperties"] != false {
		return fmt.Errorf("%s: unknown properties must be rejected", label)
	}
	_, err := compileJSONSchema(label, schema)
	return err
}

func validateDiscriminator(discriminator string, variant OptionVariant) error {
	properties, ok := stringMap(variant.Schema["properties"])
	if !ok {
		return fmt.Errorf("option variant %q must define discriminator %q", variant.ID, discriminator)
	}
	property, ok := stringMap(properties[discriminator])
	if !ok {
		return fmt.Errorf("option variant %q must define discriminator %q", variant.ID, discriminator)
	}
	if property["const"] != variant.ID {
		return fmt.Errorf("option variant %q discriminator %q must have const %q", variant.ID, discriminator, variant.ID)
	}
	if property["readOnly"] != true {
		return fmt.Errorf("option variant %q discriminator %q must be readOnly", variant.ID, discriminator)
	}
	if !containsString(variant.Schema["required"], discriminator) {
		return fmt.Errorf("option variant %q must require discriminator %q", variant.ID, discriminator)
	}
	return nil
}

func stringMap(value any) (map[string]any, bool) {
	switch typed := value.(type) {
	case JSONSchema:
		return map[string]any(typed), true
	case map[string]any:
		return typed, true
	default:
		return nil, false
	}
}

func containsString(value any, expected string) bool {
	switch values := value.(type) {
	case []string:
		for _, value := range values {
			if value == expected {
				return true
			}
		}
	case []any:
		for _, value := range values {
			if value == expected {
				return true
			}
		}
	}
	return false
}

var compiledOptionSchemas sync.Map

func compileJSONSchema(label string, schema JSONSchema) (*jsonschema.Schema, error) {
	raw, err := json.Marshal(schema)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", label, err)
	}
	if compiled, ok := compiledOptionSchemas.Load(string(raw)); ok {
		return compiled.(*jsonschema.Schema), nil
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", label, err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource("schema.json", document); err != nil {
		return nil, fmt.Errorf("add %s: %w", label, err)
	}
	compiled, err := compiler.Compile("schema.json")
	if err != nil {
		return nil, fmt.Errorf("compile %s: %w", label, err)
	}
	stored, _ := compiledOptionSchemas.LoadOrStore(string(raw), compiled)
	return stored.(*jsonschema.Schema), nil
}
