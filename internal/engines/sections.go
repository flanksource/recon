package engines

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Sections is an engine's option catalog, grouped for display.
//
// Properties are a slice rather than a map because their order is the form
// layout: the UI renders each section's fields in declaration order, and Go maps
// randomise while encoding/json sorts keys alphabetically. Either would scramble
// a carefully grouped form.
type Sections []Section

// Section is one group of options.
type Section struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Description string  `json:"description,omitempty"`
	SourceURL   string  `json:"sourceUrl,omitempty"`
	Properties  []Field `json:"-"`
}

// Field is one option, keyed by the name it takes in a profile.
type Field struct {
	Key      string
	Property Property
}

// Property describes a single option, in the subset of JSON Schema the form
// renderer understands.
type Property struct {
	Type         string    `json:"type,omitempty"`
	Title        string    `json:"title,omitempty"`
	Description  string    `json:"description,omitempty"`
	Enum         []string  `json:"enum,omitempty"`
	Items        *Property `json:"items,omitempty"`
	MultipleOf   *float64  `json:"multipleOf,omitempty"`
	Minimum      *float64  `json:"minimum,omitempty"`
	Maximum      *float64  `json:"maximum,omitempty"`
	ArrayDisplay string    `json:"x-array-display,omitempty"`
}

// MarshalJSON emits the section with `properties` as a JSON object in
// declaration order.
func (s Section) MarshalJSON() ([]byte, error) {
	var out bytes.Buffer
	out.WriteString(`{"id":`)
	writeJSONString(&out, s.ID)
	out.WriteString(`,"title":`)
	writeJSONString(&out, s.Title)
	if s.Description != "" {
		out.WriteString(`,"description":`)
		writeJSONString(&out, s.Description)
	}
	if s.SourceURL != "" {
		out.WriteString(`,"sourceUrl":`)
		writeJSONString(&out, s.SourceURL)
	}

	out.WriteString(`,"properties":{`)
	for i, field := range s.Properties {
		if i > 0 {
			out.WriteByte(',')
		}
		writeJSONString(&out, field.Key)
		out.WriteByte(':')
		encoded, err := json.Marshal(field.Property)
		if err != nil {
			return nil, fmt.Errorf("encode option %s: %w", field.Key, err)
		}
		out.Write(encoded)
	}
	out.WriteString("}}")
	return out.Bytes(), nil
}

func writeJSONString(buffer *bytes.Buffer, value string) {
	encoded, err := json.Marshal(value)
	if err != nil { // a string cannot fail to encode
		panic(err)
	}
	buffer.Write(encoded)
}

// SchemaFromSections renders one ordered form catalog as a complete JSON
// Schema, preserving the declaration order the form layout depends on.
//
// Separate from OptionsFromSections because an engine whose configuration
// varies by provider needs one of these per variant, and building each variant
// from the same Section/Field vocabulary is what keeps a hand-written catalog
// and a generated one describing options the same way.
func SchemaFromSections(sections Sections) JSONSchema {
	properties := JSONSchema{}
	order := make([]string, 0)
	layout := make([]OptionSection, 0, len(sections))
	for _, section := range sections {
		layout = append(layout, OptionSection{
			ID: section.ID, Title: section.Title, Description: section.Description, SourceURL: section.SourceURL,
		})
		for _, field := range section.Properties {
			properties[field.Key] = field.Property.jsonSchema(section.ID)
			order = append(order, field.Key)
		}
	}
	return JSONSchema{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"type":                 "object",
		"additionalProperties": false,
		"properties":           properties,
		"x-order":              order,
		"x-sections":           layout,
	}
}

// OptionsFromSections turns the original ordered form catalog into the same
// full JSON Schema contract used by provider-backed engines.
func OptionsFromSections(sections Sections) OptionCatalog {
	return OptionCatalog{Variants: []OptionVariant{{
		ID: "default", Title: "Options", Schema: SchemaFromSections(sections),
	}}}
}

func (p Property) jsonSchema(section string) JSONSchema {
	schema := JSONSchema{"x-section": section}
	if p.Type != "" {
		schema["type"] = []string{p.Type, "null"}
	}
	if p.Title != "" {
		schema["title"] = p.Title
	}
	if p.Description != "" {
		schema["description"] = p.Description
	}
	if len(p.Enum) > 0 {
		values := make([]any, 0, len(p.Enum)+1)
		for _, value := range p.Enum {
			values = append(values, value)
		}
		schema["enum"] = append(values, nil)
	}
	if p.Items != nil {
		schema["items"] = p.Items.jsonSchema("")
		delete(schema["items"].(JSONSchema), "x-section")
	}
	if p.MultipleOf != nil {
		schema["multipleOf"] = *p.MultipleOf
	}
	if p.Minimum != nil {
		schema["minimum"] = *p.Minimum
	}
	if p.Maximum != nil {
		schema["maximum"] = *p.Maximum
	}
	if p.ArrayDisplay != "" {
		schema["x-array-display"] = p.ArrayDisplay
	}
	return schema
}

// ---------------------------------------------------------------- builders

// Bool declares a boolean option.
func Bool(key, title, description string) Field {
	return Field{Key: key, Property: Property{Type: "boolean", Title: title, Description: description}}
}

// Str declares a string option.
func Str(key, title, description string) Field {
	return Field{Key: key, Property: Property{Type: "string", Title: title, Description: description}}
}

// Int declares an integer option, optionally bounded. multipleOf is redundant
// alongside type:integer for validation, but the form widget reads it as the
// spinner step, so every integer field carries it.
func Int(key, title, description string, bounds ...float64) Field {
	property := Property{Type: "integer", Title: title, Description: description, MultipleOf: Num(1)}
	if len(bounds) > 0 {
		property.Minimum = &bounds[0]
	}
	if len(bounds) > 1 {
		property.Maximum = &bounds[1]
	}
	return Field{Key: key, Property: property}
}

// Enum declares a string option restricted to a fixed set.
func Enum(key, title, description string, values ...string) Field {
	return Field{Key: key, Property: Property{Type: "string", Title: title, Description: description, Enum: values}}
}

// Num returns a pointer to a bound, so a generated catalog can express "no
// minimum" distinctly from "minimum zero".
func Num(value float64) *float64 { return &value }

// StrList declares a list-of-strings option, rendered as filter pills.
func StrList(key, title, description string) Field {
	return Field{Key: key, Property: Property{
		Type: "array", Title: title, Description: description,
		Items:        &Property{Type: "string"},
		ArrayDisplay: "filter-pills",
	}}
}

// EnumList declares a list option whose elements come from a fixed set — the
// shape a tool's comma-separated `--scanners`-style flag takes. Enum rather
// than StrList so a misspelled element is refused when the profile is saved
// rather than by the engine, minutes into a run.
func EnumList(key, title, description string, values ...string) Field {
	return Field{Key: key, Property: Property{
		Type: "array", Title: title, Description: description,
		Items:        &Property{Type: "string", Enum: values},
		ArrayDisplay: "filter-pills",
	}}
}
