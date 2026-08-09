package engines

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
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

// Lookup finds an option across every section.
func (s Sections) Lookup(key string) (Property, bool) {
	for _, section := range s {
		for _, field := range section.Properties {
			if field.Key == key {
				return field.Property, true
			}
		}
	}
	return Property{}, false
}

// Keys lists every option this engine accepts, sorted.
func (s Sections) Keys() []string {
	var keys []string
	for _, section := range s {
		for _, field := range section.Properties {
			keys = append(keys, field.Key)
		}
	}
	sort.Strings(keys)
	return keys
}

// Validate checks a profile against the catalog. An unknown option is an error
// rather than a warning: it is nearly always a typo, and silently dropping it
// would mean a profile that does not do what it says.
func (s Sections) Validate(config map[string]any) error {
	keys := make([]string, 0, len(config))
	for key := range config {
		keys = append(keys, key)
	}
	sort.Strings(keys) // deterministic message ordering

	var problems []string
	for _, key := range keys {
		property, known := s.Lookup(key)
		if !known {
			problems = append(problems, fmt.Sprintf("unsupported option: %s", key))
			continue
		}
		if err := property.validate(key, config[key]); err != nil {
			problems = append(problems, err.Error())
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

// validate checks one value.
func (p Property) validate(key string, value any) error {
	if value == nil {
		return nil // an explicit null clears the option
	}

	// An enum constrains the value regardless of declared type.
	if len(p.Enum) > 0 {
		text, ok := value.(string)
		if !ok {
			return fmt.Errorf("invalid value for %s: expected one of %s", key, strings.Join(p.Enum, ", "))
		}
		for _, allowed := range p.Enum {
			if text == allowed {
				return nil
			}
		}
		return fmt.Errorf("invalid value for %s: expected one of %s", key, strings.Join(p.Enum, ", "))
	}

	switch p.Type {
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("invalid value for %s: expected boolean", key)
		}
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("invalid value for %s: expected string", key)
		}
	case "integer", "number":
		number, ok := asNumber(value)
		if !ok {
			return fmt.Errorf("invalid value for %s: expected %s", key, p.Type)
		}
		// YAML decodes an integer as int and JSON as float64, so accept a float
		// with no fractional part where an integer is required.
		if p.Type == "integer" && number != float64(int64(number)) {
			return fmt.Errorf("invalid value for %s: expected integer", key)
		}
		if p.Minimum != nil && number < *p.Minimum {
			return fmt.Errorf("invalid value for %s: minimum is %v", key, *p.Minimum)
		}
		if p.Maximum != nil && number > *p.Maximum {
			return fmt.Errorf("invalid value for %s: maximum is %v", key, *p.Maximum)
		}
	case "array":
		items, ok := value.([]any)
		if !ok {
			return fmt.Errorf("invalid value for %s: expected array", key)
		}
		if p.Items == nil {
			return nil
		}
		for i, item := range items {
			if err := p.Items.validate(fmt.Sprintf("%s[%d]", key, i), item); err != nil {
				return err
			}
		}
	}
	return nil
}

// asNumber accepts every numeric shape a YAML or JSON decoder can produce.
func asNumber(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case uint:
		return float64(typed), true
	case uint64:
		return float64(typed), true
	case json.Number:
		parsed, err := typed.Float64()
		return parsed, err == nil
	}
	return 0, false
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
