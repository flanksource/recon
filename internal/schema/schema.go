// Package schema owns the two things that define a valid inventory: the
// Draft 2020-12 JSON Schemas the editor and the store validate against, and the
// declarative Atlas HCL that defines the database.
//
// target.schema.json is embedded rather than generated. It uses $defs,
// readOnly, additionalProperties:false, the hostname/ipv4/ipv6/uri/date-time
// formats, and an allOf if/then pair encoding "a deactivated target requires a
// reason, and no other class may carry one" — none of which survives a
// round-trip through Go struct reflection. It is also what the clicky-ui editor
// renders, so it has to stay authoritative.
package schema

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// ErrorKind.LocalizedString requires a printer and panics on nil; the library's
// own default is unexported, so build the equivalent.
var printer = message.NewPrinter(language.English)

//go:embed target.schema.json
var targetSchemaJSON []byte

//go:embed inventory.schema.json
var inventorySchemaJSON []byte

// TargetSchemaJSON is the raw document served to the editor.
func TargetSchemaJSON() []byte { return targetSchemaJSON }

// InventorySchemaJSON is the raw manifest schema.
func InventorySchemaJSON() []byte { return inventorySchemaJSON }

var (
	compileOnce sync.Once
	target      *jsonschema.Schema
	inventory   *jsonschema.Schema
	compileErr  error
)

// compile builds both validators once. Failure here is a programming error —
// the schemas are embedded, so they cannot be missing or malformed at runtime
// unless the binary itself is broken.
func compile() {
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat() // hostname/ipv4/ipv6/uri/date-time are load-bearing

	add := func(name string, raw []byte) (*jsonschema.Schema, error) {
		doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		if err := compiler.AddResource(name, doc); err != nil {
			return nil, fmt.Errorf("add %s: %w", name, err)
		}
		compiled, err := compiler.Compile(name)
		if err != nil {
			return nil, fmt.Errorf("compile %s: %w", name, err)
		}
		return compiled, nil
	}

	if target, compileErr = add("target.schema.json", targetSchemaJSON); compileErr != nil {
		return
	}
	inventory, compileErr = add("inventory.schema.json", inventorySchemaJSON)
}

// ValidateTarget checks one target document. The value must be the decoded JSON
// (map[string]any), not a Go struct: the schema forbids unknown properties, and
// only the raw document can carry one.
func ValidateTarget(label string, document any) error {
	compileOnce.Do(compile)
	if compileErr != nil {
		return compileErr
	}
	return describe(label, target.Validate(document))
}

// ValidateInventory checks the manifest.
func ValidateInventory(label string, document any) error {
	compileOnce.Do(compile)
	if compileErr != nil {
		return compileErr
	}
	return describe(label, inventory.Validate(document))
}

// ValidateTargetJSON decodes and validates raw bytes in one step.
func ValidateTargetJSON(label string, raw []byte) error {
	document, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	return ValidateTarget(label, document)
}

// describe renders a validation failure the way the TypeScript store did —
// "<label>: <instance path> <message>", joined by "; " and sorted so the text is
// stable across runs. The editor surfaces this string directly.
func describe(label string, err error) error {
	if err == nil {
		return nil
	}
	var invalid *jsonschema.ValidationError
	if !errors.As(err, &invalid) {
		return fmt.Errorf("%s: %w", label, err)
	}

	causes := leaves(invalid)
	messages := make([]string, 0, len(causes))
	for _, cause := range causes {
		location := cause.InstanceLocation
		path := "/" + strings.Join(location, "/")
		if len(location) == 0 {
			path = "/"
		}
		messages = append(messages, fmt.Sprintf("%s %s", path, cause.ErrorKind.LocalizedString(printer)))
	}
	sort.Strings(messages)
	messages = dedupe(messages)

	return fmt.Errorf("%s: %s", label, strings.Join(messages, "; "))
}

// leaves flattens the error tree to its most specific causes. The root error
// only ever says "doesn't validate", which is useless on its own.
func leaves(err *jsonschema.ValidationError) []*jsonschema.ValidationError {
	if len(err.Causes) == 0 {
		return []*jsonschema.ValidationError{err}
	}
	var out []*jsonschema.ValidationError
	for _, cause := range err.Causes {
		out = append(out, leaves(cause)...)
	}
	return out
}

func dedupe(values []string) []string {
	out := values[:0]
	var previous string
	for i, value := range values {
		if i > 0 && value == previous {
			continue
		}
		out = append(out, value)
		previous = value
	}
	return out
}

// MarshalIndentedTarget re-encodes a document the way the TypeScript store wrote
// it: two-space indent and a trailing newline. The exporter depends on this to
// reproduce the checked-in files byte for byte.
func MarshalIndentedTarget(value any) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}
