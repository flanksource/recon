package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/ulikunitz/xz"
)

// xzDictionarySize matches the Prowler catalogue artifact, so both compressed
// artifacts in this repository read back with the same reader configuration.
const xzDictionarySize = 8 * 1024 * 1024

// export models the schema export published at
// https://schema.ocsf.io/<version>/export/schema.
//
// One document rather than the per-class JSON Schema plus a metaschema fetch per
// object, because it is the only published form that carries the inheritance-
// resolved class attributes, every object definition and the attribute
// dictionary together — and it names its own version, which the JSON Schema
// export does not.
type export struct {
	Version              string               `json:"version"`
	Classes              map[string]class     `json:"classes"`
	Objects              map[string]object    `json:"objects"`
	DictionaryAttributes map[string]attribute `json:"dictionary_attributes"`
}

type class struct {
	Name        string               `json:"name"`
	UID         int                  `json:"uid"`
	CategoryUID int                  `json:"category_uid"`
	Caption     string               `json:"caption"`
	Description string               `json:"description"`
	Profiles    []string             `json:"profiles"`
	Attributes  map[string]attribute `json:"attributes"`
}

type object struct {
	Name        string               `json:"name"`
	Caption     string               `json:"caption"`
	Description string               `json:"description"`
	Constraints constraints          `json:"constraints"`
	Attributes  map[string]attribute `json:"attributes"`
}

// constraints are the conditions OCSF states about an object that no struct
// shape can express — chiefly at_least_one, which is why Validate exists.
type constraints struct {
	AtLeastOne []string `json:"at_least_one"`
	JustOne    []string `json:"just_one"`
}

type attribute struct {
	Type        string                `json:"type"`
	ObjectType  string                `json:"object_type"`
	IsArray     bool                  `json:"is_array"`
	Requirement string                `json:"requirement"`
	Profile     string                `json:"profile"`
	Caption     string                `json:"caption"`
	Description string                `json:"description"`
	Sibling     string                `json:"sibling"`
	Enum        map[string]enumMember `json:"enum"`
}

type enumMember struct {
	Caption     string `json:"caption"`
	Description string `json:"description"`
}

// enumFor resolves an attribute's enumeration the way the schema server does:
// a definition local to the class or object wins, and only when there is none
// does the attribute dictionary answer.
//
// The order is the whole reason this function exists. `status_id` is defined in
// the dictionary as the activity outcome — Success, Failure — and overridden on
// the finding classes as the triage state — New, Suppressed, Resolved. Reading
// the dictionary first would compile, produce plausible constants, and label
// every finding wrongly.
func (e export) enumFor(name string, attr attribute) map[string]enumMember {
	if len(attr.Enum) > 0 {
		return attr.Enum
	}
	return e.DictionaryAttributes[name].Enum
}

func loadExport(path string) (export, error) {
	compressed, err := os.ReadFile(path)
	if err != nil {
		return export{}, fmt.Errorf("read OCSF schema export: %w", err)
	}
	reader, err := (xz.ReaderConfig{
		DictCap:      xzDictionarySize,
		SingleStream: true,
	}).NewReader(bytes.NewReader(compressed))
	if err != nil {
		return export{}, fmt.Errorf("decompress OCSF schema export: %w", err)
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		return export{}, fmt.Errorf("decompress OCSF schema export: %w", err)
	}
	var loaded export
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return export{}, fmt.Errorf("parse OCSF schema export: %w", err)
	}
	if loaded.Version == "" {
		return export{}, fmt.Errorf("OCSF schema export names no version")
	}
	return loaded, nil
}

func saveExport(path string, raw []byte) error {
	var probe export
	if err := json.Unmarshal(raw, &probe); err != nil {
		return fmt.Errorf("parse fetched OCSF schema export: %w", err)
	}
	if probe.Version == "" {
		return fmt.Errorf("fetched OCSF schema export names no version")
	}
	if len(probe.Classes) == 0 || len(probe.Objects) == 0 {
		return fmt.Errorf("fetched OCSF schema export carries no classes or objects")
	}

	var compressed bytes.Buffer
	writer, err := (xz.WriterConfig{DictCap: xzDictionarySize}).NewWriter(&compressed)
	if err != nil {
		return fmt.Errorf("compress OCSF schema export: %w", err)
	}
	if _, err := writer.Write(raw); err != nil {
		return fmt.Errorf("compress OCSF schema export: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("compress OCSF schema export: %w", err)
	}
	if err := os.WriteFile(path, compressed.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write OCSF schema export: %w", err)
	}
	return nil
}
