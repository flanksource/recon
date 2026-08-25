package main

import (
	"fmt"
	"sort"
	"strconv"
)

// identityAttributes are the three integers that name the class rather than
// describe the finding. They carry single-member enumerations, so the generic
// rule would mint an enum type with one constant for each; they are emitted as
// package constants instead, which is what a caller actually wants to compare
// against.
var identityAttributes = map[string]bool{
	"class_uid":    true,
	"category_uid": true,
	"type_uid":     true,
}

type model struct {
	Version     string
	ClassOCSF   string
	ClassName   string
	ClassUID    int
	CategoryUID int
	Caption     string
	Description string
	Profiles    []string
	Root        renderedType
	Objects     []renderedType
	Enums       []renderedEnum
}

type renderedType struct {
	Name        string
	OCSF        string
	Caption     string
	Description string
	AtLeastOne  []string
	JustOne     []string
	Fields      []field
}

type field struct {
	Name        string
	OCSF        string
	GoType      string
	Requirement string
	Profile     string
	Caption     string
	Description string
	OmitEmpty   bool
}

type renderedEnum struct {
	Name        string
	OCSF        string
	Owner       string
	Caption     string
	Description string
	Members     []enumConst
}

type enumConst struct {
	Name        string
	Value       int
	Caption     string
	Description string
}

// build resolves the allowlist against the schema into everything the emitter
// needs, refusing anything it cannot account for.
func build(schema export) (model, error) {
	root, ok := schema.Classes[rootClass]
	if !ok {
		return model{}, fmt.Errorf("OCSF schema export has no class %q", rootClass)
	}

	built := model{
		Version:     schema.Version,
		ClassOCSF:   rootClass,
		ClassName:   goName(rootClass),
		ClassUID:    root.UID,
		CategoryUID: root.CategoryUID,
		Caption:     root.Caption,
		Description: root.Description,
		Profiles:    append([]string(nil), root.Profiles...),
	}
	sort.Strings(built.Profiles)

	enums := map[string]renderedEnum{}

	rendered, err := buildType(schema, rootClass, root.Caption, root.Description,
		root.Attributes, constraints{}, enums)
	if err != nil {
		return model{}, err
	}
	built.Root = rendered

	names := make([]string, 0, len(allowed))
	for name := range allowed {
		if name != rootClass {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	for _, name := range names {
		definition, ok := schema.Objects[name]
		if !ok {
			return model{}, fmt.Errorf("allowlist names object %q, which the OCSF schema does not define", name)
		}
		rendered, err := buildType(schema, name, definition.Caption, definition.Description,
			definition.Attributes, definition.Constraints, enums)
		if err != nil {
			return model{}, err
		}
		built.Objects = append(built.Objects, rendered)
	}

	for _, enum := range enums {
		built.Enums = append(built.Enums, enum)
	}
	sort.Slice(built.Enums, func(i, j int) bool { return built.Enums[i].Name < built.Enums[j].Name })

	return built, nil
}

func buildType(
	schema export,
	ocsfName, caption, description string,
	attributes map[string]attribute,
	limits constraints,
	enums map[string]renderedEnum,
) (renderedType, error) {
	wanted := allowed[ocsfName]
	rendered := newType(ocsfName, caption, description, limits, wanted)

	sorted := append([]string(nil), wanted...)
	sort.Strings(sorted)

	for _, name := range sorted {
		attr, ok := attributes[name]
		if !ok {
			return renderedType{}, fmt.Errorf(
				"allowlist names %s.%s, which the OCSF schema does not define on that type", ocsfName, name)
		}
		resolved, err := buildField(schema, ocsfName, name, attr, enums)
		if err != nil {
			return renderedType{}, err
		}
		rendered.Fields = append(rendered.Fields, resolved)
	}
	return rendered, nil
}

func newType(ocsfName, caption, description string, limits constraints, wanted []string) renderedType {
	rendered := renderedType{
		Name:        goName(ocsfName),
		OCSF:        ocsfName,
		Caption:     caption,
		Description: description,
	}
	// Only the parts of a constraint that survive pruning can be checked, and a
	// constraint listing attributes this build does not carry would make Validate
	// reject records that are in fact valid.
	kept := map[string]bool{}
	for _, name := range wanted {
		kept[name] = true
	}
	for _, name := range limits.AtLeastOne {
		if kept[name] {
			rendered.AtLeastOne = append(rendered.AtLeastOne, name)
		}
	}
	for _, name := range limits.JustOne {
		if kept[name] {
			rendered.JustOne = append(rendered.JustOne, name)
		}
	}
	sort.Strings(rendered.AtLeastOne)
	sort.Strings(rendered.JustOne)
	return rendered
}

func buildField(
	schema export,
	owner, name string,
	attr attribute,
	enums map[string]renderedEnum,
) (field, error) {
	resolved := field{
		Name:        goName(name),
		OCSF:        name,
		Requirement: attr.Requirement,
		Profile:     attr.Profile,
		Caption:     attr.Caption,
		Description: attr.Description,
	}
	// A required attribute always marshals; anything else is absent when unset,
	// which is what keeps a nuclei finding from carrying empty cloud identity.
	// A profile-gated attribute is only required when that profile is declared,
	// so it stays omitempty and Validate decides.
	resolved.OmitEmpty = attr.Requirement != "required" || attr.Profile != ""

	goType, err := fieldType(schema, owner, name, attr, enums)
	if err != nil {
		return field{}, err
	}
	resolved.GoType = goType
	return resolved, nil
}

func fieldType(schema export, owner, name string, attr attribute, enums map[string]renderedEnum) (string, error) {
	if attr.Type == "object_t" {
		target := attr.ObjectType
		// OCSF's `object` is its any-shaped escape hatch, which is exactly what
		// `unmapped` is for. It has no definition to generate.
		if target == "" || target == "object" {
			return "map[string]any", nil
		}
		if _, ok := allowed[target]; !ok {
			return "", fmt.Errorf(
				"%s.%s references object %q, which is not in the allowlist; "+
					"add it to allowed or drop the attribute", owner, name, target)
		}
		if attr.IsArray {
			return "[]" + goName(target), nil
		}
		return "*" + goName(target), nil
	}

	scalar, err := scalarType(schema, owner, name, attr, enums)
	if err != nil {
		return "", err
	}
	if attr.IsArray {
		return "[]" + scalar, nil
	}
	return scalar, nil
}

func scalarType(schema export, owner, name string, attr attribute, enums map[string]renderedEnum) (string, error) {
	if attr.Type == "integer_t" && !identityAttributes[name] {
		if members := schema.enumFor(name, attr); len(members) > 1 {
			enumName, err := registerEnum(owner, name, attr, members, enums)
			if err != nil {
				return "", err
			}
			return enumName, nil
		}
	}

	switch attr.Type {
	case "boolean_t":
		return "bool", nil
	case "integer_t", "port_t":
		return "int", nil
	case "long_t", "timestamp_t":
		return "int64", nil
	case "float_t":
		return "float64", nil
	case "json_t":
		return "json.RawMessage", nil
	default:
		// Every remaining OCSF primitive — string_t, datetime_t, url_t, ip_t,
		// hostname_t, uuid_t and the rest — is a string with a documented format
		// rather than a distinct wire type.
		return "string", nil
	}
}

func registerEnum(
	owner, name string,
	attr attribute,
	members map[string]enumMember,
	enums map[string]renderedEnum,
) (string, error) {
	enumName := goName(name)
	if owner != rootClass {
		enumName = goName(owner) + goName(name)
	}

	rendered := renderedEnum{
		Name:        enumName,
		OCSF:        name,
		Owner:       owner,
		Caption:     attr.Caption,
		Description: attr.Description,
	}
	values := make([]string, 0, len(members))
	for value := range members {
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool {
		left, _ := strconv.Atoi(values[i])
		right, _ := strconv.Atoi(values[j])
		return left < right
	})
	for _, value := range values {
		number, err := strconv.Atoi(value)
		if err != nil {
			return "", fmt.Errorf("%s.%s enum key %q is not an integer", owner, name, value)
		}
		rendered.Members = append(rendered.Members, enumConst{
			Name:        enumConstName(enumName, members[value].Caption, value),
			Value:       number,
			Caption:     members[value].Caption,
			Description: members[value].Description,
		})
	}

	if existing, clash := enums[enumName]; clash {
		if !sameEnum(existing, rendered) {
			return "", fmt.Errorf(
				"enum name %s is claimed by both %s.%s and %s.%s with different members",
				enumName, existing.Owner, existing.OCSF, owner, name)
		}
	}
	enums[enumName] = rendered
	return enumName, nil
}

func sameEnum(left, right renderedEnum) bool {
	if len(left.Members) != len(right.Members) {
		return false
	}
	for i := range left.Members {
		if left.Members[i] != right.Members[i] {
			return false
		}
	}
	return true
}
