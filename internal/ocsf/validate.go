// Package ocsf carries the Open Cybersecurity Schema Framework types recon
// stores a finding as.
//
// Everything in a *.generated.go file comes from OCSF's own published schema
// via hack/gen-ocsf and must not be edited by hand. This file is the part no
// schema can express: OCSF states requirement levels that depend on which
// profiles a record declares, and constraints such as "at least one of these
// attributes" that no struct shape enforces.
package ocsf

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Validate reports every way a record falls short of what OCSF asks of it.
//
// Profiles are read from the record's own metadata rather than passed in. A
// profile is what raises an attribute's requirement level — `cloud` is optional
// on a bare detection finding and required on one that declares the cloud
// profile — so a record that declared one set while being validated against
// another would pass here and be rejected by any other OCSF consumer.
//
// Every problem is reported together. A mapping that has gone wrong is usually
// wrong in several places at once, and fixing them one error at a time turns a
// single adapter change into a dozen rebuild cycles.
func Validate(finding DetectionFinding) error {
	declared := map[string]bool{}
	if finding.Metadata != nil {
		for _, profile := range finding.Metadata.Profiles {
			declared[profile] = true
		}
	}

	var problems []string
	present := attributesPresent(reflect.ValueOf(finding))
	for _, requirement := range Requirements {
		if requirement.Level != "required" {
			continue
		}
		if requirement.Profile != "" && !declared[requirement.Profile] {
			continue
		}
		if present[requirement.Attribute] {
			continue
		}
		problem := fmt.Sprintf("%s is required", requirement.Attribute)
		if requirement.Profile != "" {
			problem += fmt.Sprintf(" under the %s profile, which this record declares", requirement.Profile)
		}
		problems = append(problems, problem)
	}

	problems = append(problems, checkConstraints(reflect.ValueOf(finding), "")...)

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("OCSF %s (class %d): %s",
		ObjectNames["DetectionFinding"], ClassUID, strings.Join(problems, "; "))
}

// checkConstraints walks a record and checks every OCSF object it reaches.
//
// Recursive rather than a check on the top level alone, because the constraints
// that matter in practice are on the nested objects: a resource with neither a
// name nor a uid identifies nothing, and an evidence entry carrying only a name
// is the exact mistake OCSF's at_least_one exists to catch.
func checkConstraints(value reflect.Value, path string) []string {
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface:
		if value.IsNil() {
			return nil
		}
		return checkConstraints(value.Elem(), path)

	case reflect.Slice, reflect.Array:
		var problems []string
		for i := 0; i < value.Len(); i++ {
			problems = append(problems, checkConstraints(value.Index(i), fmt.Sprintf("%s[%d]", path, i))...)
		}
		return problems

	case reflect.Struct:
		return checkStruct(value, path)

	default:
		return nil
	}
}

func checkStruct(value reflect.Value, path string) []string {
	var problems []string

	if objectName, known := ObjectNames[value.Type().Name()]; known {
		if constraint, limited := Constraints[objectName]; limited {
			problems = append(problems, violations(value, objectName, path, constraint)...)
		}
	}

	for i := 0; i < value.NumField(); i++ {
		field := value.Type().Field(i)
		if !field.IsExported() {
			continue
		}
		child := path
		if name := jsonName(field); name != "" {
			if child == "" {
				child = name
			} else {
				child += "." + name
			}
		}
		problems = append(problems, checkConstraints(value.Field(i), child)...)
	}
	return problems
}

func violations(value reflect.Value, objectName, path string, constraint Constraint) []string {
	present := attributesPresent(value)
	where := objectName
	if path != "" {
		where = path
	}

	var problems []string
	if len(constraint.AtLeastOne) > 0 && countPresent(present, constraint.AtLeastOne) == 0 {
		problems = append(problems, fmt.Sprintf("%s needs at least one of %s",
			where, strings.Join(constraint.AtLeastOne, ", ")))
	}
	if found := countPresent(present, constraint.JustOne); len(constraint.JustOne) > 0 && found > 1 {
		problems = append(problems, fmt.Sprintf("%s carries %d of %s, which allows only one",
			where, found, strings.Join(constraint.JustOne, ", ")))
	}
	return problems
}

func countPresent(present map[string]bool, attributes []string) int {
	found := 0
	for _, attribute := range attributes {
		if present[attribute] {
			found++
		}
	}
	return found
}

// attributesPresent reports which OCSF attributes a value actually carries,
// keyed by the OCSF name rather than the Go one so it lines up with the
// generated requirement and constraint tables.
//
// Presence is "not the zero value", which is the same rule encoding/json
// applies for omitempty — so what Validate considers absent is exactly what
// would be missing from the marshalled record.
//
// Except for the enums, where zero is a value rather than the absence of one:
// severity_id 0 is Unknown, which is what an engine reporting a severity recon
// does not recognise honestly maps to. Reading that as "no severity was
// specified" would make Validate reject the one mapping that is telling the
// truth about not knowing.
func attributesPresent(value reflect.Value) map[string]bool {
	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return map[string]bool{}
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return map[string]bool{}
	}

	present := make(map[string]bool, value.NumField())
	for i := 0; i < value.NumField(); i++ {
		field := value.Type().Field(i)
		if !field.IsExported() {
			continue
		}
		if name := jsonName(field); name != "" {
			present[name] = isEnum(field.Type) || !value.Field(i).IsZero()
		}
	}
	return present
}

// isEnum reports whether a field's type is one of the generated enums, which is
// exactly the set of types carrying a String method over an integer.
func isEnum(fieldType reflect.Type) bool {
	if fieldType.Kind() < reflect.Int || fieldType.Kind() > reflect.Uint64 {
		return false
	}
	_, named := reflect.New(fieldType).Elem().Interface().(fmt.Stringer)
	return named
}

func jsonName(field reflect.StructField) string {
	tag, ok := field.Tag.Lookup("json")
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "-" {
		return ""
	}
	return name
}

// KnownProfiles reports the profiles OCSF defines for this class, sorted. A
// record that declares anything else is describing a shape no consumer can
// interpret, so adapters check against this rather than inventing names.
func KnownProfiles() []string {
	known := append([]string(nil), Profiles...)
	sort.Strings(known)
	return known
}
