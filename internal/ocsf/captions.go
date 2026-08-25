package ocsf

import (
	"fmt"
	"reflect"
	"strings"
)

// Captions fills in the readable half of every enum pair the record carries.
//
// OCSF models an enumerated attribute as two fields: the integer that is the
// value, and a string that is its caption — severity_id 4 beside severity
// "High". The integer is what an adapter maps to and what the database stores;
// the caption is entirely derived from it, which is why it is computed here
// rather than written out at each of the places a finding is built and left
// stale at one of them.
//
// A record carrying only the integer is still valid OCSF, since the captions are
// optional. It is not, however, readable by a consumer that renders `severity`,
// and it makes an expression reading finding.severity answer "" rather than the
// value it plainly means — a silent wrong answer rather than a loud one.
//
// Only empty captions are filled. A record that arrived over the wire with its
// own captions keeps them; disagreeing with the producer about what its own
// integers mean is not this function's business.
func Captions(record any) {
	value := reflect.ValueOf(record)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return
	}
	caption(value.Elem())
}

func caption(value reflect.Value) {
	switch value.Kind() {
	case reflect.Pointer:
		if !value.IsNil() {
			caption(value.Elem())
		}
	case reflect.Slice:
		for i := range value.Len() {
			caption(value.Index(i))
		}
	case reflect.Struct:
		for i := range value.NumField() {
			field := value.Type().Field(i)
			if !field.IsExported() {
				continue
			}
			if field.Type.Kind() == reflect.String && value.Field(i).Len() == 0 {
				if text, found := captionFor(value, field.Name); found {
					value.Field(i).SetString(text)
				}
				continue
			}
			caption(value.Field(i))
		}
	}
}

// captionFor finds the enum a caption belongs to.
//
// OCSF pairs them by name in two shapes: `severity` with `severity_id`, and
// `activity_name` with `activity_id`. The identity attributes — class_uid,
// category_uid, type_uid — are plain integers rather than generated enums, so
// class_name and its siblings find no Stringer and are left alone.
func captionFor(owner reflect.Value, name string) (string, bool) {
	candidates := []string{name + "ID"}
	if prefix := strings.TrimSuffix(name, "Name"); prefix != name && prefix != "" {
		candidates = append(candidates, prefix+"ID", prefix+"UID")
	}
	for _, candidate := range candidates {
		field := owner.FieldByName(candidate)
		if !field.IsValid() {
			continue
		}
		if stringer, usable := field.Interface().(fmt.Stringer); usable {
			return stringer.String(), true
		}
	}
	return "", false
}
