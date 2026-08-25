package mute

import (
	"encoding/json"
	"reflect"

	"github.com/flanksource/recon/internal/api"
)

// exemplar is one finding with every modelled field present.
//
// It exists so Compile can reject a path that no finding will ever carry.
// Compiling against a zero Finding declared an environment in which most of the
// schema was absent, and cel's nilsafe library answers an absent path with null
// rather than an error — so a rule with a typo in it stored successfully, muted
// nothing, and looked exactly like a rule that legitimately matched nothing.
//
// Built by reflection rather than written out, because a hand-written exemplar
// is a second copy of the OCSF schema: it would go stale the first time the
// generator emitted a new attribute, and the failure would again be silent.
func exemplar() api.Finding {
	var finding api.Finding
	populate(reflect.ValueOf(&finding).Elem(), map[reflect.Type]bool{})
	return finding
}

// rawMessage needs a value that is valid JSON. Every other zero value marshals
// fine; an empty json.RawMessage marshals to nothing and breaks the document.
var rawMessage = reflect.TypeOf(json.RawMessage(nil))

// populate gives every reachable field a value, so that the JSON projection of
// the result names every path an expression may address.
//
// inFlight stops a self-referential type from recursing forever. A type dropped
// that way loses its paths, which surfaces as a compile error on a rule that
// uses one — loud, and the correct answer until the type is handled.
func populate(value reflect.Value, inFlight map[reflect.Type]bool) {
	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() {
			value.Set(reflect.New(value.Type().Elem()))
		}
		populate(value.Elem(), inFlight)
	case reflect.Slice:
		// json_t: an evidence payload whose shape is the engine's, not the
		// schema's. Free below this point, like unmapped.
		if value.Type() == rawMessage {
			value.SetBytes([]byte(`{"` + dynamic + `":null}`))
			return
		}
		if value.Len() == 0 {
			value.Set(reflect.MakeSlice(value.Type(), 1, 1))
		}
		populate(value.Index(0), inFlight)
	case reflect.Struct:
		if inFlight[value.Type()] {
			return
		}
		inFlight[value.Type()] = true
		defer delete(inFlight, value.Type())
		for i := range value.NumField() {
			if value.Type().Field(i).IsExported() {
				populate(value.Field(i), inFlight)
			}
		}
	case reflect.Map:
		// `unmapped` is OCSF's escape hatch for whatever an engine reported that
		// the schema has no name for. It has no fixed keys, so it carries the
		// marker that tells the path check to stop rather than any real ones —
		// which also keeps it from vanishing under omitempty.
		if value.IsNil() {
			value.Set(reflect.MakeMap(value.Type()))
		}
		if value.Type().Key().Kind() == reflect.String {
			value.SetMapIndex(reflect.ValueOf(dynamic).Convert(value.Type().Key()),
				reflect.Zero(value.Type().Elem()))
		}
	}
}
