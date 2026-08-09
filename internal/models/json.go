// Package models holds the gorm structs and the projection between them and the
// wire types in internal/api. The split is deliberate: a gorm tag must never
// reach a response body, and a wire field must never dictate a column.
package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// JSON stores a typed value in a jsonb column while keeping the absent/present
// distinction the wire format depends on: a nil V is SQL NULL, which is how a
// machine-owned section that was never observed round-trips as an omitted key
// rather than an empty object.
type JSON[T any] struct {
	V *T
}

// Wrap builds a column value from a pointer, preserving nil.
func Wrap[T any](value *T) JSON[T] { return JSON[T]{V: value} }

// Get returns the stored value, or the zero value when the column was NULL. Use
// it where the wire type has no absent/present distinction to preserve — a map
// that is documented as always present, say — and V where it does.
func (j JSON[T]) Get() T {
	if j.V == nil {
		var zero T
		return zero
	}
	return *j.V
}

// Value implements driver.Valuer.
func (j JSON[T]) Value() (driver.Value, error) {
	if j.V == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(j.V)
	if err != nil {
		return nil, fmt.Errorf("encode %T: %w", j.V, err)
	}
	return string(encoded), nil
}

// Scan implements sql.Scanner.
func (j *JSON[T]) Scan(src any) error {
	if src == nil {
		j.V = nil
		return nil
	}

	var raw []byte
	switch value := src.(type) {
	case []byte:
		raw = value
	case string:
		raw = []byte(value)
	default:
		return fmt.Errorf("scan %T into JSON[%T]: unsupported source", src, *new(T))
	}

	// Postgres can hand back a literal JSON null for a jsonb column holding
	// null, which is not the same as a NULL column and must not decode into a
	// zero value that then serialises as {}.
	if string(raw) == "null" {
		j.V = nil
		return nil
	}

	var decoded T
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return fmt.Errorf("decode JSON[%T]: %w", decoded, err)
	}
	j.V = &decoded
	return nil
}

// GormDataType tells gorm the column is jsonb rather than inferring from the
// Go type, which would land on text.
func (JSON[T]) GormDataType() string { return "jsonb" }
