// Package store is the only thing that talks to the database. Everything above
// it works in terms of internal/api wire types; everything below is gorm.
package store

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// Store holds the database handle. It is safe for concurrent use.
type Store struct {
	db *gorm.DB
}

// New wraps an existing gorm handle.
func New(db *gorm.DB) *Store { return &Store{db: db} }

// DB exposes the handle for callers that need to compose a query — the entity
// layer's filter pushdown, mainly.
func (s *Store) DB(ctx context.Context) *gorm.DB { return s.db.WithContext(ctx) }

// NotFoundError reports a missing row. The message text matters: the UI renders
// it verbatim, and the TypeScript backend used exactly this wording.
type NotFoundError struct {
	Kind string
	ID   string
}

func (e *NotFoundError) Error() string { return fmt.Sprintf("%s not found: %s", e.Kind, e.ID) }

// NotFound builds a NotFoundError.
func NotFound(kind, id string) error { return &NotFoundError{Kind: kind, ID: id} }

// IsNotFound reports whether err is a missing row, from either this package or
// gorm itself.
func IsNotFound(err error) bool {
	var notFound *NotFoundError
	return errors.As(err, &notFound) || errors.Is(err, gorm.ErrRecordNotFound)
}
