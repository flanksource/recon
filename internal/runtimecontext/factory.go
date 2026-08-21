// Package runtimecontext builds commons-db contexts for engine and HTTP work.
package runtimecontext

import (
	"context"
	"strings"

	dbcontext "github.com/flanksource/commons-db/context"

	"github.com/flanksource/recon/internal/store"
)

// Factory derives a commons-db context from the caller's cancellation context.
type Factory func(context.Context) dbcontext.Context

// New returns contexts carrying the recon database and configured namespace.
func New(st *store.Store, namespace string) Factory {
	if st == nil {
		panic("runtime context store is required")
	}
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		panic("runtime context namespace is required")
	}

	return func(ctx context.Context) dbcontext.Context {
		if ctx == nil {
			panic("runtime context base is required")
		}
		return dbcontext.NewContext(ctx).
			WithDB(st.DB(ctx), nil).
			WithNamespace(namespace)
	}
}
