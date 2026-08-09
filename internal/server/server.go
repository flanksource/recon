// Package server builds the HTTP surface.
//
// It is separate from internal/cli so a test can stand the whole thing up
// against its own database without going through Cobra — the routes are what
// need testing, not the flag parsing around them.
package server

import (
	"net/http"

	"github.com/flanksource/clicky/rpc"
	"github.com/spf13/cobra"

	"github.com/flanksource/recon/internal/entities"
	"github.com/flanksource/recon/internal/store"
)

// Config is what the server needs to run.
type Config struct {
	Host string
	Port int

	// Root is the command tree the REST surface is generated from. Every entity
	// must already be registered on it: the OpenAPI spec is built on the first
	// request and then cached, so a route added later would be missing.
	Root *cobra.Command

	// Registry is the entity registry whose handlers the routes call.
	Registry *entities.Registry

	Store *store.Store
}

// Handler builds the mux.
func Handler(config Config) http.Handler {
	config.Registry.SetStore(config.Store)

	swagger := rpc.NewSwaggerServer(
		&rpc.ServeConfig{
			Host:        config.Host,
			Port:        config.Port,
			Title:       "recon",
			Description: "Attack-surface inventory, discovery and scanning",
			Executor:    &rpc.ExecutorConfig{Enabled: true, PathPrefix: "/api/v1"},
		},
		config.Root,
		nil,
	)

	mux := http.NewServeMux()
	// Registering panics on a duplicate pattern, which is the behaviour we want:
	// two routes claiming one path is a wiring bug, and it should stop the
	// process at startup rather than serve whichever won.
	swagger.RegisterRoutes(mux)
	return mux
}
