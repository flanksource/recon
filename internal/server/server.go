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

	"github.com/flanksource/recon/internal/discovery"
	"github.com/flanksource/recon/internal/entities"
	"github.com/flanksource/recon/internal/httpapi"
	"github.com/flanksource/recon/internal/scan"
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

	// Scans is the scan runtime. Optional: a test that only exercises the
	// entity routes does not need one, and the streaming route is left
	// unregistered rather than serving a nil runtime.
	Scans *scan.Runtime

	// Sweeps is the discovery runner. Optional, like Scans.
	Sweeps *discovery.Runner
}

// Handler builds the mux.
func Handler(config Config) http.Handler {
	// Every component that reaches the database is given it here, in one place.
	// The CLI path attaches it in a pre-run hook, which serve deliberately skips
	// because it opens its own connection — so missing one here left the scan
	// runtime holding a nil store until someone started a scan.
	config.Registry.SetStore(config.Store)
	if config.Sweeps != nil {
		config.Sweeps.Store = config.Store
	}

	mux := http.NewServeMux()

	if config.Scans != nil {
		config.Scans.Store = config.Store
		// Hand-written, not clicky's task SSE handler: that one writes named
		// events, and the browser's EventSource.onmessage fires only for
		// unnamed ones, so every frame would be silently discarded.
		broadcaster := httpapi.NewBroadcaster(httpapi.BroadcasterOptions{})
		config.Scans.Publisher = broadcaster
		mux.Handle("GET /api/scan/events", broadcaster)

		// The broadcaster replays the last frame to a new subscriber, so a page
		// loaded before anything has run needs one published up front.
		config.Scans.PublishCurrent()
	}

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

	// Registering panics on a duplicate pattern, which is the behaviour we want:
	// two routes claiming one path is a wiring bug, and it should stop the
	// process at startup rather than serve whichever won.
	swagger.RegisterRoutes(mux)
	return mux
}
