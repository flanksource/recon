// Package server builds the HTTP surface.
//
// It is separate from internal/cli so a test can stand the whole thing up
// against its own database without going through Cobra — the routes are what
// need testing, not the flag parsing around them.
package server

import (
	"fmt"
	"io/fs"
	"net/http"
	"net/url"

	"github.com/flanksource/clicky/rpc"
	"github.com/flanksource/clicky/task"
	"github.com/spf13/cobra"

	"github.com/flanksource/recon/internal/discovery"
	prowlerschema "github.com/flanksource/recon/internal/engines/scan/prowler/schema"
	"github.com/flanksource/recon/internal/entities"
	"github.com/flanksource/recon/internal/httpapi"
	"github.com/flanksource/recon/internal/probes"
	"github.com/flanksource/recon/internal/report"
	"github.com/flanksource/recon/internal/runtimecontext"
	"github.com/flanksource/recon/internal/scan"
	"github.com/flanksource/recon/internal/store"
)

// Config is what the server needs to run.
type Config struct {
	Host string
	Port int

	// Namespace is the default Kubernetes namespace for runtime secret
	// references and metadata catalogs.
	Namespace string

	// Root is the command tree the REST surface is generated from. Every entity
	// must already be registered on it: the OpenAPI spec is built on the first
	// request and then cached, so a route added later would be missing.
	Root *cobra.Command

	// Registry is the entity registry whose handlers the routes call.
	Registry *entities.Registry

	Store *store.Store

	// ContextFactory supplies commons-db contexts carrying the database and
	// namespace. When omitted, Handler derives one from Store and Namespace.
	ContextFactory runtimecontext.Factory

	// OnePassword overrides the public commons-db metadata catalog. Production
	// leaves it nil; tests can provide a catalog without invoking the op CLI.
	OnePassword OnePasswordCatalog

	// Scans is the scan runtime. Optional: a test that only exercises the
	// entity routes does not need one, and the streaming route is left
	// unregistered rather than serving a nil runtime.
	Scans *scan.Runtime

	// Sweeps is the discovery runner. Optional, like Scans.
	Sweeps *discovery.Runner

	// Probes is the liveness runner. Optional, like Scans.
	Probes *probes.Runner

	// UI is the built web interface. Optional: a test exercising the API does
	// not need it, and leaving it nil serves the API alone.
	UI    fs.FS
	UIDir string

	// DevServer is a running Vite dev server to serve the interface from
	// instead of UI. Set by `serve --dev`, so that what is served is the working
	// tree rather than whatever was embedded when the binary was compiled.
	DevServer *url.URL

	// ReportSourceDir renders scan reports from a template directory on disk
	// instead of the copy embedded in the binary — the same reason DevServer
	// exists, for the printed document rather than the interface. Empty uses the
	// embedded template.
	ReportSourceDir string
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
	if config.Probes != nil {
		config.Probes.Store = config.Store
	}
	contextFactory := config.ContextFactory
	if contextFactory == nil && config.Store != nil {
		namespace := config.Namespace
		if namespace == "" {
			namespace = "default"
		}
		contextFactory = runtimecontext.New(config.Store, namespace)
	}

	mux := http.NewServeMux()
	task.RegisterHandlers(mux, "/api/v1")
	if contextFactory != nil {
		registerSecretCatalogs(mux, secretCatalogOptions{
			Context: contextFactory, OnePassword: config.OnePassword,
		})
	}

	if config.Scans != nil {
		if contextFactory == nil {
			panic("scan runtime context requires a store or context factory")
		}
		config.Scans.Store = config.Store
		config.Scans.ContextFactory = contextFactory
		// Hand-written, not clicky's task SSE handler: that one writes named
		// events, and the browser's EventSource.onmessage fires only for
		// unnamed ones, so every frame would be silently discarded.
		broadcaster := httpapi.NewBroadcaster(httpapi.BroadcasterOptions{})
		config.Scans.Publisher = broadcaster
		mux.Handle("GET /api/scan/events", broadcaster)
		httpapi.RegisterScan(mux, config.Scans)

		// The broadcaster replays the last frame to a new subscriber, so a page
		// loaded before anything has run needs one published up front.
		config.Scans.PublishCurrent()
	}

	serveConfig := &rpc.ServeConfig{
		Host:        config.Host,
		Port:        config.Port,
		Title:       "recon",
		Description: "Attack-surface inventory, discovery and scanning",
		Executor:    &rpc.ExecutorConfig{Enabled: true, PathPrefix: "/api/v1"},
	}
	swagger := rpc.NewSwaggerServer(
		serveConfig,
		config.Root,
		nil,
	)

	// Registering panics on a duplicate pattern, which is the behaviour we want:
	// two routes claiming one path is a wiring bug, and it should stop the
	// process at startup rather than serve whichever won.
	components, err := prowlerschema.OpenAPIComponents()
	if err != nil {
		panic(fmt.Sprintf("load Prowler OpenAPI components: %v", err))
	}
	openAPI, err := newOpenAPIPublisher(config.Root, swagger.ConverterConfig(), components)
	if err != nil {
		panic(fmt.Sprintf("build OpenAPI document: %v", err))
	}
	mux.HandleFunc("/api/openapi.json", openAPI.serveJSON)
	mux.HandleFunc("/api/openapi.yaml", openAPI.serveYAML)
	mux.HandleFunc("/api/entities", swagger.HandleEntities)
	if !serveConfig.SkipHealth {
		mux.HandleFunc("/health", swagger.HandleHealth)
	}
	swagger.RegisterExecutionRoutes(mux)

	httpapi.RegisterSchema(mux)
	httpapi.RegisterTemplatePreview(mux, config.Registry)
	if config.Store != nil {
		httpapi.RegisterScanFiles(mux, config.Store)
		httpapi.RegisterScanReport(mux, config.Store,
			report.New(report.Options{SourceDir: config.ReportSourceDir}))
	}

	// The interface claims "/", so it is the fallback for everything the API did
	// not match. Registered last for readability only — net/http resolves by
	// specificity, not by registration order.
	if config.DevServer != nil || config.UI != nil {
		if config.DevServer != nil {
			mux.Handle("/", httpapi.DevProxy(config.DevServer))
		} else {
			mux.Handle("/", httpapi.SPA(config.UI, config.UIDir))
		}

		// "/api/" is more specific than "/", so this stops an unmatched API path
		// falling through to the SPA. Without it a request for a route that does
		// not exist — or one deliberately kept off the surface, like migrate —
		// answers 200 with index.html, which reads to a client as success.
		mux.Handle("/api/", httpapi.NotFound())
	}
	return mux
}
