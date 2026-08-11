// Package scan holds the engines that test endpoints and report findings. Unlike
// discovery they do not chain: a scan runs against a fixed endpoint list
// resolved from the inventory, and what it produces is findings, not inventory
// state.
package scan

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
)

// Engine tests endpoints and reports findings.
type Engine interface {
	Spec() engines.Spec

	// Risk judges whether this configuration sends traffic that could disrupt
	// the target. The runtime turns an intrusive verdict into a confirmation
	// gate; the engine decides what intrusive means for itself.
	Risk(config map[string]any) engines.Risk

	// Run executes one scan, reporting to sink as the scan progresses rather
	// than at the end: a scan takes minutes, and findings the UI only learns
	// about on completion are findings nobody can act on while it runs.
	//
	// Cancellation is the context. Returning nil means the engine ran to
	// completion — not that it found nothing.
	Run(ctx context.Context, run engines.Run, sink Sink) error
}

// Catalogue is implemented by engines that can say which templates a
// configuration selects before it runs.
//
// Optional, like Progress was: it is answerable for a template-driven scanner
// and meaningless for one whose checks are compiled in. An engine that cannot
// answer is not asked, and the UI shows no preview rather than a wrong one.
type Catalogue interface {
	// Templates lists everything the engine could run, unfiltered.
	Templates() ([]api.Template, error)

	// Preview reports what one configuration selects.
	Preview(config map[string]any) (api.TemplatePreview, error)

	// Corpus describes the installed catalogue without loading it into API
	// values. It reports its own failure rather than returning an error, because
	// "the templates are missing" is the answer an engine listing needs to show,
	// not a reason to fail the listing.
	Corpus() api.EngineTemplates
}

// Sink receives everything a run produces.
//
// It replaces reading an engine's stdout: nuclei is linked in, so findings
// arrive as values and progress arrives as counters. There is no stdout/stderr
// distinction here because in-process there is no such thing — the runtime
// decides which stream to attribute engine output to.
type Sink interface {
	// Finding records one finding. An error aborts the run.
	Finding(api.Finding) error

	// Stats reports progress. Called often; the last call wins.
	Stats(api.ScanStats)

	// Log records the engine's own log output, verbatim.
	Log(text string)
}

var (
	mu       sync.RWMutex
	registry = map[string]Engine{}
)

// Register adds an engine. It panics on a bad spec or a duplicate name: both are
// programming errors that must fail at startup, not mid-scan.
func Register(engine Engine) {
	spec := engine.Spec()
	if err := spec.Validate(); err != nil {
		panic(fmt.Sprintf("scan engine: %v", err))
	}

	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[spec.Name]; exists {
		panic(fmt.Sprintf("scan engine %s registered twice", spec.Name))
	}
	registry[spec.Name] = engine
}

// Get returns one engine.
func Get(name string) (Engine, error) {
	mu.RLock()
	defer mu.RUnlock()
	engine, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown scan engine: %s", name)
	}
	return engine, nil
}

// All returns every registered engine, ordered by name.
func All() []Engine {
	mu.RLock()
	defer mu.RUnlock()

	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]Engine, 0, len(names))
	for _, name := range names {
		out = append(out, registry[name])
	}
	return out
}

// Specs returns every registered spec, ordered by name.
func Specs() []engines.Spec {
	all := All()
	specs := make([]engines.Spec, 0, len(all))
	for _, engine := range all {
		specs = append(specs, engine.Spec())
	}
	return specs
}
