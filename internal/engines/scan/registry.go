// Package scan holds the engines that test endpoints and report findings. Unlike
// discovery they do not chain: a scan runs against a fixed endpoint list
// resolved from the inventory, and what it produces is findings, not inventory
// state.
package scan

import (
	"fmt"
	"io"
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

	// Args builds the command line for one run.
	Args(engines.Run) []string

	// Parse reads the engine's output, calling emit for each finding. Streaming
	// so a long scan surfaces findings as they land rather than at the end.
	Parse(r io.Reader, emit func(api.Finding) error) error
}

// Progress is implemented by engines that report machine-readable progress.
// Optional on purpose: nuclei emits periodic stats, most tools do not, and
// requiring it would mean every other engine returning false forever.
type Progress interface {
	// Progress parses one output line, returning stats when the line carried
	// them.
	Progress(line string) (api.ScanStats, bool)
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
